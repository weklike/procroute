// SPDX-License-Identifier: GPL-3.0-or-later
//! 把服务自己的日志转成 `log.subscribe` 事件（界面的日志页）。
//!
//! 作为 `tracing` 的一层挂在全局过滤器之后，只转发已经通过级别过滤的事件。服务的日志从设计上就不含
//! 凭据与完整节点地址（AGENTS 4.3，C-SEC-04），这里原样转发结构化字段，不做额外加工；
//! sing-box 自己的输出不经过这里（守护进程直接丢弃）。
//!
//! 转发路径上不得再写日志，否则每条日志都会引出新的日志。

use std::collections::BTreeMap;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use procroute_proto::event::{LogEvent, LogLevel};
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer};

use crate::events::StreamEvent;

/// 单个字段值的长度上限，超出截断；防止一条日志撑大 IPC 消息。
const MAX_FIELD_CHARS: usize = 2048;

/// 把日志事件发到高频事件通道。
pub struct BroadcastLayer {
    tx: broadcast::Sender<StreamEvent>,
}

impl BroadcastLayer {
    pub fn new(tx: broadcast::Sender<StreamEvent>) -> Self {
        Self { tx }
    }
}

impl<S: Subscriber> Layer<S> for BroadcastLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        // 没有任何连接时不必构造事件
        if self.tx.receiver_count() == 0 {
            return;
        }
        let _ = self
            .tx
            .send(StreamEvent::Log(to_log_event(event, now_ms())));
    }
}

fn to_log_event(event: &Event<'_>, ts_ms: u64) -> LogEvent {
    let meta = event.metadata();
    let mut fields = Fields::default();
    event.record(&mut fields);
    LogEvent {
        ts_ms,
        level: level(meta.level()),
        module: module(meta.target()),
        message: fields.message,
        fields: fields.rest,
    }
}

fn level(l: &Level) -> LogLevel {
    match *l {
        Level::ERROR => LogLevel::Error,
        Level::WARN => LogLevel::Warn,
        Level::INFO => LogLevel::Info,
        _ => LogLevel::Debug,
    }
}

/// `procroute_core_mgr::supervisor` → `core-mgr`；`audit` → `audit`；第三方库取第一段。
fn module(target: &str) -> String {
    let head = target.split("::").next().unwrap_or(target);
    head.strip_prefix("procroute_")
        .unwrap_or(head)
        .replace('_', "-")
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[derive(Default)]
struct Fields {
    message: String,
    rest: BTreeMap<String, String>,
}

impl Fields {
    fn put(&mut self, field: &Field, mut value: String) {
        if let Some((cut, _)) = value.char_indices().nth(MAX_FIELD_CHARS) {
            value.truncate(cut);
            value.push('…');
        }
        if field.name() == "message" {
            self.message = value;
        } else {
            self.rest.insert(field.name().to_owned(), value);
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.put(field, format!("{value:?}"));
    }
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    fn capture(f: impl FnOnce()) -> Vec<LogEvent> {
        let (tx, mut rx) = broadcast::channel(16);
        let subscriber = tracing_subscriber::registry().with(BroadcastLayer::new(tx));
        tracing::subscriber::with_default(subscriber, f);
        let mut out = Vec::new();
        while let Ok(StreamEvent::Log(e)) = rx.try_recv() {
            out.push(e);
        }
        out
    }

    #[test]
    fn structured_fields_and_message_are_forwarded() {
        let events = capture(|| {
            tracing::warn!(pid = 4120, rule = %"game", "flow redirected");
            tracing::info!(target: "audit", method = "profile.save", "ipc call");
        });
        assert_eq!(events.len(), 2);
        let e = &events[0];
        assert_eq!(e.level, LogLevel::Warn);
        assert_eq!(e.module, "svc");
        assert_eq!(e.message, "flow redirected");
        assert_eq!(e.fields["pid"], "4120");
        assert_eq!(e.fields["rule"], "game");
        assert!(e.ts_ms > 0);
        assert_eq!(events[1].module, "audit");
        assert_eq!(events[1].fields["method"], "profile.save");
    }

    #[test]
    fn nothing_is_built_without_receivers() {
        let (tx, rx) = broadcast::channel::<StreamEvent>(4);
        drop(rx);
        let subscriber = tracing_subscriber::registry().with(BroadcastLayer::new(tx.clone()));
        tracing::subscriber::with_default(subscriber, || tracing::info!("nobody listens"));
        assert_eq!(tx.len(), 0);
    }

    #[test]
    fn modules_and_levels_are_mapped() {
        assert_eq!(module("procroute_core_mgr::supervisor"), "core-mgr");
        assert_eq!(module("procroute_svc"), "svc");
        assert_eq!(module("tokio::net"), "tokio");
        assert_eq!(level(&Level::TRACE), LogLevel::Debug);
        assert_eq!(level(&Level::ERROR), LogLevel::Error);
    }

    #[test]
    fn long_values_are_truncated() {
        let long = "x".repeat(MAX_FIELD_CHARS + 10);
        let events = capture(|| tracing::info!(value = %long, "long"));
        let v = &events[0].fields["value"];
        assert_eq!(v.chars().count(), MAX_FIELD_CHARS + 1);
        assert!(v.ends_with('…'));
    }
}
