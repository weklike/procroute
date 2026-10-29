// SPDX-License-Identifier: GPL-3.0-or-later
//! TUN 模式的连接事件（F10）：每秒读一次内核的连接列表，与上一次比较后推送 `conn.subscribe` 事件。
//!
//! - 只推送被改道的连接：规则选中的出站是 `direct` 的连接（非目标进程、命中排除规则）既不推送也不保留
//!   任何内容，只记住它的 id 以免重复判定（C-NET-02）；
//! - 进程组按 `procroute-rules` 对进程路径重新判定，内核没查到进程时按出站反查；
//! - 节点出站的标签是节点 id，展示时换成节点名；
//! - TUN 模式下拿不到 PID，事件里的 `pid` 为 0。
//!
//! 内核重启期间读不到列表，就保持上一次的状态；会话停止时为所有仍在跟踪的连接发「已关闭」。

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use procroute_core_mgr::clash_api::{KernelConnection, fetch_connections};
use procroute_core_mgr::config_gen::DIRECT_TAG;
use procroute_platform_win::secret::Secret;
use procroute_proto::event::{ConnEvent, ConnPhase};
use procroute_proto::profile::Profile;
use procroute_rules::engine::{CompileError, RuleEngine};
use procroute_rules::matcher::NormalizedProcess;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::events::EventHub;

/// 两次读取之间的间隔。
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// 单次读取的超时；内核重启期间不要长时间占着阻塞线程。
const FETCH_TIMEOUT: Duration = Duration::from_millis(800);

/// 一条连接属于哪个进程组、显示成哪个出站。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    pub group: String,
    pub outbound: String,
}

/// 按方案判定连接的归属。
pub struct Classifier {
    engine: RuleEngine,
    node_names: HashMap<String, String>,
}

impl Classifier {
    /// `node_names`：节点 id（出站标签）→ 节点名。
    pub fn new(
        profile: &Profile,
        node_names: HashMap<String, String>,
    ) -> Result<Self, CompileError> {
        Ok(Self {
            engine: RuleEngine::compile(profile)?,
            node_names,
        })
    }

    /// 被改道的连接返回归属；直连的返回 `None`。
    pub fn classify(&self, c: &KernelConnection) -> Option<Attribution> {
        let routed = c.routed_outbound()?;
        if routed == DIRECT_TAG {
            return None;
        }
        let by_process = (!c.process_path.is_empty())
            .then(|| {
                self.engine
                    .decide(&NormalizedProcess::new("", &c.process_path))
                    .group()
            })
            .flatten()
            .and_then(|i| self.engine.group(i));
        let group = by_process
            .or_else(|| self.engine.groups().iter().find(|g| g.outbound == routed))
            .map_or_else(String::new, |g| g.tag.clone());
        let used = c.chains.first().map_or(routed, String::as_str);
        let outbound = self
            .node_names
            .get(used)
            .cloned()
            .unwrap_or_else(|| used.to_owned());
        Some(Attribution { group, outbound })
    }
}

/// 两次快照之间的差异 → 连接事件。
#[derive(Default)]
pub struct ConnTracker {
    /// 内核连接 id → 最近一次推送的事件。
    known: HashMap<String, ConnEvent>,
    /// 直连的连接 id，只为了不重复判定。
    ignored: HashSet<String>,
    next_id: u64,
}

impl ConnTracker {
    pub fn update(
        &mut self,
        snapshot: &[KernelConnection],
        now_ms: u64,
        classify: impl Fn(&KernelConnection) -> Option<Attribution>,
    ) -> Vec<ConnEvent> {
        let mut events = Vec::new();
        let mut seen = HashSet::with_capacity(snapshot.len());
        for c in snapshot {
            seen.insert(c.id.as_str());
            if self.ignored.contains(&c.id) {
                continue;
            }
            if let Some(known) = self.known.get_mut(&c.id) {
                if known.upload_bytes != c.upload || known.download_bytes != c.download {
                    known.phase = ConnPhase::Updated;
                    known.upload_bytes = c.upload;
                    known.download_bytes = c.download;
                    events.push(known.clone());
                }
                continue;
            }
            let Some(who) = classify(c) else {
                self.ignored.insert(c.id.clone());
                continue;
            };
            self.next_id += 1;
            let event = ConnEvent {
                conn_id: self.next_id,
                phase: ConnPhase::Opened,
                pid: 0,
                process: process_name(&c.process_path),
                target: target(c),
                network: c.network,
                group: who.group,
                outbound: who.outbound,
                upload_bytes: c.upload,
                download_bytes: c.download,
                started_at_ms: c.started_at_ms.unwrap_or(now_ms),
            };
            events.push(event.clone());
            self.known.insert(c.id.clone(), event);
        }
        self.ignored.retain(|id| seen.contains(id.as_str()));
        let gone: Vec<String> = self
            .known
            .keys()
            .filter(|id| !seen.contains(id.as_str()))
            .cloned()
            .collect();
        for id in gone {
            if let Some(mut e) = self.known.remove(&id) {
                e.phase = ConnPhase::Closed;
                events.push(e);
            }
        }
        events
    }

    /// 会话结束：所有仍在跟踪的连接都已关闭。
    pub fn close_all(&mut self) -> Vec<ConnEvent> {
        self.ignored.clear();
        self.known
            .drain()
            .map(|(_, mut e)| {
                e.phase = ConnPhase::Closed;
                e
            })
            .collect()
    }
}

fn process_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `域名:端口`，没有域名时 `IP:端口`（IPv6 加方括号）。
fn target(c: &KernelConnection) -> String {
    let host = if c.host.is_empty() {
        &c.destination_ip
    } else {
        &c.host
    };
    if host.contains(':') {
        format!("[{host}]:{}", c.destination_port)
    } else {
        format!("{host}:{}", c.destination_port)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 运行中的连接轮询；[`ConnWatch::stop`] 等它为剩余连接发完「已关闭」再返回。
pub struct ConnWatch {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl ConnWatch {
    pub fn spawn(
        hub: Arc<EventHub>,
        api: SocketAddr,
        secret: Secret<String>,
        classifier: Classifier,
        interval: Duration,
    ) -> Self {
        let (stop, stopped) = watch::channel(false);
        let task = tokio::spawn(poll(
            hub,
            api,
            Arc::new(secret),
            classifier,
            interval,
            stopped,
        ));
        Self { stop, task }
    }

    pub async fn stop(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

async fn poll(
    hub: Arc<EventHub>,
    api: SocketAddr,
    secret: Arc<Secret<String>>,
    classifier: Classifier,
    interval: Duration,
    mut stopped: watch::Receiver<bool>,
) {
    let mut tracker = ConnTracker::default();
    let mut tick = tokio::time::interval(interval);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = tick.tick() => {}
            _ = stopped.changed() => break,
        }
        let secret = secret.clone();
        let fetch =
            tokio::task::spawn_blocking(move || fetch_connections(api, &secret, FETCH_TIMEOUT));
        // 停止请求不等正在进行的读取（内核停掉时它要等到超时）；阻塞线程自己结束
        let fetched = tokio::select! {
            fetched = fetch => fetched,
            _ = stopped.changed() => break,
        };
        // 内核重启中或暂时读不到：保持上一次的状态，下一轮再试
        let Ok(Ok(snapshot)) = fetched else {
            continue;
        };
        for event in tracker.update(&snapshot, now_ms(), |c| classifier.classify(c)) {
            hub.publish_conn(event);
        }
    }
    for event in tracker.close_all() {
        hub.publish_conn(event);
    }
}

#[cfg(test)]
mod tests;
