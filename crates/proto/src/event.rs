// SPDX-License-Identifier: GPL-3.0-or-later
//! 服务主动推送的事件，以及事件订阅、进程列表、驱动状态的类型。

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::session::ComponentState;

/// 传输层协议。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Tcp,
    Udp,
}

/// 连接事件所处的阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ConnPhase {
    Opened,
    Updated,
    Closed,
}

/// 一条被改道连接的事件（`conn.subscribe` 通道）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ConnEvent {
    pub conn_id: u64,
    pub phase: ConnPhase,
    pub pid: u32,
    pub process: String,
    /// `host:port` 或 `ip:port`。
    pub target: String,
    pub network: Network,
    /// 命中的进程组标签。
    pub group: String,
    pub outbound: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub started_at_ms: u64,
}

/// 日志级别，按严重程度从低到高排列。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// 一条日志（`log.subscribe` 通道）。字段里不得含凭据（C-SEC-04）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct LogEvent {
    pub ts_ms: u64,
    pub level: LogLevel,
    /// 产生日志的模块，例如 `intercept`、`relay`。
    pub module: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

/// `log.subscribe` 的参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct LogSubscribeParams {
    pub min_level: LogLevel,
}

/// 拦截驱动的状态（`driver.status` 的返回值与事件负载）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DriverStatus {
    pub state: ComponentState,
    /// 锁定的驱动版本，例如 `2.2.2`。
    pub version: Option<String>,
}

/// 运行中的一个进程（`process.list`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
    /// 若命中当前方案，给出进程组标签。
    pub matched_group: Option<String>,
}

/// `process.list` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProcessListResult {
    pub processes: Vec<ProcessInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conn_event_round_trips() {
        let e = ConnEvent {
            conn_id: 7,
            phase: ConnPhase::Opened,
            pid: 4120,
            process: "MyGame.exe".into(),
            target: "203.0.113.24:27015".into(),
            network: Network::Udp,
            group: "game".into(),
            outbound: "hk-auto".into(),
            upload_bytes: 0,
            download_bytes: 0,
            started_at_ms: 1_793_000_000_000,
        };
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains(r#""network":"udp""#));
        assert_eq!(serde_json::from_str::<ConnEvent>(&json).unwrap(), e);
    }

    #[test]
    fn log_levels_are_ordered() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn log_fields_serialize_as_object() {
        let mut fields = BTreeMap::new();
        fields.insert("pid".to_owned(), "4120".to_owned());
        let e = LogEvent {
            ts_ms: 1,
            level: LogLevel::Info,
            module: "relay".into(),
            message: "flow redirected".into(),
            fields,
        };
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["fields"]["pid"], "4120");
    }
}
