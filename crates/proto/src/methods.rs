// SPDX-License-Identifier: GPL-3.0-or-later
//! 方法与事件通道登记表。
//!
//! 新增方法或事件只改这里：服务端据此校验方法名、判断是否需要写审计日志（C-SEC-03），
//! `cargo xtask gen-types` 据此生成前端的 `IpcRequest` / `IpcResult` / `IpcEvent`。

use ts_rs::{Config, TS, TypeVisitor};

use crate::Empty;
use crate::event::{ConnEvent, DriverStatus, LogEvent, LogSubscribeParams, ProcessListResult};
use crate::node::{
    NodeImportParams, NodeImportResult, NodeListResult, NodeTestParams, NodeTestResult,
};
use crate::profile::{Profile, ProfileIdParams, ProfileListResult, ProfileSaveResult};
use crate::rpc::{HelloParams, HelloResult};
use crate::session::{SessionStartParams, SessionStatus};

/// 一个 IPC 方法的元数据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodInfo {
    /// 方法名，格式 `<领域>.<动词>`。
    pub name: &'static str,
    /// 是否修改状态。修改类方法必须写审计日志（C-SEC-03）。
    pub mutating: bool,
}

macro_rules! access {
    (read) => {
        false
    };
    (write) => {
        true
    };
}

macro_rules! ipc_methods {
    ($( $name:literal => $params:ty, $result:ty, $access:ident; )*) => {
        /// 全部 IPC 方法。
        pub const METHODS: &[MethodInfo] = &[
            $( MethodInfo { name: $name, mutating: access!($access) } ),*
        ];

        /// （方法名, 参数 TS 类型名, 返回值 TS 类型名）
        pub(crate) fn method_ts_names(cfg: &Config) -> Vec<(&'static str, String, String)> {
            vec![ $( ($name, <$params as TS>::name(cfg), <$result as TS>::name(cfg)) ),* ]
        }

        pub(crate) fn visit_method_types(v: &mut impl TypeVisitor) {
            $( v.visit::<$params>(); v.visit::<$result>(); )*
        }
    };
}

macro_rules! ipc_events {
    ($( $channel:literal => $payload:ty; )*) => {
        /// 全部事件通道名。
        pub const EVENT_CHANNELS: &[&str] = &[ $( $channel ),* ];

        /// （通道名, 负载 TS 类型名）
        pub(crate) fn event_ts_names(cfg: &Config) -> Vec<(&'static str, String)> {
            vec![ $( ($channel, <$payload as TS>::name(cfg)) ),* ]
        }

        pub(crate) fn visit_event_types(v: &mut impl TypeVisitor) {
            $( v.visit::<$payload>(); )*
        }
    };
}

ipc_methods! {
    "ipc.hello" => HelloParams, HelloResult, read;
    "session.start" => SessionStartParams, SessionStatus, write;
    "session.stop" => Empty, SessionStatus, write;
    "session.status" => Empty, SessionStatus, read;
    "profile.list" => Empty, ProfileListResult, read;
    "profile.get" => ProfileIdParams, Profile, read;
    "profile.save" => Profile, ProfileSaveResult, write;
    "profile.delete" => ProfileIdParams, Empty, write;
    "node.import" => NodeImportParams, NodeImportResult, write;
    "node.list" => Empty, NodeListResult, read;
    "node.test" => NodeTestParams, NodeTestResult, read;
    "process.list" => Empty, ProcessListResult, read;
    "conn.subscribe" => Empty, Empty, read;
    "log.subscribe" => LogSubscribeParams, Empty, read;
    "driver.status" => Empty, DriverStatus, read;
    "driver.unload" => Empty, DriverStatus, write;
}

ipc_events! {
    "conn.subscribe" => ConnEvent;
    "log.subscribe" => LogEvent;
    "session.status" => SessionStatus;
    "driver.status" => DriverStatus;
}

/// 按方法名查元数据。
pub fn method(name: &str) -> Option<&'static MethodInfo> {
    METHODS.iter().find(|m| m.name == name)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn method_names_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for m in METHODS {
            assert!(seen.insert(m.name), "duplicate method {}", m.name);
            let (domain, verb) = m.name.split_once('.').unwrap();
            assert!(!domain.is_empty() && !verb.is_empty(), "{}", m.name);
            assert_eq!(m.name, m.name.to_ascii_lowercase(), "{}", m.name);
        }
    }

    #[test]
    fn state_changing_methods_are_marked_mutating() {
        for name in [
            "session.start",
            "session.stop",
            "profile.save",
            "profile.delete",
            "node.import",
            "driver.unload",
        ] {
            assert!(method(name).unwrap().mutating, "{name} must be audited");
        }
        assert!(!method("session.status").unwrap().mutating);
        assert!(method("no.such").is_none());
    }

    #[test]
    fn every_event_channel_is_unique() {
        let set: HashSet<_> = EVENT_CHANNELS.iter().collect();
        assert_eq!(set.len(), EVENT_CHANNELS.len());
    }
}
