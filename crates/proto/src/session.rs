// SPDX-License-Identifier: GPL-3.0-or-later
//! 会话：按某个方案启动或停止改道，以及三个组件（服务、驱动、内核）的状态。

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::profile::Mode;

/// 会话整体状态。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    #[default]
    Stopped,
    Starting,
    Running,
    Stopping,
    /// fail-closed 已触发：目标进程网络被阻断（C-UI-02 要求界面明确提示）。
    Blocked,
}

/// 单个组件的状态。界面按组件把它翻译成「运行中 / 已加载」等文字。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum ComponentState {
    Active,
    #[default]
    Inactive,
    Restarting,
    Failed,
}

/// 服务、驱动、内核三者的状态，界面必须如实显示（C-UI-02）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ComponentStatus {
    pub service: ComponentState,
    pub driver: ComponentState,
    pub kernel: ComponentState,
}

/// 进入 `blocked` 的原因。只给原因码，文案由界面的 i18n 资源提供。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReason {
    /// 内核在 1 分钟内异常退出超过重启上限（C-PERF-05）。
    KernelCrashLoop,
    /// 本地中继无法连上内核的入口。
    RelayUnavailable,
    /// 拦截驱动加载或运行失败。
    DriverFailed,
}

/// `session.status` 的返回值，也是 `session.status` 事件的负载。
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, TS)]
pub struct SessionStatus {
    pub state: SessionState,
    pub profile_id: Option<String>,
    pub profile_name: Option<String>,
    pub mode: Option<Mode>,
    pub components: ComponentStatus,
    pub blocked_reason: Option<BlockedReason>,
}

/// `session.start` 的参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SessionStartParams {
    pub profile_id: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips() {
        let s = SessionStatus {
            state: SessionState::Blocked,
            profile_id: Some("p1".into()),
            profile_name: Some("游戏加速".into()),
            mode: Some(Mode::Precise),
            components: ComponentStatus {
                service: ComponentState::Active,
                driver: ComponentState::Active,
                kernel: ComponentState::Failed,
            },
            blocked_reason: Some(BlockedReason::KernelCrashLoop),
        };
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""state":"blocked""#));
        assert!(json.contains(r#""blocked_reason":"kernel_crash_loop""#));
        assert_eq!(serde_json::from_str::<SessionStatus>(&json).unwrap(), s);
    }

    #[test]
    fn default_status_is_stopped_and_inactive() {
        let s = SessionStatus::default();
        assert_eq!(s.state, SessionState::Stopped);
        assert_eq!(s.components.driver, ComponentState::Inactive);
    }

    #[test]
    fn start_params_reject_unknown_fields() {
        assert!(serde_json::from_str::<SessionStartParams>(r#"{"profile_id":"a"}"#).is_ok());
        assert!(serde_json::from_str::<SessionStartParams>(r#"{"profile_id":"a","x":1}"#).is_err());
    }
}
