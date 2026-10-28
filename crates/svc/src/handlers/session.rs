// SPDX-License-Identifier: GPL-3.0-or-later
//! `session.*`。

use procroute_proto::Empty;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::session::{
    ComponentState, ComponentStatus, SessionStartParams, SessionState, SessionStatus,
};
use serde_json::Value;

use super::{Services, blocking, store_error, to_json};
use crate::ipc_server::parse_params;

/// 服务刚启动时的状态：服务在运行，驱动与内核未启动（C-UI-02 要求如实显示）。
pub(super) fn initial_status() -> SessionStatus {
    SessionStatus {
        components: ComponentStatus {
            service: ComponentState::Active,
            ..ComponentStatus::default()
        },
        ..SessionStatus::default()
    }
}

pub(super) fn status(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    to_json(svc.session_snapshot())
}

/// 方案存在时，因为内核管理（core-mgr，T-055）尚未接入而明确失败；不改变任何网络设置。
pub(super) async fn start(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let SessionStartParams { profile_id } = parse_params(params)?;
    if svc.session_snapshot().state != SessionState::Stopped {
        return Err(IpcError::new(
            ErrorCode::SessionAlreadyRunning,
            "a session is already running",
        ));
    }
    let store = svc.profiles.clone();
    blocking(move || store.get(&profile_id).map_err(store_error)).await?;
    Err(IpcError::new(
        ErrorCode::KernelUnavailable,
        "sing-box integration is not available in this build yet",
    ))
}

pub(super) fn stop(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    if svc.session_snapshot().state == SessionState::Stopped {
        return Err(IpcError::new(
            ErrorCode::SessionNotRunning,
            "no session is running",
        ));
    }
    // 目前没有任何会话能进入运行状态（见 start）；接入 core-mgr 后在这里撤销改道。
    to_json(svc.session_snapshot())
}
