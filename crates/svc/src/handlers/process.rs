// SPDX-License-Identifier: GPL-3.0-or-later
//! `process.list`：运行中的进程，以及它们命中当前会话方案的哪个进程组（F1：从进程列表添加规则）。
//!
//! 服务以 LocalSystem 运行，能看到所有登录用户的进程；这里只列出与调用者（界面）同一 Windows 会话的进程，
//! 不把其他用户会话里的进程透露给界面。拿不到路径的进程（受保护进程等）路径为空。

use std::cmp::Ordering;

use procroute_platform_win::process::{list_processes, process_image_path, process_session_id};
use procroute_proto::Empty;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::event::{ProcessInfo, ProcessListResult};
use procroute_proto::session::SessionState;
use procroute_rules::engine::RuleEngine;
use procroute_rules::matcher::NormalizedProcess;
use serde_json::Value;

use super::{Services, blocking, store_error, to_json};
use crate::ipc_server::{Caller, parse_params};

pub(super) async fn list(
    svc: &Services,
    params: Value,
    caller: &Caller,
) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    let engine = active_engine(svc).await?;
    let caller_pid = caller.pid;
    let mut processes = blocking(move || {
        let session = process_session_id(caller_pid).map_err(|e| {
            IpcError::new(
                ErrorCode::Internal,
                format!("cannot determine the caller's session: {e}"),
            )
        })?;
        let entries = list_processes().map_err(|e| {
            IpcError::new(ErrorCode::Internal, format!("cannot list processes: {e}"))
        })?;
        Ok(entries
            .into_iter()
            // PID 0 是系统空闲进程
            .filter(|e| e.pid != 0 && process_session_id(e.pid).ok() == Some(session))
            .map(|e| ProcessInfo {
                path: process_image_path(e.pid).unwrap_or_default(),
                pid: e.pid,
                name: e.name,
                matched_group: None,
            })
            .collect::<Vec<_>>())
    })
    .await?;
    if let Some(engine) = engine {
        for p in &mut processes {
            p.matched_group = engine
                .decide(&NormalizedProcess::new(&p.name, &p.path))
                .group()
                .and_then(|i| engine.group(i))
                .map(|g| g.tag.clone());
        }
    }
    processes.sort_by(compare);
    to_json(ProcessListResult { processes })
}

/// 运行中会话的方案编译成的规则引擎；没有会话时为空。
async fn active_engine(svc: &Services) -> Result<Option<RuleEngine>, IpcError> {
    let status = svc.session_snapshot();
    let Some(id) = status
        .profile_id
        .filter(|_| status.state != SessionState::Stopped)
    else {
        return Ok(None);
    };
    let store = svc.profiles.clone();
    let profile = blocking(move || store.get(&id).map_err(store_error)).await?;
    // 保存时已经校验过；编译失败只说明方案文件被改坏了，不影响列出进程
    Ok(RuleEngine::compile(&profile).ok())
}

/// 命中的排在前面，其余按名称（不区分大小写）、再按 PID 排序。
fn compare(a: &ProcessInfo, b: &ProcessInfo) -> Ordering {
    b.matched_group
        .is_some()
        .cmp(&a.matched_group.is_some())
        .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        .then(a.pid.cmp(&b.pid))
}
