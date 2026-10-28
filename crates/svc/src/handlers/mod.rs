// SPDX-License-Identifier: GPL-3.0-or-later
//! 各领域的 IPC 处理函数（T-058）。
//!
//! 已接上：`session.status` / `session.stop`、`profile.*`。
//! 尚未接上、如实返回错误而不假装成功的：
//! - `session.start`：需要 core-mgr（T-055，等待锁定 sing-box 版本）；
//! - `node.*`：分享链接解析、订阅拉取与测速尚未实现；
//! - `process.list`、`conn.subscribe`、`log.subscribe`、`driver.*`：随 M2 的各模块接入。

use std::sync::Mutex;

use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::session::SessionStatus;
use serde::Serialize;
use serde_json::Value;

use crate::ipc_server::{Call, Handler};
use crate::store::{ProfileStore, StoreError};

mod profile;
mod session;

/// 服务的全部状态，由 IPC 服务端共享。
pub struct Services {
    profiles: ProfileStore,
    session: Mutex<SessionStatus>,
}

impl Services {
    pub fn new(profiles: ProfileStore) -> Self {
        Self {
            profiles,
            session: Mutex::new(session::initial_status()),
        }
    }

    /// 当前会话状态的副本。锁只在拷贝期间持有。
    fn session_snapshot(&self) -> SessionStatus {
        match self.session.lock() {
            Ok(s) => s.clone(),
            // 持锁线程 panic 过：状态本身仍是一份完整的值，照常使用。
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }
}

impl Handler for Services {
    async fn handle(&self, call: Call<'_>) -> Result<Value, IpcError> {
        let params = call.params;
        match call.method.name {
            "session.status" => session::status(self, params),
            "session.start" => session::start(self, params).await,
            "session.stop" => session::stop(self, params),
            "profile.list" => profile::list(self, params).await,
            "profile.get" => profile::get(self, params).await,
            "profile.save" => profile::save(self, params).await,
            "profile.delete" => profile::delete(self, params).await,
            other => {
                tracing::debug!(
                    method = other,
                    pid = call.caller.pid,
                    "method not wired yet"
                );
                Err(IpcError::new(
                    ErrorCode::Internal,
                    "method is not available in this build yet",
                ))
            }
        }
    }
}

fn to_json<T: Serialize>(value: T) -> Result<Value, IpcError> {
    serde_json::to_value(value).map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
}

/// 在阻塞线程池上运行文件 IO（C-CODE-05）。
async fn blocking<T, F>(f: F) -> Result<T, IpcError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, IpcError> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("worker failed: {e}")))?
}

fn store_error(e: StoreError) -> IpcError {
    match e {
        StoreError::NotFound => IpcError::new(ErrorCode::ProfileNotFound, "profile not found"),
        StoreError::InvalidId => IpcError::new(ErrorCode::IpcInvalidParams, "invalid profile id"),
        other => {
            tracing::error!(error = %other, "profile storage failure");
            IpcError::new(ErrorCode::Internal, "profile storage failure")
        }
    }
}

#[cfg(test)]
mod tests;
