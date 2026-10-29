// SPDX-License-Identifier: GPL-3.0-or-later
//! 各领域的 IPC 处理函数（T-058）。
//!
//! 已接上：`session.*`（TUN 模式，见 [`session`] 模块文档）、`profile.*`、
//! `node.import`（分享链接与订阅）/ `node.list` / `node.test`（见 [`latency`]）、`process.list`。
//! `conn.subscribe` / `log.subscribe` 由管道服务端处理。
//! 尚未接上、如实返回错误而不假装成功的：`driver.*`，随 M2 的拦截后端接入。

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::session::SessionStatus;
use serde::Serialize;
use serde_json::Value;
use tokio::sync::{Mutex, broadcast};

use crate::events::{EventHub, StreamEvent, Subscription};
use crate::fail_closed::FailClosedGuard;
use crate::ipc_server::{Call, Handler};
use crate::kernel::KernelLauncher;
use crate::node_store::NodeStore;
use crate::store::{ProfileStore, StoreError};

mod latency;
mod node;
mod process;
mod profile;
mod session;
mod subscription;

/// 服务的全部状态，由 IPC 服务端共享。
pub struct Services {
    profiles: ProfileStore,
    nodes: NodeStore,
    /// 会话状态与推送事件；会话状态只存在这里。
    hub: Arc<EventHub>,
    launcher: Arc<dyn KernelLauncher>,
    /// TUN 模式 `block` 策略的阻断（C-NET-03）。
    guard: Arc<dyn FailClosedGuard>,
    /// 运行中的内核。启动与停止都持有这把锁，彼此互斥。
    kernel: Mutex<Option<session::RunningSession>>,
    /// 当前会话的编号；旧会话的内核回调发现编号变了就不再改写状态。
    epoch: Arc<AtomicU64>,
    /// ProcRoute 自身的可执行文件，永久直连（C-NET-05）。
    self_exe_paths: Vec<String>,
}

impl Services {
    /// `stream` 是日志与连接事件的发送端：日志层在服务状态之前创建，两者共用。
    pub fn new(
        profiles: ProfileStore,
        nodes: NodeStore,
        stream: broadcast::Sender<StreamEvent>,
        launcher: Arc<dyn KernelLauncher>,
        guard: Arc<dyn FailClosedGuard>,
        self_exe_paths: Vec<String>,
    ) -> Self {
        Self {
            profiles,
            nodes,
            hub: Arc::new(EventHub::with_stream(session::initial_status(), stream)),
            launcher,
            guard,
            kernel: Mutex::new(None),
            epoch: Arc::new(AtomicU64::new(0)),
            self_exe_paths,
        }
    }

    /// 服务退出前停止会话。
    pub async fn shutdown(&self) {
        session::shutdown(self).await;
    }

    /// 当前会话状态的副本。
    fn session_snapshot(&self) -> SessionStatus {
        self.hub.session()
    }
}

impl Handler for Services {
    async fn handle(&self, call: Call<'_>) -> Result<Value, IpcError> {
        let params = call.params;
        match call.method.name {
            "session.status" => session::status(self, params),
            "session.start" => session::start(self, params).await,
            "session.stop" => session::stop(self, params).await,
            "profile.list" => profile::list(self, params).await,
            "profile.get" => profile::get(self, params).await,
            "profile.save" => profile::save(self, params).await,
            "profile.delete" => profile::delete(self, params).await,
            "node.import" => node::import(self, params).await,
            "node.list" => node::list(self, params).await,
            "node.test" => latency::test(self, params).await,
            "process.list" => process::list(self, params, call.caller).await,
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

    fn events(&self) -> Option<Subscription> {
        Some(self.hub.subscribe())
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
