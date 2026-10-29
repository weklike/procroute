// SPDX-License-Identifier: GPL-3.0-or-later
//! `session.*`：按方案启停改道（T-058）。
//!
//! 目前只有 TUN 模式能真正启动：服务生成配置，经 [`KernelLauncher`] 启动 sing-box，
//! 守护进程的状态变化实时写回会话状态并推给界面（C-UI-02）。
//!
//! 如实拒绝、不假装成功的情形：
//! - 精确进程模式：拦截驱动后端（T-071 起）尚未接入，返回 `driver.not_loaded`；
//! - TUN 模式 + `fail_policy = block`：sing-box 一退出（崩溃、重启间隙、超出重启上限），TUN 与路由
//!   随之撤销，目标进程会回落直连，无法满足 C-NET-03，返回 `session.fail_closed_unsupported`。
//!   要支持它，需要一个不依赖 sing-box 存活的阻断手段（见 TASKS.md）。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use procroute_core_mgr::config_gen::{GenError, NodeOutbound, Runtime, generate_tun};
use procroute_core_mgr::runtime::{free_loopback_port, random_api_secret};
use procroute_core_mgr::supervisor::{KernelState, StopReason};
use procroute_proto::Empty;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::profile::{FailPolicy, Mode, Profile};
use procroute_proto::session::{
    BlockedReason, ComponentState, ComponentStatus, SessionStartParams, SessionState, SessionStatus,
};
use serde_json::Value;

use super::{Services, blocking, node, store_error, to_json};
use crate::conn_watch::{Classifier, ConnWatch, POLL_INTERVAL};
use crate::events::EventHub;
use crate::ipc_server::parse_params;
use crate::kernel::{RunningKernel, StateCallback};

/// 运行中的会话：内核，以及 TUN 模式下读取内核连接列表的轮询（连接面板）。
pub(super) struct RunningSession {
    kernel: Box<dyn RunningKernel>,
    conn_watch: Option<ConnWatch>,
}

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

pub(super) async fn start(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let SessionStartParams { profile_id } = parse_params(params)?;
    // 整个启动过程持有内核槽位的锁：启动与停止互斥
    let mut slot = svc.kernel.lock().await;
    if svc.session_snapshot().state != SessionState::Stopped {
        return Err(IpcError::new(
            ErrorCode::SessionAlreadyRunning,
            "a session is already running",
        ));
    }
    // 上一个会话的内核超出重启上限后，守护已经结束，这里只做收尾
    if let Some(stale) = slot.take() {
        stop_session(stale).await;
    }
    let store = svc.profiles.clone();
    let profile = blocking(move || store.get(&profile_id).map_err(store_error)).await?;
    check_supported(&profile)?;
    let config = tun_config(svc, &profile).await?;

    let epoch = svc.epoch.fetch_add(1, Ordering::SeqCst) + 1;
    svc.hub.update_session(|s| *s = starting(&profile));
    let on_state = state_callback(
        svc.hub.clone(),
        svc.epoch.clone(),
        epoch,
        profile.fail_policy,
    );
    let launcher = svc.launcher.clone();
    let api = SocketAddr::from((Ipv4Addr::LOCALHOST, config.api_port));
    let text = config.text;
    let launched = tokio::task::spawn_blocking(move || launcher.launch(text, api, on_state)).await;
    match launched {
        Ok(Ok(kernel)) => {
            let conn_watch = match Classifier::new(&profile, config.node_names) {
                Ok(classifier) => Some(ConnWatch::spawn(
                    svc.hub.clone(),
                    api,
                    config.api_secret,
                    classifier,
                    POLL_INTERVAL,
                )),
                Err(e) => {
                    // 方案已通过校验，不会走到这里；连接面板没有数据，会话照常运行
                    tracing::error!(error = %e, "cannot attribute connections");
                    None
                }
            };
            *slot = Some(RunningSession { kernel, conn_watch });
            let status = svc.hub.update_session(|s| {
                s.state = SessionState::Running;
                s.components.kernel = ComponentState::Active;
            });
            tracing::info!(profile = %profile.id, mode = "tun", "session started");
            to_json(status)
        }
        Ok(Err(e)) => {
            svc.epoch.fetch_add(1, Ordering::SeqCst);
            svc.hub.update_session(|s| {
                *s = initial_status();
                s.components.kernel = ComponentState::Failed;
            });
            tracing::warn!(error = %e, "sing-box failed to start");
            Err(IpcError::new(
                ErrorCode::KernelUnavailable,
                format!("sing-box failed to start: {e}"),
            ))
        }
        Err(e) => {
            svc.epoch.fetch_add(1, Ordering::SeqCst);
            svc.hub.update_session(|s| *s = initial_status());
            Err(IpcError::new(
                ErrorCode::Internal,
                format!("kernel launcher failed: {e}"),
            ))
        }
    }
}

pub(super) async fn stop(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    let mut slot = svc.kernel.lock().await;
    if svc.session_snapshot().state == SessionState::Stopped && slot.is_none() {
        return Err(IpcError::new(
            ErrorCode::SessionNotRunning,
            "no session is running",
        ));
    }
    // 先作废旧会话的回调，停止过程中守护上报的状态不再改写会话
    svc.epoch.fetch_add(1, Ordering::SeqCst);
    svc.hub.update_session(|s| s.state = SessionState::Stopping);
    if let Some(running) = slot.take() {
        stop_session(running).await;
    }
    let status = svc.hub.update_session(|s| *s = initial_status());
    tracing::info!("session stopped");
    to_json(status)
}

/// 服务退出前停止内核。内核也会随作业对象在服务退出时被终止，这里只是让退出更干净。
pub(super) async fn shutdown(svc: &Services) {
    let mut slot = svc.kernel.lock().await;
    svc.epoch.fetch_add(1, Ordering::SeqCst);
    if let Some(running) = slot.take() {
        stop_session(running).await;
    }
}

/// 先停连接轮询（为剩余连接发「已关闭」），再停内核。
async fn stop_session(running: RunningSession) {
    if let Some(watch) = running.conn_watch {
        watch.stop().await;
    }
    let kernel = running.kernel;
    if let Err(e) = tokio::task::spawn_blocking(move || kernel.stop()).await {
        tracing::error!(error = %e, "stopping the kernel failed");
    }
}

/// 拒绝当前还不能安全运行的组合（见模块文档）。
fn check_supported(profile: &Profile) -> Result<(), IpcError> {
    match (profile.mode, profile.fail_policy) {
        (Mode::Precise, _) => Err(IpcError::new(
            ErrorCode::DriverNotLoaded,
            "precise mode needs the interception driver, which is not available in this build yet",
        )),
        (Mode::Tun, FailPolicy::Block) => Err(IpcError::new(
            ErrorCode::SessionFailClosedUnsupported,
            "TUN mode cannot keep target processes blocked while sing-box is down",
        )),
        (Mode::Tun, FailPolicy::Allow) => Ok(()),
    }
}

struct TunConfig {
    text: procroute_platform_win::secret::Secret<String>,
    api_port: u16,
    /// 控制 API 密钥，连接轮询要用。
    api_secret: procroute_platform_win::secret::Secret<String>,
    /// 节点 id（出站标签）→ 节点名，连接面板显示用。
    node_names: HashMap<String, String>,
}

/// 生成本次启动的 sing-box 配置：节点按 id 作为出站标签，控制 API 用随机端口与密钥（C-NET-08）。
async fn tun_config(svc: &Services, profile: &Profile) -> Result<TunConfig, IpcError> {
    let nodes = svc.nodes.clone();
    let stored = blocking(move || nodes.load().map_err(node::storage_error)).await?;
    let node_names = stored
        .iter()
        .map(|n| (n.id.clone(), n.name.clone()))
        .collect();
    let outbounds: Vec<NodeOutbound> = stored
        .into_iter()
        .map(|n| NodeOutbound {
            tag: n.id,
            node: n.node,
            credentials: n.credentials,
        })
        .collect();
    let api_port = free_loopback_port()
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("no free loopback port: {e}")))?;
    let api_secret =
        random_api_secret().map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
    let runtime = Runtime {
        api_port,
        api_secret: api_secret.clone(),
        self_exe_paths: svc.self_exe_paths.clone(),
    };
    let text = generate_tun(profile, &outbounds, &[], &runtime).map_err(gen_error)?;
    Ok(TunConfig {
        text,
        api_port,
        api_secret,
        node_names,
    })
}

/// 生成错误的文本只含标签与规则位置，不含凭据，可以直接带给界面。
fn gen_error(e: GenError) -> IpcError {
    let code = match e {
        GenError::UnknownOutbound { .. } => ErrorCode::NodeNotFound,
        GenError::InvalidProfile(_) | GenError::NoGroups | GenError::InvalidRule { .. } => {
            ErrorCode::ProfileInvalidSchema
        }
        _ => {
            tracing::error!(error = %e, "cannot generate the sing-box config");
            ErrorCode::Internal
        }
    };
    IpcError::new(code, e.to_string())
}

fn starting(profile: &Profile) -> SessionStatus {
    SessionStatus {
        state: SessionState::Starting,
        profile_id: Some(profile.id.clone()),
        profile_name: Some(profile.name.clone()),
        mode: Some(profile.mode),
        ..initial_status()
    }
}

/// 守护上报的状态写回会话。`epoch` 不再是当前值时（会话已停止或换了新会话）忽略。
fn state_callback(
    hub: Arc<EventHub>,
    current: Arc<AtomicU64>,
    epoch: u64,
    policy: FailPolicy,
) -> StateCallback {
    Box::new(move |state| {
        if current.load(Ordering::SeqCst) != epoch {
            return;
        }
        match &state {
            KernelState::Running { pid } => tracing::info!(pid, "sing-box running"),
            KernelState::Restarting { attempt } => {
                tracing::warn!(attempt, "sing-box exited unexpectedly; restarting");
            }
            KernelState::Stopped(StopReason::Requested) => {}
            KernelState::Stopped(reason) => {
                tracing::error!(?reason, "sing-box supervision gave up");
            }
        }
        hub.update_session(|s| apply_kernel_state(s, policy, &state));
    })
}

/// 内核状态 → 会话状态。
///
/// 守护放弃（超出重启上限或无法重新启动）时：`block` 进入 `blocked` 并给出原因，界面必须明确提示
/// 「目标进程网络已阻断」（C-UI-02）；`allow` 是用户显式选择的放行，会话结束。
fn apply_kernel_state(status: &mut SessionStatus, policy: FailPolicy, state: &KernelState) {
    let live = matches!(status.state, SessionState::Starting | SessionState::Running);
    match state {
        KernelState::Running { .. } => {
            if live {
                status.state = SessionState::Running;
                status.components.kernel = ComponentState::Active;
            }
        }
        KernelState::Restarting { .. } => {
            if live {
                status.components.kernel = ComponentState::Restarting;
            }
        }
        KernelState::Stopped(StopReason::Requested) => {}
        KernelState::Stopped(_) => {
            if !live {
                return;
            }
            status.components.kernel = ComponentState::Failed;
            match policy {
                FailPolicy::Block => {
                    status.state = SessionState::Blocked;
                    status.blocked_reason = Some(BlockedReason::KernelCrashLoop);
                }
                FailPolicy::Allow => {
                    *status = SessionStatus {
                        components: status.components,
                        ..initial_status()
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use procroute_core_mgr::supervisor::LaunchError;

    use super::*;

    fn running() -> SessionStatus {
        SessionStatus {
            state: SessionState::Running,
            profile_id: Some("p1".into()),
            profile_name: Some("x".into()),
            mode: Some(Mode::Tun),
            components: ComponentStatus {
                service: ComponentState::Active,
                driver: ComponentState::Inactive,
                kernel: ComponentState::Active,
            },
            blocked_reason: None,
        }
    }

    #[test]
    fn restarts_are_reported_and_recovered() {
        let mut s = running();
        apply_kernel_state(
            &mut s,
            FailPolicy::Allow,
            &KernelState::Restarting { attempt: 1 },
        );
        assert_eq!(s.state, SessionState::Running);
        assert_eq!(s.components.kernel, ComponentState::Restarting);
        apply_kernel_state(&mut s, FailPolicy::Allow, &KernelState::Running { pid: 7 });
        assert_eq!(s, running());
    }

    #[test]
    fn crash_loop_blocks_under_block_policy() {
        let mut s = running();
        apply_kernel_state(
            &mut s,
            FailPolicy::Block,
            &KernelState::Stopped(StopReason::CrashLoop),
        );
        assert_eq!(s.state, SessionState::Blocked);
        assert_eq!(s.blocked_reason, Some(BlockedReason::KernelCrashLoop));
        assert_eq!(s.components.kernel, ComponentState::Failed);
        assert_eq!(
            s.profile_id.as_deref(),
            Some("p1"),
            "the blocked session is kept"
        );
    }

    #[test]
    fn crash_loop_ends_the_session_under_allow_policy() {
        let mut s = running();
        let failed = KernelState::Stopped(StopReason::LaunchFailed(LaunchError::HashMismatch));
        apply_kernel_state(&mut s, FailPolicy::Allow, &failed);
        assert_eq!(s.state, SessionState::Stopped);
        assert_eq!(s.profile_id, None);
        assert_eq!(s.components.kernel, ComponentState::Failed);
        assert_eq!(s.blocked_reason, None);
    }

    #[test]
    fn late_events_do_not_touch_a_stopped_session() {
        let mut s = initial_status();
        for state in [
            KernelState::Running { pid: 1 },
            KernelState::Restarting { attempt: 1 },
            KernelState::Stopped(StopReason::CrashLoop),
            KernelState::Stopped(StopReason::Requested),
        ] {
            apply_kernel_state(&mut s, FailPolicy::Block, &state);
            assert_eq!(s, initial_status(), "{state:?}");
        }
    }
}
