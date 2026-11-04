// SPDX-License-Identifier: GPL-3.0-or-later
//! `session.*`：按方案启停改道（T-058、T-078）。
//!
//! 服务生成配置，经 [`KernelLauncher`] 启动 sing-box，守护进程的状态变化实时写回会话状态并推给界面
//! （C-UI-02）。两种模式：
//!
//! - TUN 模式：sing-box 的 TUN 入站按进程规则分流。`fail_policy = block` 时 sing-box 一退出，TUN 与路由
//!   随之撤销；启动内核之前先经 [`FailClosedGuard`] 装好阻断（服务持有的动态 WFP 过滤器），内核不在时
//!   目标进程的连接被拒绝而不是直连（C-NET-03）；装不上就拒绝启动（`session.fail_closed_unsupported`）。
//!   阻断在会话停止、内核停下之后才撤销。
//! - 精确进程模式（见 [`crate::precise`]）：进程追踪 → 目标集合，sing-box 的本地 SOCKS 入口，回环中继，
//!   最后启动拦截后端。内核不在时中继对新连接回 RST，不直连（C-NET-03）。`allow` 策略下内核放弃重启时
//!   同时撤下拦截，目标进程回到直连，与会话「已结束」的状态一致。拦截后端起不来返回 `driver.not_loaded`。
//!   TCP 经回环中继，UDP（含 53 端口）经 UDP 中继，都转给 sing-box 的本地 SOCKS 入口。

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use procroute_core_mgr::config_gen::{
    GenError, NodeOutbound, Runtime, SocksInbound, generate_precise, generate_tun,
};
use procroute_core_mgr::runtime::{free_loopback_port, random_api_secret};
use procroute_core_mgr::supervisor::{KernelState, StopReason};
use procroute_intercept::divert::socket::{ProcessResolver, SystemProcesses};
use procroute_intercept::{ExclusionSet, InterceptSettings, Interceptor, StartContext};
use procroute_platform_win::secret::Secret;
use procroute_procwatch::watcher::{Options, Watcher};
use procroute_proto::Empty;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::profile::{FailPolicy, Mode, Profile};
use procroute_proto::session::{
    BlockedReason, ComponentState, ComponentStatus, SessionStartParams, SessionState, SessionStatus,
};
use procroute_rules::engine::RuleEngine;
use serde_json::Value;

use super::{Services, blocking, node, store_error, to_json};
use crate::conn_watch::{Classifier, ConnWatch, POLL_INTERVAL};
use crate::events::EventHub;
use crate::fail_closed::{FailClosedGuard, GuardHandle};
use crate::ipc_server::parse_params;
use crate::kernel::{RunningKernel, StateCallback};
use crate::precise::{
    GroupLabels, NatMap, RelaySet, Targets, UdpBridge, new_nat, resolve_servers, spawn_conn_events,
};

/// 后端的流事件通道容量。满了丢事件并计数（拦截层不阻塞收包线程，C-CODE-05）。
const FLOW_EVENT_QUEUE: usize = 4096;
/// 解析节点服务器地址（写进排除表）最多等这么久。
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(2);

/// 精确模式的拦截后端。内核放弃重启时的回调（`allow` 策略）也要能撤下它，所以与会话共用。
type SharedBackend = Arc<std::sync::Mutex<Option<Box<dyn Interceptor>>>>;

/// 运行中的会话：内核、TUN 模式下读取内核连接列表的轮询（连接面板）与 `block` 策略的阻断，
/// 或精确模式的各个组件。
pub(super) struct RunningSession {
    kernel: Box<dyn RunningKernel>,
    conn_watch: Option<ConnWatch>,
    guard: Option<Box<dyn GuardHandle>>,
    precise: Option<PreciseRun>,
}

/// 精确模式会话的组件。
struct PreciseRun {
    backend: SharedBackend,
    relays: RelaySet,
    udp: Arc<UdpBridge>,
    watcher: Watcher,
    events: Option<std::thread::JoinHandle<()>>,
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
    let running = match profile.mode {
        Mode::Tun => start_tun(svc, &profile).await?,
        Mode::Precise => start_precise(svc, &profile).await?,
    };
    let precise = running.precise.is_some();
    *slot = Some(running);
    let status = svc.hub.update_session(|s| {
        s.state = SessionState::Running;
        s.components.kernel = ComponentState::Active;
        if precise {
            s.components.driver = ComponentState::Active;
        }
    });
    let mode = if precise { "precise" } else { "tun" };
    tracing::info!(profile = %profile.id, mode, "session started");
    to_json(status)
}

async fn start_tun(svc: &Services, profile: &Profile) -> Result<RunningSession, IpcError> {
    let config = tun_config(svc, profile).await?;
    // 先装阻断再启动内核：从第一个包起就不会直连
    let guard = match profile.fail_policy {
        FailPolicy::Block => Some(install_guard(svc.guard.clone(), profile).await?),
        FailPolicy::Allow => None,
    };
    let epoch = svc.epoch.fetch_add(1, Ordering::SeqCst) + 1;
    svc.hub.update_session(|s| *s = starting(profile));
    let on_state = state_callback(
        svc.hub.clone(),
        svc.epoch.clone(),
        epoch,
        profile.fail_policy,
        None,
    );
    let api = SocketAddr::from((Ipv4Addr::LOCALHOST, config.api_port));
    let kernel = match launch_kernel(svc, config.text, api, on_state).await {
        Ok(kernel) => kernel,
        Err(e) => {
            stop_guard(guard).await;
            return Err(e);
        }
    };
    let conn_watch = match Classifier::new(profile, config.node_names) {
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
    Ok(RunningSession {
        kernel,
        conn_watch,
        guard,
        precise: None,
    })
}

async fn start_precise(svc: &Services, profile: &Profile) -> Result<RunningSession, IpcError> {
    let config = precise_config(svc, profile).await?;
    let engine = |p: &Profile| {
        RuleEngine::compile(p)
            .map_err(|e| IpcError::new(ErrorCode::ProfileInvalidSchema, e.to_string()))
    };
    let inherit = profile.groups.iter().map(|g| g.include_children).collect();
    let targets = Arc::new(Targets::new(engine(profile)?, inherit, &config.self_paths));
    let watch_engine = engine(profile)?;
    let epoch = svc.epoch.fetch_add(1, Ordering::SeqCst) + 1;
    svc.hub.update_session(|s| *s = starting(profile));

    // 1. 进程追踪：第一次快照在返回前完成，已运行的目标进程从一开始就在集合里
    let watch_targets = Arc::clone(&targets);
    let watcher = tokio::task::spawn_blocking(move || {
        Watcher::start(watch_engine, Options::default(), move |changes| {
            watch_targets.apply(changes);
        })
    })
    .await;
    let watcher = match watcher {
        Ok(Ok(w)) => w,
        Ok(Err(e)) => {
            return Err(abort_start(
                svc,
                ErrorCode::Internal,
                format!("process tracking failed: {e}"),
            ));
        }
        Err(e) => {
            return Err(abort_start(
                svc,
                ErrorCode::Internal,
                format!("process tracking failed: {e}"),
            ));
        }
    };

    // 2. 内核：`allow` 策略下放弃重启时撤下拦截
    let backend: SharedBackend = Arc::default();
    let give_up: Option<Arc<dyn Fn() + Send + Sync>> = match profile.fail_policy {
        FailPolicy::Allow => {
            let backend = Arc::clone(&backend);
            Some(Arc::new(move || stop_backend(&backend)))
        }
        FailPolicy::Block => None,
    };
    let on_state = state_callback(
        svc.hub.clone(),
        svc.epoch.clone(),
        epoch,
        profile.fail_policy,
        give_up,
    );
    let api = SocketAddr::from((Ipv4Addr::LOCALHOST, config.api_port));
    let kernel = match launch_kernel(svc, config.text, api, on_state).await {
        Ok(kernel) => kernel,
        Err(e) => {
            stop_watcher(watcher).await;
            return Err(e);
        }
    };

    // 3. 回环中继
    let nat = new_nat(profile.fail_policy);
    let group_tags: Arc<[String]> = profile.groups.iter().map(|g| g.tag.clone()).collect();
    let socks = SocketAddr::from((Ipv4Addr::LOCALHOST, config.socks_port));
    // UDP 中继（每个会话一个 SOCKS5 UDP ASSOCIATE）
    let udp = UdpBridge::new(
        socks,
        config.socks_password.clone(),
        Arc::clone(&group_tags),
    );
    let relays =
        match RelaySet::start(socks, config.socks_password, group_tags, Arc::clone(&nat)).await {
            Ok(r) => r,
            Err(e) => {
                stop_kernel(kernel).await;
                stop_watcher(watcher).await;
                return Err(abort_start(
                    svc,
                    ErrorCode::Internal,
                    format!("cannot start the relay: {e}"),
                ));
            }
        };

    // 4. 拦截后端
    let exclusions = exclusions(config.servers).await;
    let (events_tx, events_rx) = std::sync::mpsc::sync_channel(FLOW_EVENT_QUEUE);
    let ctx = StartContext {
        settings: InterceptSettings {
            fail_policy: profile.fail_policy,
            udp_enabled: profile.udp.enabled,
            block_quic: profile.udp.block_quic,
            hijack_port53: profile.dns.hijack_port53,
        },
        exclusions,
        policy: Arc::clone(&targets) as _,
        events: events_tx,
    };
    let mut created = svc.backend.create(
        relays.relays,
        Arc::new(NatMap(nat)),
        Some(Arc::clone(&udp) as _),
    );
    let started = tokio::task::spawn_blocking(move || {
        let r = created.start(ctx);
        (created, r)
    })
    .await;
    match started {
        Ok((b, Ok(()))) => {
            *backend.lock().unwrap_or_else(PoisonError::into_inner) = Some(b);
        }
        failed => {
            let message = match failed {
                Ok((_, Err(e))) => e.to_string(),
                Err(e) => e.to_string(),
                Ok((_, Ok(()))) => String::new(),
            };
            relays.stop().await;
            stop_kernel(kernel).await;
            stop_watcher(watcher).await;
            tracing::error!(error = %message, "the interception backend failed to start");
            return Err(abort_start(
                svc,
                ErrorCode::DriverNotLoaded,
                format!("the interception driver failed to start: {message}"),
            ));
        }
    }

    // 5. 连接面板
    let events = spawn_conn_events(events_rx, svc.hub.clone(), targets, config.labels)
        .map_err(|e| tracing::error!(error = %e, "cannot start the connection events thread"))
        .ok();
    Ok(RunningSession {
        kernel,
        conn_watch: None,
        guard: None,
        precise: Some(PreciseRun {
            backend,
            relays,
            udp,
            watcher,
            events,
        }),
    })
}

/// 启动中途失败：作废这次启动的回调，会话回到初始状态，返回错误。
fn abort_start(svc: &Services, code: ErrorCode, message: String) -> IpcError {
    svc.epoch.fetch_add(1, Ordering::SeqCst);
    svc.hub.update_session(|s| *s = initial_status());
    IpcError::new(code, message)
}

/// 启动内核并等控制 API 就绪。失败时作废回调、复位会话状态。
async fn launch_kernel(
    svc: &Services,
    text: Secret<String>,
    api: SocketAddr,
    on_state: StateCallback,
) -> Result<Box<dyn RunningKernel>, IpcError> {
    let launcher = svc.launcher.clone();
    let launched = tokio::task::spawn_blocking(move || launcher.launch(text, api, on_state)).await;
    match launched {
        Ok(Ok(kernel)) => Ok(kernel),
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
        Err(e) => Err(abort_start(
            svc,
            ErrorCode::Internal,
            format!("kernel launcher failed: {e}"),
        )),
    }
}

/// 排除表：服务自身，加上节点服务器解析出的地址（C-NET-05）。sing-box 已按可执行文件排除在目标之外。
async fn exclusions(servers: Vec<(String, u16)>) -> ExclusionSet {
    let resolved = tokio::time::timeout(
        RESOLVE_TIMEOUT,
        tokio::task::spawn_blocking(move || resolve_servers(&servers)),
    )
    .await;
    let ips = match resolved {
        Ok(Ok(ips)) => ips,
        _ => {
            tracing::warn!("resolving node servers timed out; excluding by process only");
            Vec::new()
        }
    };
    let me = SystemProcesses.resolve(std::process::id());
    ExclusionSet::new(me, ips)
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

/// 精确模式先撤下拦截（目标进程回到直连）再停中继与追踪；然后停连接轮询（为剩余连接发「已关闭」）、
/// 停内核，最后撤销阻断。
async fn stop_session(running: RunningSession) {
    if let Some(p) = running.precise {
        let backend = p.backend;
        let _ = tokio::task::spawn_blocking(move || stop_backend(&backend)).await;
        p.udp.shutdown();
        p.relays.stop().await;
        stop_watcher(p.watcher).await;
        if let Some(t) = p.events {
            let _ = tokio::task::spawn_blocking(move || t.join()).await;
        }
    }
    if let Some(watch) = running.conn_watch {
        watch.stop().await;
    }
    stop_kernel(running.kernel).await;
    stop_guard(running.guard).await;
}

/// 撤下拦截后端（撤销全部过滤器）。阻塞调用。
fn stop_backend(backend: &SharedBackend) {
    let taken = backend
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take();
    if let Some(mut b) = taken
        && let Err(e) = b.stop()
    {
        tracing::warn!(error = %e, "stopping the interception backend failed");
    }
}

async fn stop_kernel(kernel: Box<dyn RunningKernel>) {
    if let Err(e) = tokio::task::spawn_blocking(move || kernel.stop()).await {
        tracing::error!(error = %e, "stopping the kernel failed");
    }
}

async fn stop_watcher(watcher: Watcher) {
    let _ = tokio::task::spawn_blocking(move || watcher.stop()).await;
}

async fn install_guard(
    guard: Arc<dyn FailClosedGuard>,
    profile: &Profile,
) -> Result<Box<dyn GuardHandle>, IpcError> {
    let profile = profile.clone();
    match tokio::task::spawn_blocking(move || guard.install(&profile)).await {
        Ok(Ok(handle)) => Ok(handle),
        Ok(Err(e)) => {
            tracing::error!(error = %e, "cannot install the fail-closed filters");
            Err(IpcError::new(
                ErrorCode::SessionFailClosedUnsupported,
                format!("cannot install the fail-closed filters: {e}"),
            ))
        }
        Err(e) => Err(IpcError::new(
            ErrorCode::Internal,
            format!("fail-closed installer failed: {e}"),
        )),
    }
}

async fn stop_guard(guard: Option<Box<dyn GuardHandle>>) {
    if let Some(guard) = guard
        && let Err(e) = tokio::task::spawn_blocking(move || guard.stop()).await
    {
        tracing::error!(error = %e, "removing the fail-closed filters failed");
    }
}

/// 两种模式共用的出站与运行参数。
struct Outbounds {
    nodes: Vec<NodeOutbound>,
    /// 节点 id（出站标签）→ 节点名，连接面板显示用。
    names: HashMap<String, String>,
    /// 节点服务器的域名或地址与端口，写进排除表用。
    servers: Vec<(String, u16)>,
    runtime: Runtime,
    api_port: u16,
    /// 控制 API 密钥，TUN 模式的连接轮询要用。
    api_secret: Secret<String>,
}

/// 节点按 id 作为出站标签，控制 API 用随机端口与密钥（C-NET-08）。
async fn outbounds(svc: &Services) -> Result<Outbounds, IpcError> {
    let nodes = svc.nodes.clone();
    let stored = blocking(move || nodes.load().map_err(node::storage_error)).await?;
    let names = stored
        .iter()
        .map(|n| (n.id.clone(), n.name.clone()))
        .collect();
    let servers = stored
        .iter()
        .map(|n| (n.node.server.clone(), n.node.server_port))
        .collect();
    let nodes: Vec<NodeOutbound> = stored
        .into_iter()
        .map(|n| NodeOutbound {
            tag: n.id,
            node: n.node,
            credentials: n.credentials,
        })
        .collect();
    let api_port = loopback_port()?;
    let api_secret = secret()?;
    let runtime = Runtime {
        api_port,
        api_secret: api_secret.clone(),
        self_exe_paths: svc.self_exe_paths.clone(),
    };
    Ok(Outbounds {
        nodes,
        names,
        servers,
        runtime,
        api_port,
        api_secret,
    })
}

fn loopback_port() -> Result<u16, IpcError> {
    free_loopback_port()
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("no free loopback port: {e}")))
}

fn secret() -> Result<Secret<String>, IpcError> {
    random_api_secret().map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
}

struct TunConfig {
    text: Secret<String>,
    api_port: u16,
    api_secret: Secret<String>,
    node_names: HashMap<String, String>,
}

async fn tun_config(svc: &Services, profile: &Profile) -> Result<TunConfig, IpcError> {
    let o = outbounds(svc).await?;
    let text = generate_tun(profile, &o.nodes, &[], &o.runtime).map_err(gen_error)?;
    Ok(TunConfig {
        text,
        api_port: o.api_port,
        api_secret: o.api_secret,
        node_names: o.names,
    })
}

struct PreciseConfig {
    text: Secret<String>,
    api_port: u16,
    socks_port: u16,
    socks_password: Secret<String>,
    servers: Vec<(String, u16)>,
    /// 进程组下标 → （组标签, 出站显示名）。
    labels: GroupLabels,
    /// ProcRoute 自身的可执行文件（服务、界面、sing-box），永远不是目标。
    self_paths: Vec<String>,
}

/// 精确模式的 sing-box 配置：本地 SOCKS 入口只绑定 127.0.0.1，端口与密码每次启动随机生成（C-NET-08）。
async fn precise_config(svc: &Services, profile: &Profile) -> Result<PreciseConfig, IpcError> {
    let o = outbounds(svc).await?;
    let socks = SocksInbound {
        port: loopback_port()?,
        password: secret()?,
    };
    let text = generate_precise(profile, &o.nodes, &[], &o.runtime, &socks).map_err(gen_error)?;
    let labels: GroupLabels = profile
        .groups
        .iter()
        .map(|g| {
            let outbound = o
                .names
                .get(&g.outbound)
                .cloned()
                .unwrap_or_else(|| g.outbound.clone());
            (g.tag.clone(), outbound)
        })
        .collect();
    let mut self_paths = svc.self_exe_paths.clone();
    if let Some(kernel) = &svc.diag.kernel_exe {
        self_paths.push(kernel.to_string_lossy().into_owned());
    }
    Ok(PreciseConfig {
        text,
        api_port: o.api_port,
        socks_port: socks.port,
        socks_password: socks.password,
        servers: o.servers,
        labels,
        self_paths,
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
///
/// `give_up`：守护放弃重启时、写回状态之前调用（精确模式的 `allow` 策略用它撤下拦截）。
fn state_callback(
    hub: Arc<EventHub>,
    current: Arc<AtomicU64>,
    epoch: u64,
    policy: FailPolicy,
    give_up: Option<Arc<dyn Fn() + Send + Sync>>,
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
                if let Some(give_up) = &give_up {
                    give_up();
                }
            }
        }
        hub.update_session(|s| apply_kernel_state(s, policy, &state));
    })
}

/// 内核状态 → 会话状态。
///
/// 守护放弃（超出重启上限或无法重新启动）时：`block` 进入 `blocked` 并给出原因，界面必须明确提示
/// 「目标进程网络已阻断」（C-UI-02）；`allow` 是用户显式选择的放行，会话结束，拦截已经撤下。
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
                        components: ComponentStatus {
                            driver: ComponentState::Inactive,
                            ..status.components
                        },
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
