// SPDX-License-Identifier: GPL-3.0-or-later
//! SOCKET 层归属（T-072，设计文档 6.1 第 2 步）。
//!
//! 以只嗅探方式（`SNIFF | RECV_ONLY`）打开 WinDivert 的 SOCKET 层，收 TCP / UDP 的 CONNECT 与 CLOSE 事件：
//!
//! - CONNECT：事件带 PID、本地端口与远端，补上进程创建时间组成进程身份（C-DRV-04）后按 [`decide`] 判定；
//!   要改道或阻断的目标流登记进 [`FlowTable`]，NETWORK 层（T-075）按出站包查它；
//! - 非目标进程只读这些元数据，不改写、不延迟（C-NET-02）。同一键上残留的旧登记随之清掉，
//!   端口被非目标进程复用时不会被误改道；
//! - CLOSE：撤销该套接字的登记。
//!
//! 每条流在这里判定一次，计数器（含 `attribution_miss`）也在这里记一次。
//!
//! 事件按连接计、不按包计。登记表按本地端口分片加锁：NETWORK 层逐包查询时只锁一个分片、
//! 不分配内存（C-CODE-04）。收事件在专用 OS 线程（C-CODE-05）。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};
use std::thread::JoinHandle;

use procroute_platform_win::process::process_creation_time;
use procroute_proto::event::Network;
use thiserror::Error;

use super::ffi::{Address, DivertError, Handle, Layer, Param, Shutdown, WinDivert, event, flags};
use crate::backend::{Counters, FlowPolicy, InterceptSettings, Verdict, decide};
use crate::exclude::ExclusionSet;
use crate::flow::{FlowKey, NewFlow, ProcessKey};

/// SOCKET 层过滤器：TCP / UDP 的 CONNECT 与 CLOSE。回环连接永不改道（C-NET-05），在驱动里就滤掉。
pub const FILTER: &str = "(event == CONNECT or event == CLOSE) and (tcp or udp) and not loopback";

/// 事件队列长度取上限（`WINDIVERT_PARAM_QUEUE_LENGTH_MAX`），突发大量连接时少丢事件。
const QUEUE_LENGTH: u64 = 16_384;

/// 登记表默认上限，与 NAT 表一致（C-PERF-04）。
pub const DEFAULT_CAPACITY: usize = 65_536;

/// 登记表的分片数。按本地端口取模，临时端口顺序分配，各分片大致均匀。
const SHARDS: usize = 64;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// SOCKET 层的一个事件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketEvent {
    Connect { pid: u32, key: FlowKey },
    Close { pid: u32, key: FlowKey },
}

/// 解码 SOCKET 层地址。不是 SOCKET 层、不是 CONNECT / CLOSE、不是 TCP / UDP 时返回 `None`。
pub fn decode(addr: &Address) -> Option<SocketEvent> {
    if addr.layer() != Layer::Socket as u8 {
        return None;
    }
    let e = addr.endpoint();
    let network = match e.protocol {
        PROTO_TCP => Network::Tcp,
        PROTO_UDP => Network::Udp,
        _ => return None,
    };
    let key = FlowKey {
        network,
        local: SocketAddr::new(e.local_addr, e.local_port),
        remote: SocketAddr::new(e.remote_addr, e.remote_port),
    };
    let pid = e.process_id;
    match addr.event() {
        event::SOCKET_CONNECT => Some(SocketEvent::Connect { pid, key }),
        event::SOCKET_CLOSE => Some(SocketEvent::Close { pid, key }),
        _ => None,
    }
}

/// 目标流在 NETWORK 层要执行的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetAction {
    /// 改道到本地中继，`group` 为进程组下标。
    Redirect { group: u16 },
    /// 阻断：TCP 回 RST、UDP 丢弃。
    Block,
}

/// 登记表里的一条目标流。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetFlow {
    /// CONNECT 事件里的五元组。
    pub key: FlowKey,
    pub process: ProcessKey,
    pub action: TargetAction,
}

/// 登记表的键：协议 + 本地端口 + 远端。出站包的这三项与 CONNECT 事件一致；本地地址不参与，
/// 免得事件与包里的本地地址写法不同（例如没有显式绑定的双栈套接字）时查不到。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SlotKey {
    network: Network,
    local_port: u16,
    remote_ip: IpAddr,
    remote_port: u16,
}

impl SlotKey {
    fn new(network: Network, local_port: u16, remote: SocketAddr) -> Self {
        Self {
            network,
            local_port,
            remote_ip: remote.ip(),
            remote_port: remote.port(),
        }
    }
}

type Shard = HashMap<SlotKey, TargetFlow>;

/// 目标流登记表：SOCKET 层写，NETWORK 层（T-075）读。
///
/// 只登记目标流；非目标流不进表（C-NET-02）。满了以后拒绝新登记并计数，不淘汰已有的登记。
#[derive(Debug)]
pub struct FlowTable {
    shards: Box<[Mutex<Shard>]>,
    capacity: usize,
    len: AtomicUsize,
    overflows: AtomicU64,
}

impl Default for FlowTable {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }
}

impl FlowTable {
    pub fn new(capacity: usize) -> Self {
        // 预留容量：表不满时登记不扩容
        let per_shard = capacity.div_ceil(SHARDS);
        Self {
            shards: (0..SHARDS)
                .map(|_| Mutex::new(Shard::with_capacity(per_shard)))
                .collect(),
            capacity,
            len: AtomicUsize::new(0),
            overflows: AtomicU64::new(0),
        }
    }

    fn shard(&self, local_port: u16) -> MutexGuard<'_, Shard> {
        // 分片里只有可整体替换的值，持锁的线程 panic 也不会留下改了一半的表项
        self.shards[usize::from(local_port) % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// 登记或覆盖一条目标流。表满且是新键时拒绝并返回 `false`。
    pub fn register(&self, flow: TargetFlow) -> bool {
        let slot = SlotKey::new(flow.key.network, flow.key.local.port(), flow.key.remote);
        let mut shard = self.shard(slot.local_port);
        if let Some(existing) = shard.get_mut(&slot) {
            *existing = flow;
            return true;
        }
        if self.len.load(Ordering::Relaxed) >= self.capacity {
            self.overflows.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        shard.insert(slot, flow);
        self.len.fetch_add(1, Ordering::Relaxed);
        true
    }

    /// 按出站包的协议、本地端口与远端查登记。只锁一个分片，不分配内存（C-CODE-04）。
    pub fn get(&self, network: Network, local_port: u16, remote: SocketAddr) -> Option<TargetFlow> {
        self.shard(local_port)
            .get(&SlotKey::new(network, local_port, remote))
            .copied()
    }

    /// 撤销一条登记（不论属于哪个进程）。
    pub fn unregister(&self, key: &FlowKey) -> Option<TargetFlow> {
        let slot = SlotKey::new(key.network, key.local.port(), key.remote);
        let removed = self.shard(slot.local_port).remove(&slot);
        if removed.is_some() {
            self.len.fetch_sub(1, Ordering::Relaxed);
        }
        removed
    }

    /// 套接字关闭：撤销 `pid` 在这个本地端口上的登记。`remote` 为 `None`（未连接的 UDP 套接字）时
    /// 撤销该端口上的全部登记。返回撤销的条数。
    pub fn forget_socket(
        &self,
        pid: u32,
        network: Network,
        local_port: u16,
        remote: Option<SocketAddr>,
    ) -> usize {
        let mut shard = self.shard(local_port);
        let before = shard.len();
        shard.retain(|k, f| {
            let same_socket = k.network == network
                && k.local_port == local_port
                && remote.is_none_or(|r| (k.remote_ip, k.remote_port) == (r.ip(), r.port()));
            !(same_socket && f.process.pid == pid)
        });
        let removed = before - shard.len();
        self.len.fetch_sub(removed, Ordering::Relaxed);
        removed
    }

    /// 清空（后端停止时）。
    pub fn clear(&self) {
        for shard in &self.shards {
            let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            self.len.fetch_sub(shard.len(), Ordering::Relaxed);
            shard.clear();
        }
    }

    pub fn len(&self) -> usize {
        self.len.load(Ordering::Relaxed)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 因表满被拒绝的登记数。
    pub fn overflows(&self) -> u64 {
        self.overflows.load(Ordering::Relaxed)
    }

    /// 全部登记的副本，供诊断与测试使用（会分配内存，不要用在逐包路径上）。
    pub fn entries(&self) -> Vec<TargetFlow> {
        let mut all = Vec::with_capacity(self.len());
        for shard in &self.shards {
            let shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            all.extend(shard.values().copied());
        }
        all
    }
}

/// 把 PID 补成进程身份（PID + 创建时间，C-DRV-04）。
pub trait ProcessResolver: Send + Sync {
    /// 进程已退出或打不开时返回 `None`，这条流按无法归属处理（C-NET-04）。
    fn resolve(&self, pid: u32) -> Option<ProcessKey>;
}

/// 直接向系统查询（`OpenProcess` + `GetProcessTimes`）。CONNECT 事件产生于 connect 调用期间，
/// 处理时进程通常还在；已经退出的按无法归属处理。
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemProcesses;

impl ProcessResolver for SystemProcesses {
    fn resolve(&self, pid: u32) -> Option<ProcessKey> {
        // PID 0 是 Idle 进程，打不开
        if pid == 0 {
            return None;
        }
        process_creation_time(pid)
            .ok()
            .map(|created_at| ProcessKey { pid, created_at })
    }
}

/// SOCKET 层事件的处理：判定并维护登记表。与收事件的线程分开，不加载驱动也能测试。
pub struct Attributor {
    settings: InterceptSettings,
    exclusions: RwLock<Arc<ExclusionSet>>,
    policy: Arc<dyn FlowPolicy>,
    resolver: Arc<dyn ProcessResolver>,
    table: Arc<FlowTable>,
    counters: Arc<Counters>,
}

impl std::fmt::Debug for Attributor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attributor")
            .field("settings", &self.settings)
            .field("registered", &self.table.len())
            .finish_non_exhaustive()
    }
}

impl Attributor {
    pub fn new(
        settings: InterceptSettings,
        exclusions: ExclusionSet,
        policy: Arc<dyn FlowPolicy>,
        resolver: Arc<dyn ProcessResolver>,
        table: Arc<FlowTable>,
        counters: Arc<Counters>,
    ) -> Self {
        Self {
            settings,
            exclusions: RwLock::new(Arc::new(exclusions)),
            policy,
            resolver,
            table,
            counters,
        }
    }

    /// 整体替换排除表，从下一个事件起生效（C-NET-05）。已登记的流不受影响。
    pub fn set_exclusions(&self, exclusions: ExclusionSet) {
        let mut current = self
            .exclusions
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *current = Arc::new(exclusions);
    }

    fn exclusions(&self) -> Arc<ExclusionSet> {
        Arc::clone(
            &self
                .exclusions
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        )
    }

    pub fn table(&self) -> &Arc<FlowTable> {
        &self.table
    }

    /// 处理一个事件。CONNECT 返回判定结果，CLOSE 返回 `None`。
    pub fn handle(&self, event: SocketEvent) -> Option<Verdict> {
        match event {
            SocketEvent::Connect { pid, key } => Some(self.connect(pid, key)),
            SocketEvent::Close { pid, key } => {
                // 未连接的 UDP 套接字关闭时没有远端
                let remote = (key.remote.port() != 0).then_some(key.remote);
                self.table
                    .forget_socket(pid, key.network, key.local.port(), remote);
                None
            }
        }
    }

    fn connect(&self, pid: u32, key: FlowKey) -> Verdict {
        let process = self.resolver.resolve(pid);
        let flow = NewFlow { key, process };
        let verdict = decide(
            &flow,
            &self.settings,
            &self.exclusions(),
            self.policy.as_ref(),
            &self.counters,
        );
        let action = match verdict {
            Verdict::Redirect { group } => Some(TargetAction::Redirect { group }),
            Verdict::Block => Some(TargetAction::Block),
            Verdict::Bypass(_) => None,
        };
        match (action, process) {
            (Some(action), Some(process)) => {
                self.table.register(TargetFlow {
                    key,
                    process,
                    action,
                });
            }
            // 非目标：只清掉同一键上可能残留的旧登记，其余什么也不做（C-NET-02）
            _ => {
                self.table.unregister(&key);
            }
        }
        verdict
    }
}

#[derive(Debug, Error)]
pub enum MonitorError {
    #[error(transparent)]
    Divert(#[from] DivertError),
    #[error("SOCKET 层句柄设置失败：{0}")]
    Param(io::Error),
    #[error("无法启动 SOCKET 层线程：{0}")]
    Spawn(io::Error),
}

/// 运行中的 SOCKET 层监视：一个只嗅探的句柄和一个收事件的专用线程。丢弃即停止并关闭句柄。
pub struct SocketMonitor {
    handle: Arc<Handle>,
    stopping: Arc<AtomicBool>,
    failure: Arc<OnceLock<io::Error>>,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for SocketMonitor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SocketMonitor")
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl SocketMonitor {
    /// 打开 SOCKET 层句柄（第一次打开句柄时加载驱动，需要管理员权限）并开始收事件。
    pub fn start(api: &Arc<WinDivert>, attributor: Arc<Attributor>) -> Result<Self, MonitorError> {
        let handle =
            Arc::new(api.open(FILTER, Layer::Socket, 0, flags::SNIFF | flags::RECV_ONLY)?);
        handle
            .set_param(Param::QueueLength, QUEUE_LENGTH)
            .map_err(MonitorError::Param)?;
        let stopping = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let thread = {
            let handle = Arc::clone(&handle);
            let stopping = Arc::clone(&stopping);
            let failure = Arc::clone(&failure);
            std::thread::Builder::new()
                .name("divert-socket".to_owned())
                .spawn(move || {
                    if let Some(e) = receive(&handle, &attributor, &stopping) {
                        let _ = failure.set(e);
                    }
                })
                .map_err(MonitorError::Spawn)?
        };
        Ok(Self {
            handle,
            stopping,
            failure,
            thread: Some(thread),
        })
    }

    /// 收事件的线程是否还在运行。
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// 收事件的线程因错误退出时的错误。此后不再有新的归属，上层必须按 fail_policy 处理。
    pub fn failure(&self) -> Option<&io::Error> {
        self.failure.get()
    }

    /// 停止收事件并关闭句柄。登记表不动，由后端决定是否清空。
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(thread) = self.thread.take() {
            self.stopping.store(true, Ordering::Release);
            // 让阻塞在 recv 上的线程返回；失败说明句柄已经不可用，线程也会因 recv 出错而退出
            let _ = self.handle.shutdown(Shutdown::Recv);
            let _ = thread.join();
        }
    }
}

impl Drop for SocketMonitor {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 收事件的循环。正常停止返回 `None`，出错返回错误。
fn receive(handle: &Handle, attributor: &Attributor, stopping: &AtomicBool) -> Option<io::Error> {
    let mut addr = Address::default();
    loop {
        match handle.recv_event(&mut addr) {
            Ok(()) => {
                if let Some(event) = decode(&addr) {
                    attributor.handle(event);
                }
            }
            Err(_) if stopping.load(Ordering::Acquire) => return None,
            Err(e) => return Some(e),
        }
    }
}

#[cfg(test)]
mod tests;
