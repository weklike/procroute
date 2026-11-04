// SPDX-License-Identifier: GPL-3.0-or-later
//! NETWORK 层的收发线程（T-075）与首包竞态的暂存（T-076，C-NET-04）。
//!
//! - 收包线程：多个线程同时在同一个句柄上收包（WinDivert 允许），每个线程的缓冲区在启动时分配好，
//!   逐包交给 [`Engine::process`]，按结果放回、改写后注入或丢弃（C-CODE-04、C-CODE-05）；
//! - 暂存：新流的第一个包（TCP 的 SYN、UDP 的数据报）先于 SOCKET 层事件到达时（[`Outcome::Hold`]），把它
//!   放进预先分配的暂存槽，每 [`PENDING_TICK`] 重新查一次登记表；超过 [`PENDING_LIMIT`] 仍没有归属，就在系统
//!   连接表里反查 PID（TCP 按「本地端口 + 远端」，UDP 按本地地址与端口），交给 [`Attributor::attribute`] 判定。
//!   反查不到的按无法归属放行并计入 `attribution_miss`。暂存槽满了或包放不下，就在收包线程上直接兜底归属；
//! - 暂存线程同时每秒回收一次已收尾的连接（[`Engine::sweep`]）。

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procroute_platform_win::nettable::{tcp_owner_pid, udp_owner_pid};
use procroute_proto::event::Network;

use super::ffi::{Address, Handle, Layer, MTU_MAX, Param, Shutdown, WinDivert};
use super::network::{Engine, Outcome};
use super::socket::{Attributor, MonitorError};
use crate::flow::FlowKey;
use crate::packet;

/// 暂存的 SYN 多久重查一次登记表。
pub const PENDING_TICK: Duration = Duration::from_millis(2);
/// 暂存的上限，之后反查连接表兜底（C-NET-04）。
pub const PENDING_LIMIT: Duration = Duration::from_millis(50);
/// 连接跟踪的回收间隔。
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// 暂存槽数与每槽字节数。SYN 不带数据时不到 100 字节，放不下的（带 TFO 数据、较大的 UDP 数据报）直接兜底归属。
const PENDING_SLOTS: usize = 256;
const PENDING_BYTES: usize = 256;
/// 句柄队列长度取上限（`WINDIVERT_PARAM_QUEUE_LENGTH_MAX`）。
const QUEUE_LENGTH: u64 = 16_384;

struct Pending {
    len: usize,
    buf: [u8; PENDING_BYTES],
    addr: Address,
    since: Instant,
}

/// 暂存区与唤醒暂存线程的条件变量。
struct Holding {
    slots: Mutex<Vec<Pending>>,
    wake: Condvar,
}

struct Shared {
    handle: Handle,
    api: Arc<WinDivert>,
    engine: Arc<Engine>,
    attributor: Arc<Attributor>,
    holding: Holding,
    stopping: AtomicBool,
    failure: OnceLock<io::Error>,
}

/// 运行中的 NETWORK 层：一个句柄、若干收包线程和一个暂存线程。丢弃即停止并关闭句柄（过滤器随之撤销）。
pub struct NetworkWorker {
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for NetworkWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkWorker")
            .field("threads", &self.threads.len())
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl NetworkWorker {
    /// 打开 NETWORK 层句柄并启动 `receivers` 个收包线程（至少一个）与暂存线程。
    pub fn start(
        api: &Arc<WinDivert>,
        engine: Arc<Engine>,
        attributor: Arc<Attributor>,
        receivers: usize,
    ) -> Result<Self, MonitorError> {
        let handle = api.open(&engine.relays().filter(), Layer::Network, 0, 0)?;
        handle
            .set_param(Param::QueueLength, QUEUE_LENGTH)
            .map_err(MonitorError::Param)?;
        let shared = Arc::new(Shared {
            handle,
            api: Arc::clone(api),
            engine,
            attributor,
            holding: Holding {
                slots: Mutex::new(Vec::with_capacity(PENDING_SLOTS)),
                wake: Condvar::new(),
            },
            stopping: AtomicBool::new(false),
            failure: OnceLock::new(),
        });
        let mut worker = Self {
            shared,
            threads: Vec::new(),
        };
        for i in 0..receivers.max(1) {
            let shared = Arc::clone(&worker.shared);
            let t = std::thread::Builder::new()
                .name(format!("divert-net-{i}"))
                .spawn(move || receive(&shared))
                .map_err(MonitorError::Spawn)?;
            worker.threads.push(t);
        }
        let shared = Arc::clone(&worker.shared);
        let t = std::thread::Builder::new()
            .name("divert-pending".to_owned())
            .spawn(move || hold_and_sweep(&shared))
            .map_err(MonitorError::Spawn)?;
        worker.threads.push(t);
        Ok(worker)
    }

    /// 所有线程是否都还在运行。
    pub fn is_running(&self) -> bool {
        !self.threads.is_empty() && self.threads.iter().all(|t| !t.is_finished())
    }

    /// 收包线程因错误退出时的错误。此后目标流不再被改道，上层必须按 fail_policy 处理。
    pub fn failure(&self) -> Option<&io::Error> {
        self.shared.failure.get()
    }

    pub fn engine(&self) -> &Arc<Engine> {
        &self.shared.engine
    }

    /// 在本句柄上注入自己拼的包（UDP 回包）。
    pub fn injector(&self) -> Injector {
        Injector(Arc::clone(&self.shared))
    }

    /// 停止全部线程并关闭句柄。连接跟踪不动，由后端决定是否清空。
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.threads.is_empty() {
            return;
        }
        self.shared.stopping.store(true, Ordering::Release);
        // 让阻塞在 recv 上的线程返回；失败说明句柄已经不可用，线程也会因 recv 出错而退出
        let _ = self.shared.handle.shutdown(Shutdown::Both);
        self.shared.holding.wake.notify_all();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for NetworkWorker {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 在 NETWORK 层句柄上注入包：重算校验和后发送。可以在任何线程上使用。
#[derive(Clone)]
pub struct Injector(Arc<Shared>);

impl std::fmt::Debug for Injector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Injector").finish_non_exhaustive()
    }
}

impl Injector {
    /// 注入一个包。返回是否成功（句柄已关闭、接口已消失时失败，包丢弃）。
    pub fn inject(&self, pkt: &mut [u8], addr: &mut Address) -> bool {
        self.0.api.calc_checksums(pkt, addr) && self.0.handle.send(pkt, addr).is_ok()
    }
}

/// 收包循环。缓冲区只在这里分配一次。
fn receive(shared: &Shared) {
    let mut buf = vec![0u8; MTU_MAX];
    let mut addr = Address::default();
    loop {
        let n = match shared.handle.recv(&mut buf, &mut addr) {
            Ok(n) => n,
            Err(_) if shared.stopping.load(Ordering::Acquire) => return,
            Err(e) => {
                let _ = shared.failure.set(e);
                return;
            }
        };
        let pkt = &mut buf[..n];
        let now = Instant::now();
        match shared.engine.process(pkt, &mut addr, now) {
            Outcome::Hold => {
                if !hold(shared, pkt, addr, now) {
                    // 暂存槽满或包太大：就地兜底归属
                    let outcome = fallback(shared, pkt, &mut addr, now);
                    deliver(shared, pkt, &mut addr, outcome);
                }
            }
            outcome => deliver(shared, pkt, &mut addr, outcome),
        }
    }
}

/// 按处理结果放回、注入或丢弃。注入失败（例如接口刚刚消失）只能丢弃。
fn deliver(shared: &Shared, pkt: &mut [u8], addr: &mut Address, outcome: Outcome) {
    match outcome {
        Outcome::Pass => {
            let _ = shared.handle.send(pkt, addr);
        }
        Outcome::Inject => {
            if shared.api.calc_checksums(pkt, addr) {
                let _ = shared.handle.send(pkt, addr);
            }
        }
        Outcome::Drop | Outcome::Hold => {}
    }
}

/// 放进暂存槽。同一条 TCP 流已经在暂存（重传的 SYN）就丢掉这份；UDP 的每个数据报都是数据，各占一个槽。
/// 放不下返回 `false`。
fn hold(shared: &Shared, pkt: &[u8], addr: Address, now: Instant) -> bool {
    if pkt.len() > PENDING_BYTES {
        return false;
    }
    let Some(key) = flow_key(pkt) else {
        return false;
    };
    let mut slots = shared
        .holding
        .slots
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if key.0 == Network::Tcp && slots.iter().any(|s| flow_key(&s.buf[..s.len]) == Some(key)) {
        return true;
    }
    if slots.len() >= PENDING_SLOTS {
        return false;
    }
    let mut buf = [0u8; PENDING_BYTES];
    buf[..pkt.len()].copy_from_slice(pkt);
    slots.push(Pending {
        len: pkt.len(),
        buf,
        addr,
        since: now,
    });
    shared.holding.wake.notify_one();
    true
}

/// 暂存的包的（协议, 源端口, 目的地址）。
fn flow_key(pkt: &[u8]) -> Option<(Network, u16, SocketAddr)> {
    let mut copy = [0u8; PENDING_BYTES];
    let len = pkt.len().min(PENDING_BYTES);
    copy[..len].copy_from_slice(&pkt[..len]);
    let p = packet::parse(&mut copy[..len]).ok()?;
    Some((p.network(), p.src().port(), p.dst()))
}

/// 兜底归属：反查连接表拿 PID 后判定登记，再交给引擎。反查不到按无法归属（PID 0）判定。
fn fallback(shared: &Shared, pkt: &mut [u8], addr: &mut Address, now: Instant) -> Outcome {
    let Ok(p) = packet::parse(pkt) else {
        return Outcome::Pass;
    };
    let (network, src, dst) = (p.network(), p.src(), p.dst());
    let owner = match network {
        Network::Tcp => tcp_owner_pid(src.port(), dst),
        Network::Udp => udp_owner_pid(src),
    };
    let pid = owner.ok().flatten().unwrap_or(0);
    let key = FlowKey {
        network,
        local: src,
        remote: dst,
    };
    shared.attributor.attribute(pid, key);
    match shared.engine.process(pkt, addr, now) {
        // 登记表满、登记被拒：已按无法归属计数，放行
        Outcome::Hold => Outcome::Pass,
        outcome => outcome,
    }
}

/// 暂存线程：重查暂存的包，超时兜底归属；每秒回收一次连接跟踪。
fn hold_and_sweep(shared: &Shared) {
    let mut last_sweep = Instant::now();
    let mut ready: Vec<Pending> = Vec::with_capacity(PENDING_SLOTS);
    while !shared.stopping.load(Ordering::Acquire) {
        {
            let slots = shared
                .holding
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let wait = if slots.is_empty() {
                SWEEP_INTERVAL
            } else {
                PENDING_TICK
            };
            let (mut slots, _) = shared
                .holding
                .wake
                .wait_timeout(slots, wait)
                .unwrap_or_else(PoisonError::into_inner);
            // 取出全部，锁外处理；仍要等的再放回
            ready.extend(slots.drain(..));
        }
        let now = Instant::now();
        let mut keep = Vec::new();
        for mut p in ready.drain(..) {
            let len = p.len;
            let outcome = match shared.engine.process(&mut p.buf[..len], &mut p.addr, now) {
                Outcome::Hold if now.saturating_duration_since(p.since) < PENDING_LIMIT => {
                    keep.push(p);
                    continue;
                }
                Outcome::Hold => fallback(shared, &mut p.buf[..len], &mut p.addr, now),
                outcome => outcome,
            };
            deliver(shared, &mut p.buf[..len], &mut p.addr, outcome);
        }
        if !keep.is_empty() {
            shared
                .holding
                .slots
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(keep);
        }
        if now.saturating_duration_since(last_sweep) >= SWEEP_INTERVAL {
            shared.engine.sweep(now);
            last_sweep = now;
        }
    }
}
