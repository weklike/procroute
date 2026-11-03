// SPDX-License-Identifier: GPL-3.0-or-later
//! NETWORK 层：把目标 TCP 流改道到回环中继，回程反向改写（T-075，设计文档 6.1 第 3、5 步）。
//!
//! 抓本机全部出站 TCP（不含回环，2026-11-03 定）与中继发回的回环包：
//!
//! - 应用 → 原始目标：
//!   - 已跟踪的连接：改写成「回环:映射端口 → 回环:中继端口」后出站注入，协议栈把它送进回环上的中继。
//!     映射端口就是应用的源端口，中继按它查 NAT 表；
//!   - 新连接的第一个 SYN：取 SOCKET 层的登记（[`FlowTable::take_for_syn`]）。改道的先经 [`RedirectMap`]
//!     登记进中继的 NAT 表再改写；阻断的丢弃；放行的原样放回；还没有登记的交给调用方暂存（C-NET-04）；
//!   - 其余的包（非目标、改道开始前已建立的连接）只读五元组，原样放回（C-NET-02）。
//! - 中继 → 应用：按映射端口取回连接，改写成「原始目标 → 应用」，在原来的接口上入站注入。
//!
//! 连接跟踪按 FIN / RST 回收：双方都 FIN 后再留 30 秒、RST 后再留 5 秒，接住迟到的 ACK 与重传，免得它们
//! 被当成「不认识的连接」直接发往原始目标；没有收尾的连接空闲两小时后回收。回收时发出 `Closed`，并撤销
//! NAT 表项。
//!
//! 处理不了的目标包（登记 NAT 失败、映射端口被占、没有对应地址族的中继）按 fail_policy（C-NET-07）。
//! 逐包路径只锁一个分片、不分配内存、不写日志（C-CODE-04）。

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use procroute_proto::event::Network;
use procroute_proto::profile::FailPolicy;

use super::ffi::{Address, NetworkData};
use super::socket::{FlowAction, FlowRecord, FlowTable};
use crate::backend::{Counters, Verdict, emit, unprocessable};
use crate::flow::{FlowEvent, FlowKey, ProcessKey};
use crate::packet::{self, Packet, tcp_flags};

/// 双方都 FIN 之后连接跟踪再保留的时间。
pub const FIN_LINGER: Duration = Duration::from_secs(30);
/// RST 之后连接跟踪再保留的时间。
pub const RST_LINGER: Duration = Duration::from_secs(5);
/// 没有收尾的连接空闲这么久后回收（与 Windows 的 TCP keepalive 默认间隔一致）。
pub const IDLE_LIMIT: Duration = Duration::from_secs(2 * 60 * 60);

const SHARDS: usize = 64;
/// 连接跟踪表每个分片预留的容量：映射端口最多 65536 个。
const PER_SHARD: usize = 65_536 / SHARDS;

/// 中继在回环上的监听地址。IPv6 中继可以没有，那样 IPv6 目标流按 fail_policy 处理。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relays {
    pub v4: SocketAddr,
    pub v6: Option<SocketAddr>,
}

impl Relays {
    fn for_family(&self, ip: IpAddr) -> Option<SocketAddr> {
        match ip {
            IpAddr::V4(_) => Some(self.v4),
            IpAddr::V6(_) => self.v6,
        }
    }

    fn is_relay_port(&self, port: u16) -> bool {
        port == self.v4.port() || self.v6.is_some_and(|v6| v6.port() == port)
    }

    /// NETWORK 层过滤器：出站的非回环 TCP，加上中继发回的回环包（回环包只出现在出站方向）。
    /// 其他驱动注入的包（impostor）不抓，免得与别的改道工具互相转圈。
    pub fn filter(&self) -> String {
        let relay_ports = match self.v6 {
            Some(v6) if v6.port() != self.v4.port() => {
                format!(
                    "tcp.SrcPort == {} or tcp.SrcPort == {}",
                    self.v4.port(),
                    v6.port()
                )
            }
            _ => format!("tcp.SrcPort == {}", self.v4.port()),
        };
        format!(
            "tcp and !impostor and ((outbound and !loopback) or (loopback and ({relay_ports})))"
        )
    }
}

/// 把改道登记进中继的 NAT 表。由 svc 实现：intercept 与 relay 只经 trait 交互（C-ARCH-02）。
///
/// 在改写第一个 SYN 之前同步调用，保证中继接受连接时已经查得到映射。实现必须快、不阻塞。
pub trait RedirectMap: Send + Sync {
    /// 映射端口 → 原始目标与进程组。返回 `false` 表示登记失败（表满、端口被占），这条流按 fail_policy 处理。
    fn map(
        &self,
        network: Network,
        mapped_port: u16,
        original: SocketAddr,
        process: ProcessKey,
        group: u16,
    ) -> bool;

    fn unmap(&self, network: Network, mapped_port: u16);
}

/// 一个包的处理结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// 原样放回（地址信息也不变）。
    Pass,
    /// 已就地改写（包与地址信息），重算校验和后注入。
    Inject,
    /// 丢弃。
    Drop,
    /// 新连接的第一个 SYN 还没有归属：调用方暂存，稍后重试或兜底归属（C-NET-04）。
    Hold,
}

#[derive(Debug, Clone, Copy)]
struct Conn {
    /// 应用一侧的本地地址与端口（端口即映射端口）。
    app: SocketAddr,
    original: SocketAddr,
    iface: NetworkData,
    process: ProcessKey,
    group: u16,
    state: u8,
    last_seen: Instant,
}

const APP_FIN: u8 = 1;
const RELAY_FIN: u8 = 2;
const RESET: u8 = 4;

impl Conn {
    fn key(&self) -> FlowKey {
        FlowKey {
            network: Network::Tcp,
            local: self.app,
            remote: self.original,
        }
    }

    fn observe(&mut self, flags: u8, fin_bit: u8, now: Instant) {
        if flags & tcp_flags::RST != 0 {
            self.state |= RESET;
        }
        if flags & tcp_flags::FIN != 0 {
            self.state |= fin_bit;
        }
        self.last_seen = now;
    }

    fn expired(&self, now: Instant) -> bool {
        let idle = now.saturating_duration_since(self.last_seen);
        if self.state & RESET != 0 {
            idle >= RST_LINGER
        } else if self.state & (APP_FIN | RELAY_FIN) == APP_FIN | RELAY_FIN {
            idle >= FIN_LINGER
        } else {
            idle >= IDLE_LIMIT
        }
    }
}

type Shard = HashMap<u16, Conn>;

/// 逐包处理：连接跟踪、改写与新连接的建立。可被多个收包线程同时使用。
pub struct Engine {
    flows: Arc<FlowTable>,
    conns: Box<[Mutex<Shard>]>,
    relays: Relays,
    map: Arc<dyn RedirectMap>,
    fail_policy: FailPolicy,
    counters: Arc<Counters>,
    events: SyncSender<FlowEvent>,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine")
            .field("relays", &self.relays)
            .field("fail_policy", &self.fail_policy)
            .finish_non_exhaustive()
    }
}

impl Engine {
    pub fn new(
        flows: Arc<FlowTable>,
        relays: Relays,
        map: Arc<dyn RedirectMap>,
        fail_policy: FailPolicy,
        counters: Arc<Counters>,
        events: SyncSender<FlowEvent>,
    ) -> Self {
        Self {
            flows,
            conns: (0..SHARDS)
                .map(|_| Mutex::new(Shard::with_capacity(PER_SHARD)))
                .collect(),
            relays,
            map,
            fail_policy,
            counters,
            events,
        }
    }

    pub fn relays(&self) -> &Relays {
        &self.relays
    }

    pub fn flows(&self) -> &Arc<FlowTable> {
        &self.flows
    }

    fn shard(&self, port: u16) -> MutexGuard<'_, Shard> {
        // 分片里只有可整体替换的值，持锁的线程 panic 也不会留下改了一半的表项
        self.conns[usize::from(port) % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// 处理一个收到的包。返回 [`Outcome::Inject`] 时包与地址信息都已就地改写。
    pub fn process(&self, pkt: &mut [u8], addr: &mut Address, now: Instant) -> Outcome {
        let Ok(mut p) = packet::parse(pkt) else {
            // 读不出 TCP 端口就无从归属：既不是能改写的目标包，也不能确定是谁的，原样放回
            return Outcome::Pass;
        };
        if p.network() != Network::Tcp {
            return Outcome::Pass;
        }
        if addr.loopback() {
            self.on_relay_packet(&mut p, addr, now)
        } else if addr.outbound() {
            self.on_app_packet(&mut p, addr, now)
        } else {
            Outcome::Pass
        }
    }

    fn on_app_packet(&self, p: &mut Packet<'_>, addr: &mut Address, now: Instant) -> Outcome {
        let (src, dst, flags) = (p.src(), p.dst(), p.tcp_flags());
        let port = src.port();
        let tracked = {
            let mut shard = self.shard(port);
            match shard.get_mut(&port) {
                Some(c) if c.app == src && c.original == dst => {
                    c.observe(flags, APP_FIN, now);
                    true
                }
                _ => false,
            }
        };
        if tracked {
            return self.to_relay(p, port);
        }
        // 只有新连接的第一个 SYN 才可能开始改道
        if flags & (tcp_flags::SYN | tcp_flags::ACK) != tcp_flags::SYN {
            return Outcome::Pass;
        }
        match self.flows.take_for_syn(port, dst) {
            None => Outcome::Hold,
            Some(record) => self.start(record, p, addr.network(), now),
        }
    }

    /// 按登记开始处理一条新连接（第一个 SYN）。
    fn start(
        &self,
        record: FlowRecord,
        p: &mut Packet<'_>,
        iface: NetworkData,
        now: Instant,
    ) -> Outcome {
        let (src, dst) = (p.src(), p.dst());
        let key = FlowKey {
            network: Network::Tcp,
            local: src,
            remote: dst,
        };
        let (group, process) = match (record.action, record.process) {
            (FlowAction::Redirect { group }, Some(process)) => (group, process),
            (FlowAction::Block, process) => {
                emit(
                    &self.events,
                    FlowEvent::Blocked { key, process },
                    &self.counters,
                );
                return Outcome::Drop;
            }
            _ => return Outcome::Pass,
        };
        if self.relays.for_family(dst.ip()).is_none() {
            return self.fail(key, Some(process));
        }
        // 端口上残留的旧连接（收尾等待期内端口被复用）先让位
        self.evict(src.port());
        if !self.map.map(Network::Tcp, src.port(), dst, process, group) {
            return self.fail(key, Some(process));
        }
        let conn = Conn {
            app: src,
            original: dst,
            iface,
            process,
            group,
            state: 0,
            last_seen: now,
        };
        self.shard(src.port()).insert(src.port(), conn);
        emit(
            &self.events,
            FlowEvent::Redirected {
                key,
                process,
                group,
            },
            &self.counters,
        );
        self.to_relay(p, src.port())
    }

    /// 改写成「回环:映射端口 → 回环:中继端口」，出站注入。
    fn to_relay(&self, p: &mut Packet<'_>, port: u16) -> Outcome {
        let (loopback, relay) = if p.is_ipv6() {
            (IpAddr::V6(Ipv6Addr::LOCALHOST), self.relays.v6)
        } else {
            (IpAddr::V4(Ipv4Addr::LOCALHOST), Some(self.relays.v4))
        };
        let Some(relay) = relay else {
            return Outcome::Drop;
        };
        if p.set_src(SocketAddr::new(loopback, port)).is_err() || p.set_dst(relay).is_err() {
            return Outcome::Drop;
        }
        Outcome::Inject
    }

    fn on_relay_packet(&self, p: &mut Packet<'_>, addr: &mut Address, now: Instant) -> Outcome {
        let (src, dst, flags) = (p.src(), p.dst(), p.tcp_flags());
        if !self.relays.is_relay_port(src.port()) {
            return Outcome::Pass;
        }
        let port = dst.port();
        let conn = {
            let mut shard = self.shard(port);
            match shard.get_mut(&port) {
                Some(c) => {
                    c.observe(flags, RELAY_FIN, now);
                    *c
                }
                // 没有对应的连接（已回收）：中继的回包无处可去
                None => return Outcome::Drop,
            }
        };
        if p.set_src(conn.original).is_err() || p.set_dst(conn.app).is_err() {
            return Outcome::Drop;
        }
        addr.set_outbound(false);
        addr.set_loopback(false);
        addr.set_network(conn.iface);
        Outcome::Inject
    }

    /// 目标流处理不了：按 fail_policy 阻断或放行（C-NET-07）。
    fn fail(&self, key: FlowKey, process: Option<ProcessKey>) -> Outcome {
        match unprocessable(self.fail_policy, &self.counters) {
            Verdict::Block => {
                emit(
                    &self.events,
                    FlowEvent::Blocked { key, process },
                    &self.counters,
                );
                Outcome::Drop
            }
            _ => Outcome::Pass,
        }
    }

    /// 回收一个端口上的连接：发出 `Closed` 并撤销 NAT 表项。
    fn evict(&self, port: u16) {
        let removed = self.shard(port).remove(&port);
        if let Some(conn) = removed {
            self.closed(&conn);
        }
    }

    fn closed(&self, conn: &Conn) {
        self.map.unmap(Network::Tcp, conn.app.port());
        emit(
            &self.events,
            FlowEvent::Closed { key: conn.key() },
            &self.counters,
        );
    }

    /// 回收已收尾或空闲太久的连接，返回回收的条数。由定时线程调用。
    pub fn sweep(&self, now: Instant) -> usize {
        let mut expired = Vec::new();
        for shard in self.conns.iter() {
            let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            shard.retain(|_, c| {
                let keep = !c.expired(now);
                if !keep {
                    expired.push(*c);
                }
                keep
            });
        }
        for conn in &expired {
            self.closed(conn);
        }
        expired.len()
    }

    /// 停止时回收全部连接。
    pub fn clear(&self) {
        let mut all = Vec::new();
        for shard in self.conns.iter() {
            let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            all.extend(shard.drain().map(|(_, c)| c));
        }
        for conn in &all {
            self.closed(conn);
        }
    }

    /// 正在跟踪的改道连接数。
    pub fn active(&self) -> usize {
        self.conns
            .iter()
            .map(|s| s.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }

    /// 某个映射端口上的连接属于哪个进程与进程组（诊断与测试）。
    pub fn conn_info(&self, port: u16) -> Option<(FlowKey, ProcessKey, u16)> {
        self.shard(port)
            .get(&port)
            .map(|c| (c.key(), c.process, c.group))
    }
}

#[cfg(test)]
mod tests;
