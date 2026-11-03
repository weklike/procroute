// SPDX-License-Identifier: GPL-3.0-or-later
//! 目标进程 UDP 的改道（T-091，设计文档 6.2）。
//!
//! UDP 没有回环中继：数据报直接交给进程内的 UDP 中继（[`UdpForward`]，由 svc 接到 `procroute-relay`，
//! C-ARCH-02），原包丢弃；中继的回包经 [`UdpReplies`] 交回这里，拼成「远端 → 应用」的入站数据报，在应用
//! 原来的接口上注入。
//!
//! - 目标 UDP 套接字按本地端口登记（[`UdpSockets`]）：中继按「本地地址 + 端口」建会话保持 full-cone，
//!   同一套接字发往新的远端时，SOCKET 层的登记还没到也认得出它；
//! - 套接字空闲 [`UDP_IDLE`] 后回收（与中继会话的超时一致，C-PERF-04）；
//! - 中继拒收（会话数超限、队列满）的数据报丢弃，绝不直连（C-NET-03）。

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::ffi::{Address, MTU_MAX, NetworkData};
use super::network::Engine;
use super::worker::Injector;
use crate::flow::ProcessKey;
use crate::packet;

/// 目标 UDP 套接字的空闲超时。
pub const UDP_IDLE: Duration = Duration::from_secs(60);

const SHARDS: usize = 64;

/// 把目标进程的 UDP 数据报交给中继。由 svc 实现。
pub trait UdpForward: Send + Sync {
    /// 交出一个数据报。`session` 是应用的本地地址与端口。返回 `false` 表示中继拒收（数据报已丢弃）。
    /// 在收包线程上同步调用，实现必须快且不阻塞（C-CODE-05）。
    fn forward(&self, session: SocketAddr, group: u16, dst: SocketAddr, payload: &[u8]) -> bool;

    /// 后端启动时交来注入回包的出口，停止时交 `None`。
    fn attach(&self, replies: Option<Arc<dyn UdpReplies>>);
}

/// 中继的回包出口，由本后端实现。
pub trait UdpReplies: Send + Sync {
    /// 把 `src → session` 的数据报注入回应用。不认识的会话（套接字已回收）丢弃。
    fn deliver(&self, session: SocketAddr, src: SocketAddr, payload: &[u8]);
}

#[derive(Debug, Clone, Copy)]
struct Socket {
    app: SocketAddr,
    process: ProcessKey,
    group: u16,
    iface: NetworkData,
    last_seen: Instant,
}

/// 目标 UDP 套接字表：本地端口 → 应用地址、进程、进程组与接口。
#[derive(Debug)]
pub struct UdpSockets {
    shards: Box<[Mutex<HashMap<u16, Socket>>]>,
}

impl Default for UdpSockets {
    fn default() -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
        }
    }
}

impl UdpSockets {
    fn shard(&self, port: u16) -> MutexGuard<'_, HashMap<u16, Socket>> {
        self.shards[usize::from(port) % SHARDS]
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// 已登记的目标套接字：返回进程组并刷新活跃时间。本地地址不一致（端口被别的套接字复用）视为没有。
    pub fn touch(&self, app: SocketAddr, now: Instant) -> Option<u16> {
        let mut shard = self.shard(app.port());
        let s = shard.get_mut(&app.port()).filter(|s| s.app == app)?;
        s.last_seen = now;
        Some(s.group)
    }

    pub fn insert(
        &self,
        app: SocketAddr,
        process: ProcessKey,
        group: u16,
        iface: NetworkData,
        now: Instant,
    ) {
        self.shard(app.port()).insert(
            app.port(),
            Socket {
                app,
                process,
                group,
                iface,
                last_seen: now,
            },
        );
    }

    /// 回包的去向：应用地址与接口。
    pub fn reply_target(&self, port: u16) -> Option<(SocketAddr, NetworkData)> {
        self.shard(port).get(&port).map(|s| (s.app, s.iface))
    }

    /// 某个端口上的套接字属于哪个进程与进程组（诊断与测试）。
    pub fn owner(&self, port: u16) -> Option<(ProcessKey, u16)> {
        self.shard(port).get(&port).map(|s| (s.process, s.group))
    }

    /// 回收空闲的套接字，返回回收的个数。
    pub fn sweep(&self, now: Instant) -> usize {
        let mut removed = 0;
        for shard in self.shards.iter() {
            let mut shard = shard.lock().unwrap_or_else(PoisonError::into_inner);
            let before = shard.len();
            shard.retain(|_, s| now.saturating_duration_since(s.last_seen) < UDP_IDLE);
            removed += before - shard.len();
        }
        removed
    }

    pub fn clear(&self) {
        for shard in self.shards.iter() {
            shard.lock().unwrap_or_else(PoisonError::into_inner).clear();
        }
    }

    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(PoisonError::into_inner).len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// 中继回包的注入：按会话找回应用地址与接口，拼包后入站注入。
pub struct UdpReplier {
    engine: Arc<Engine>,
    injector: Injector,
}

impl std::fmt::Debug for UdpReplier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpReplier").finish_non_exhaustive()
    }
}

impl UdpReplier {
    pub fn new(engine: Arc<Engine>, injector: Injector) -> Self {
        Self { engine, injector }
    }
}

thread_local! {
    /// 每个调用线程一个拼包缓冲区，只分配一次。
    static REPLY_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; MTU_MAX]);
}

impl UdpReplies for UdpReplier {
    fn deliver(&self, session: SocketAddr, src: SocketAddr, payload: &[u8]) {
        let Some((app, iface)) = self.engine.udp_sockets().reply_target(session.port()) else {
            return;
        };
        let Some(src) = same_family(src, app.ip()) else {
            return;
        };
        REPLY_BUF.with_borrow_mut(|buf| {
            let Some(n) = packet::build_udp(buf, src, app, payload) else {
                return;
            };
            // 默认的地址信息就是 NETWORK 层的入站包；接口取应用发包时的接口
            let mut addr = Address::default();
            addr.set_network(iface);
            self.injector.inject(&mut buf[..n], &mut addr);
        });
    }
}

/// 把回包的源地址换成与应用相同的地址族（IPv4 映射地址 ↔ IPv4）。换不了返回 `None`。
fn same_family(src: SocketAddr, app: IpAddr) -> Option<SocketAddr> {
    let ip = match (src.ip(), app) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => src.ip(),
        (IpAddr::V6(v6), IpAddr::V4(_)) => IpAddr::V4(v6.to_ipv4_mapped()?),
        (IpAddr::V4(v4), IpAddr::V6(_)) => IpAddr::V6(v4.to_ipv6_mapped()),
    };
    Some(SocketAddr::new(ip, src.port()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAME: ProcessKey = ProcessKey {
        pid: 4120,
        created_at: 10,
    };
    const IFACE: NetworkData = NetworkData {
        if_idx: 12,
        sub_if_idx: 0,
    };

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn sockets_are_found_by_port_and_app_address() {
        let t = UdpSockets::default();
        let t0 = Instant::now();
        let app = sock("192.168.1.5:6000");
        assert_eq!(t.touch(app, t0), None);
        t.insert(app, GAME, 3, IFACE, t0);
        assert_eq!(t.touch(app, t0), Some(3));
        // 同一端口、另一个本地地址：不是这个套接字
        assert_eq!(t.touch(sock("10.0.0.2:6000"), t0), None);
        assert_eq!(t.reply_target(6000), Some((app, IFACE)));
        assert_eq!(t.owner(6000), Some((GAME, 3)));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn idle_sockets_are_reclaimed_and_touching_keeps_them() {
        let t = UdpSockets::default();
        let t0 = Instant::now();
        let a = sock("192.168.1.5:6000");
        let b = sock("192.168.1.5:6001");
        t.insert(a, GAME, 0, IFACE, t0);
        t.insert(b, GAME, 0, IFACE, t0);
        t.touch(a, t0 + UDP_IDLE - Duration::from_secs(1));
        assert_eq!(t.sweep(t0 + UDP_IDLE), 1);
        assert!(t.reply_target(6000).is_some());
        assert!(t.reply_target(6001).is_none());
        t.clear();
        assert!(t.is_empty());
    }

    #[test]
    fn reply_sources_follow_the_app_address_family() {
        let v4 = sock("192.168.1.5:6000").ip();
        let v6 = sock("[2001:db8::5]:6000").ip();
        assert_eq!(
            same_family(sock("203.0.113.24:53"), v4),
            Some(sock("203.0.113.24:53"))
        );
        assert_eq!(
            same_family(sock("[::ffff:203.0.113.24]:53"), v4),
            Some(sock("203.0.113.24:53"))
        );
        assert_eq!(same_family(sock("[2001:db8::1]:53"), v4), None);
        assert_eq!(
            same_family(sock("203.0.113.24:53"), v6),
            Some(sock("[::ffff:203.0.113.24]:53"))
        );
    }
}
