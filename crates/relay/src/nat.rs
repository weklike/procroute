// SPDX-License-Identifier: GPL-3.0-or-later
//! NAT 表：映射端口 → 原始目标、进程、进程组（T-073，设计文档 6.1）。
//!
//! - TCP、UDP 各一张表，按映射端口索引；
//! - 表项空闲超过超时时间（默认 TCP 300 s、UDP 60 s）后回收；
//! - 单表上限默认 65 536 条。表满时先回收过期表项，仍然满则拒绝新流，由调用方按
//!   `fail_policy` 处理；活跃表项永远不会被淘汰（C-PERF-04）。
//!
//! 时间由调用方传入，便于测试，也避免在表内部读时钟。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use procroute_proto::event::Network;
use procroute_proto::profile::FailPolicy;
use thiserror::Error;

/// C-PERF-04 规定的默认值。
pub const DEFAULT_TCP_IDLE: Duration = Duration::from_secs(300);
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(60);
pub const DEFAULT_CAPACITY: usize = 65_536;

/// 一条映射。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatEntry {
    /// 应用原本要连接的目标。
    pub original: SocketAddr,
    pub pid: u32,
    /// 与 `pid` 一起构成进程身份（C-DRV-04）。
    pub process_created_at: u64,
    /// 方案里进程组的下标。
    pub group: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NatConfig {
    pub tcp_idle: Duration,
    pub udp_idle: Duration,
    /// 每张表（TCP、UDP 分别计）的上限。
    pub capacity: usize,
    /// 表满时新流的处理方式，原样交还给调用方。
    pub fail_policy: FailPolicy,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            tcp_idle: DEFAULT_TCP_IDLE,
            udp_idle: DEFAULT_UDP_IDLE,
            capacity: DEFAULT_CAPACITY,
            fail_policy: FailPolicy::Block,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NatError {
    /// 表满且没有可回收的过期表项。调用方必须按 `fail_policy` 处理这条新流。
    #[error("{network:?} NAT 表已满，按 {fail_policy:?} 处理新流")]
    Full {
        network: Network,
        fail_policy: FailPolicy,
    },
    /// 映射端口被一条仍然活跃的流占用。
    #[error("{network:?} 映射端口 {port} 正被活跃流使用")]
    PortInUse { network: Network, port: u16 },
}

#[derive(Debug, Clone, Copy)]
struct Slot {
    entry: NatEntry,
    last_seen: Instant,
}

#[derive(Debug, Default)]
struct Table {
    slots: HashMap<u16, Slot>,
}

impl Table {
    fn is_expired(slot: &Slot, now: Instant, idle: Duration) -> bool {
        now.saturating_duration_since(slot.last_seen) >= idle
    }

    fn sweep(&mut self, now: Instant, idle: Duration) -> usize {
        let before = self.slots.len();
        self.slots.retain(|_, s| !Self::is_expired(s, now, idle));
        before - self.slots.len()
    }
}

/// TCP 与 UDP 两张映射表。
#[derive(Debug)]
pub struct NatTable {
    config: NatConfig,
    tcp: Table,
    udp: Table,
}

impl NatTable {
    pub fn new(config: NatConfig) -> Self {
        Self {
            config,
            tcp: Table::default(),
            udp: Table::default(),
        }
    }

    pub fn config(&self) -> &NatConfig {
        &self.config
    }

    fn parts(&mut self, network: Network) -> (&mut Table, Duration) {
        match network {
            Network::Tcp => (&mut self.tcp, self.config.tcp_idle),
            Network::Udp => (&mut self.udp, self.config.udp_idle),
        }
    }

    /// 登记一条新映射。
    pub fn insert(
        &mut self,
        network: Network,
        port: u16,
        entry: NatEntry,
        now: Instant,
    ) -> Result<(), NatError> {
        let capacity = self.config.capacity;
        let fail_policy = self.config.fail_policy;
        let (table, idle) = self.parts(network);
        if let Some(existing) = table.slots.get(&port) {
            if !Table::is_expired(existing, now, idle) {
                return Err(NatError::PortInUse { network, port });
            }
        } else if table.slots.len() >= capacity && table.sweep(now, idle) == 0 {
            return Err(NatError::Full {
                network,
                fail_policy,
            });
        }
        table.slots.insert(
            port,
            Slot {
                entry,
                last_seen: now,
            },
        );
        Ok(())
    }

    /// 查找映射并刷新活跃时间。已过期的表项视为不存在并就地回收。
    pub fn lookup(&mut self, network: Network, port: u16, now: Instant) -> Option<NatEntry> {
        let (table, idle) = self.parts(network);
        let slot = table.slots.get_mut(&port)?;
        if Table::is_expired(slot, now, idle) {
            table.slots.remove(&port);
            return None;
        }
        slot.last_seen = now;
        Some(slot.entry)
    }

    /// 只刷新活跃时间（流上有数据经过时调用）。返回表项是否存在且未过期。
    pub fn touch(&mut self, network: Network, port: u16, now: Instant) -> bool {
        self.lookup(network, port, now).is_some()
    }

    /// 连接关闭时移除映射。
    pub fn remove(&mut self, network: Network, port: u16) -> Option<NatEntry> {
        self.parts(network).0.slots.remove(&port).map(|s| s.entry)
    }

    /// 回收两张表里全部过期表项，返回回收数量。由后台定时调用。
    pub fn sweep(&mut self, now: Instant) -> usize {
        let tcp = self.tcp.sweep(now, self.config.tcp_idle);
        let udp = self.udp.sweep(now, self.config.udp_idle);
        tcp + udp
    }

    /// 当前表项数（含尚未回收的过期项）。
    pub fn len(&self, network: Network) -> usize {
        match network {
            Network::Tcp => self.tcp.slots.len(),
            Network::Udp => self.udp.slots.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.tcp.slots.is_empty() && self.udp.slots.is_empty()
    }
}

impl Default for NatTable {
    fn default() -> Self {
        Self::new(NatConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn entry(n: u16) -> NatEntry {
        NatEntry {
            original: SocketAddr::from(([203, 0, 113, 24], n)),
            pid: 4120,
            process_created_at: 10,
            group: 0,
        }
    }

    fn small(capacity: usize, fail_policy: FailPolicy) -> NatTable {
        NatTable::new(NatConfig {
            capacity,
            fail_policy,
            ..NatConfig::default()
        })
    }

    #[test]
    fn defaults_follow_c_perf_04() {
        let c = NatConfig::default();
        assert_eq!(c.tcp_idle, Duration::from_secs(300));
        assert_eq!(c.udp_idle, Duration::from_secs(60));
        assert_eq!(c.capacity, 65_536);
        assert_eq!(c.fail_policy, FailPolicy::Block);
    }

    #[test]
    fn insert_then_lookup() {
        let t0 = Instant::now();
        let mut nat = NatTable::default();
        nat.insert(Network::Tcp, 40000, entry(443), t0).unwrap();
        assert_eq!(nat.lookup(Network::Tcp, 40000, t0), Some(entry(443)));
        // TCP 与 UDP 是两张表
        assert_eq!(nat.lookup(Network::Udp, 40000, t0), None);
        assert_eq!(nat.lookup(Network::Tcp, 40001, t0), None);
        assert_eq!(nat.remove(Network::Tcp, 40000), Some(entry(443)));
        assert!(nat.is_empty());
    }

    #[test]
    fn idle_entries_expire_per_protocol() {
        let t0 = Instant::now();
        let mut nat = NatTable::default();
        nat.insert(Network::Tcp, 1, entry(1), t0).unwrap();
        nat.insert(Network::Udp, 1, entry(1), t0).unwrap();

        let t59 = t0 + Duration::from_secs(59);
        assert!(nat.touch(Network::Udp, 1, t59));
        // UDP 在最后一次活跃后 60 秒过期
        assert_eq!(
            nat.lookup(Network::Udp, 1, t59 + Duration::from_secs(60)),
            None
        );
        assert_eq!(nat.len(Network::Udp), 0);

        let t299 = t0 + Duration::from_secs(299);
        assert!(nat.touch(Network::Tcp, 1, t299));
        assert_eq!(nat.sweep(t299 + Duration::from_secs(299)), 0);
        assert_eq!(nat.sweep(t299 + Duration::from_secs(300)), 1);
        assert!(nat.is_empty());
    }

    #[test]
    fn active_port_is_not_overwritten_but_expired_one_is() {
        let t0 = Instant::now();
        let mut nat = NatTable::default();
        nat.insert(Network::Tcp, 7, entry(1), t0).unwrap();
        assert_eq!(
            nat.insert(Network::Tcp, 7, entry(2), t0 + Duration::from_secs(1)),
            Err(NatError::PortInUse {
                network: Network::Tcp,
                port: 7
            })
        );
        let later = t0 + DEFAULT_TCP_IDLE;
        nat.insert(Network::Tcp, 7, entry(2), later).unwrap();
        assert_eq!(nat.lookup(Network::Tcp, 7, later), Some(entry(2)));
    }

    #[test]
    fn full_table_rejects_new_flows_with_fail_policy_and_keeps_active_ones() {
        let t0 = Instant::now();
        let mut nat = small(2, FailPolicy::Block);
        nat.insert(Network::Udp, 1, entry(1), t0).unwrap();
        nat.insert(Network::Udp, 2, entry(2), t0).unwrap();
        assert_eq!(
            nat.insert(Network::Udp, 3, entry(3), t0),
            Err(NatError::Full {
                network: Network::Udp,
                fail_policy: FailPolicy::Block
            })
        );
        // 活跃流没有被淘汰
        assert_eq!(nat.lookup(Network::Udp, 1, t0), Some(entry(1)));
        assert_eq!(nat.lookup(Network::Udp, 2, t0), Some(entry(2)));
        // 另一张表不受影响
        nat.insert(Network::Tcp, 3, entry(3), t0).unwrap();

        let mut allow = small(1, FailPolicy::Allow);
        allow.insert(Network::Tcp, 1, entry(1), t0).unwrap();
        assert_eq!(
            allow.insert(Network::Tcp, 2, entry(2), t0),
            Err(NatError::Full {
                network: Network::Tcp,
                fail_policy: FailPolicy::Allow
            })
        );
    }

    #[test]
    fn full_table_reclaims_expired_entries_before_rejecting() {
        let t0 = Instant::now();
        let mut nat = small(2, FailPolicy::Block);
        nat.insert(Network::Udp, 1, entry(1), t0).unwrap();
        nat.insert(Network::Udp, 2, entry(2), t0 + Duration::from_secs(30))
            .unwrap();
        // 第 1 条已过期，第 2 条仍活跃
        let t = t0 + DEFAULT_UDP_IDLE;
        nat.insert(Network::Udp, 3, entry(3), t).unwrap();
        assert_eq!(nat.lookup(Network::Udp, 1, t), None);
        assert_eq!(nat.lookup(Network::Udp, 2, t), Some(entry(2)));
        assert_eq!(nat.lookup(Network::Udp, 3, t), Some(entry(3)));
    }

    #[derive(Debug, Clone)]
    enum Op {
        Insert(u16, u64),
        Lookup(u16, u64),
        Remove(u16),
        Sweep(u64),
    }

    fn op() -> impl Strategy<Value = Op> {
        let port = 0u16..16;
        let dt = 0u64..90;
        prop_oneof![
            (port.clone(), dt.clone()).prop_map(|(p, d)| Op::Insert(p, d)),
            (port.clone(), dt.clone()).prop_map(|(p, d)| Op::Lookup(p, d)),
            port.prop_map(Op::Remove),
            dt.prop_map(Op::Sweep),
        ]
    }

    proptest! {
        /// 任意操作序列下：表项数不超过上限，且未过期、未移除的表项永远查得到。
        #[test]
        fn capacity_is_never_exceeded_and_live_entries_survive(ops in prop::collection::vec(op(), 1..200)) {
            let t0 = Instant::now();
            let mut now = t0;
            let mut nat = small(4, FailPolicy::Block);
            // 参照模型：端口 → 最后活跃时间
            let mut live: HashMap<u16, Instant> = HashMap::new();
            let idle = DEFAULT_UDP_IDLE;
            for op in ops {
                match op {
                    Op::Insert(p, d) => {
                        now += Duration::from_secs(d);
                        if nat.insert(Network::Udp, p, entry(p), now).is_ok() {
                            live.insert(p, now);
                        }
                    }
                    Op::Lookup(p, d) => {
                        now += Duration::from_secs(d);
                        let expected_alive = live.get(&p).is_some_and(|t| now.duration_since(*t) < idle);
                        prop_assert_eq!(nat.lookup(Network::Udp, p, now).is_some(), expected_alive);
                        if expected_alive { live.insert(p, now); } else { live.remove(&p); }
                    }
                    Op::Remove(p) => {
                        nat.remove(Network::Udp, p);
                        live.remove(&p);
                    }
                    Op::Sweep(d) => {
                        now += Duration::from_secs(d);
                        nat.sweep(now);
                    }
                }
                prop_assert!(nat.len(Network::Udp) <= 4);
                for (p, t) in &live {
                    if now.duration_since(*t) < idle {
                        // 直接看内部表，避免 lookup 刷新活跃时间而改变模型
                        let alive = nat.udp.slots.contains_key(p);
                        prop_assert!(alive, "live entry {} was evicted", p);
                    }
                }
            }
        }
    }
}
