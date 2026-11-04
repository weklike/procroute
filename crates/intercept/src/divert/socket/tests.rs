// SPDX-License-Identifier: GPL-3.0-or-later
//! 不加载驱动的测试：事件解码、登记表、判定与登记。收事件的线程在 `tests/divert_vm.rs` 里测（C-TEST-04）。

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use procroute_proto::profile::FailPolicy;

use super::*;
use crate::backend::BypassReason;

const GAME: ProcessKey = ProcessKey {
    pid: 4120,
    created_at: 10,
};
const OTHER: ProcessKey = ProcessKey {
    pid: 77,
    created_at: 3,
};
const PROXY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn key(network: Network, local: &str, remote: &str) -> FlowKey {
    FlowKey {
        network,
        local: sock(local),
        remote: sock(remote),
    }
}

fn tcp(local_port: u16, remote: &str) -> FlowKey {
    key(Network::Tcp, &format!("192.168.1.5:{local_port}"), remote)
}

/// 按 WINDIVERT_DATA_SOCKET 的布局拼一个 SOCKET 层地址。
fn socket_address(
    event: u8,
    pid: u32,
    protocol: u8,
    local: SocketAddr,
    remote: SocketAddr,
) -> Address {
    fn put_ip(d: &mut [u8; 64], off: usize, ip: IpAddr) {
        let v = match ip {
            IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
            IpAddr::V6(v6) => u128::from(v6),
        };
        for i in 0..4 {
            let w = (v >> (32 * i)) as u32;
            d[off + 4 * i..off + 4 * i + 4].copy_from_slice(&w.to_ne_bytes());
        }
    }
    let mut d = [0u8; 64];
    d[16..20].copy_from_slice(&pid.to_ne_bytes());
    put_ip(&mut d, 20, local.ip());
    put_ip(&mut d, 36, remote.ip());
    d[52..54].copy_from_slice(&local.port().to_ne_bytes());
    d[54..56].copy_from_slice(&remote.port().to_ne_bytes());
    d[56] = protocol;
    // Layer = SOCKET，Sniffed，Outbound
    let bits = Layer::Socket as u32 | (u32::from(event) << 8) | (1 << 16) | (1 << 17);
    Address::from_parts(bits, d)
}

#[test]
fn decodes_connect_and_close_events() {
    let a = socket_address(
        event::SOCKET_CONNECT,
        4120,
        PROTO_TCP,
        sock("192.168.1.5:50001"),
        sock("203.0.113.24:443"),
    );
    assert_eq!(
        decode(&a),
        Some(SocketEvent::Connect {
            pid: 4120,
            key: tcp(50001, "203.0.113.24:443"),
        })
    );

    let a = socket_address(
        event::SOCKET_CLOSE,
        9,
        PROTO_UDP,
        sock("[2001:db8::5]:5353"),
        sock("[::]:0"),
    );
    assert_eq!(
        decode(&a),
        Some(SocketEvent::Close {
            pid: 9,
            key: key(Network::Udp, "[2001:db8::5]:5353", "[::]:0"),
        })
    );
}

#[test]
fn ignores_other_events_protocols_and_layers() {
    let local = sock("192.168.1.5:50001");
    let remote = sock("203.0.113.24:443");
    // BIND 事件
    let bind = socket_address(event::SOCKET_BIND, 1, PROTO_TCP, local, remote);
    assert_eq!(decode(&bind), None);
    // ICMP
    let icmp = socket_address(event::SOCKET_CONNECT, 1, 1, local, remote);
    assert_eq!(decode(&icmp), None);
    // FLOW 层的地址即使布局相同也不收
    let flow_layer = Address::from_parts(
        Layer::Flow as u32 | (u32::from(event::FLOW_ESTABLISHED) << 8),
        [0; 64],
    );
    assert_eq!(decode(&flow_layer), None);
}

#[test]
fn system_events_are_not_flows() {
    // 放回一个包时 WFP 再报的 PID 4 CONNECT：登记它会用「放行」盖掉目标流的改道登记
    let local = sock("192.168.1.5:50001");
    let remote = sock("203.0.113.24:443");
    for ev in [event::SOCKET_CONNECT, event::SOCKET_CLOSE] {
        let a = socket_address(ev, SYSTEM_PID, PROTO_UDP, local, remote);
        assert_eq!(decode(&a), None, "{ev}");
    }
}

#[test]
fn the_filter_compiles_at_the_socket_layer() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert/bin");
    let wd = WinDivert::load(&dir.canonicalize().unwrap_or_else(|e| {
        panic!("找不到锁定版本的 WinDivert（{e}），先运行 `cargo xtask fetch-deps`")
    }))
    .expect("load the locked WinDivert");
    wd.check_filter(FILTER, Layer::Socket)
        .expect("SOCKET layer filter");
}

fn record(key: FlowKey, process: ProcessKey, action: FlowAction) -> FlowRecord {
    FlowRecord {
        key,
        pid: process.pid,
        process: Some(process),
        action,
    }
}

fn target(key: FlowKey, process: ProcessKey, group: u16) -> FlowRecord {
    record(key, process, FlowAction::Redirect { group })
}

#[test]
fn table_registers_replaces_and_looks_up_by_port_and_remote() {
    let t = FlowTable::default();
    let k = tcp(50001, "203.0.113.24:443");
    assert!(t.register(target(k, GAME, 1)));
    assert_eq!(t.len(), 1);
    // 本地地址不参与查找
    assert_eq!(
        t.get(Network::Tcp, 50001, sock("203.0.113.24:443")),
        Some(target(k, GAME, 1))
    );
    assert_eq!(t.get(Network::Udp, 50001, sock("203.0.113.24:443")), None);
    assert_eq!(t.get(Network::Tcp, 50002, sock("203.0.113.24:443")), None);
    assert_eq!(t.get(Network::Tcp, 50001, sock("203.0.113.24:80")), None);

    // 同一键再次登记：覆盖，不增加条数
    assert!(t.register(target(k, GAME, 4)));
    assert_eq!(t.len(), 1);
    assert_eq!(
        t.get(Network::Tcp, 50001, sock("203.0.113.24:443"))
            .map(|f| f.action),
        Some(FlowAction::Redirect { group: 4 })
    );

    assert_eq!(t.unregister(&k), Some(target(k, GAME, 4)));
    assert_eq!(t.unregister(&k), None);
    assert!(t.is_empty());
}

#[test]
fn table_handles_ipv6_remotes() {
    let t = FlowTable::default();
    let k = key(Network::Tcp, "[2001:db8::5]:50001", "[2001:db8::1]:443");
    assert!(t.register(target(k, GAME, 0)));
    let remote = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        443,
    );
    assert!(t.get(Network::Tcp, 50001, remote).is_some());
}

#[test]
fn the_first_syn_consumes_redirect_and_bypass_records_but_not_block() {
    let t = FlowTable::default();
    let redirect = tcp(50001, "203.0.113.24:443");
    let bypass = tcp(50002, "203.0.113.24:443");
    let block = tcp(50003, "203.0.113.24:443");
    t.register(target(redirect, GAME, 1));
    t.register(record(bypass, OTHER, FlowAction::Bypass));
    t.register(record(block, GAME, FlowAction::Block));

    assert_eq!(
        t.take_for_syn(50001, redirect.remote),
        Some(target(redirect, GAME, 1))
    );
    assert_eq!(t.take_for_syn(50001, redirect.remote), None);
    assert_eq!(
        t.take_for_syn(50002, bypass.remote).map(|r| r.action),
        Some(FlowAction::Bypass)
    );
    assert_eq!(t.take_for_syn(50002, bypass.remote), None);
    // 阻断的登记留着，重传的 SYN 照样被挡
    for _ in 0..2 {
        assert_eq!(
            t.take_for_syn(50003, block.remote).map(|r| r.action),
            Some(FlowAction::Block)
        );
    }
    assert_eq!(t.len(), 1);
    // 只看 TCP
    let udp = key(Network::Udp, "192.168.1.5:50004", "203.0.113.24:443");
    t.register(target(udp, GAME, 1));
    assert_eq!(t.take_for_syn(50004, udp.remote), None);
}

#[test]
fn closing_a_socket_forgets_only_its_own_flows() {
    let t = FlowTable::default();
    let a = key(Network::Udp, "0.0.0.0:6000", "203.0.113.24:27015");
    let b = key(Network::Udp, "0.0.0.0:6000", "203.0.113.25:27015");
    let other_port = key(Network::Udp, "0.0.0.0:6001", "203.0.113.24:27015");
    for k in [a, b, other_port] {
        assert!(t.register(target(k, GAME, 0)));
    }
    // 别的进程关闭同一端口（不可能同时存在，但不能误删）
    assert_eq!(t.forget_socket(OTHER.pid, Network::Udp, 6000, None), 0);
    // TCP 的同号端口不受影响
    assert_eq!(t.forget_socket(GAME.pid, Network::Tcp, 6000, None), 0);
    // 指定远端只撤销那一条
    assert_eq!(
        t.forget_socket(GAME.pid, Network::Udp, 6000, Some(a.remote)),
        1
    );
    assert_eq!(t.len(), 2);
    // 不指定远端撤销该端口上的全部
    assert_eq!(t.forget_socket(GAME.pid, Network::Udp, 6000, None), 1);
    assert_eq!(t.entries(), vec![target(other_port, GAME, 0)]);
}

#[test]
fn a_full_table_refuses_new_keys_but_keeps_existing_ones() {
    let t = FlowTable::new(2);
    let k1 = tcp(50001, "203.0.113.24:443");
    let k2 = tcp(50002, "203.0.113.24:443");
    let k3 = tcp(50003, "203.0.113.24:443");
    assert!(t.register(target(k1, GAME, 0)));
    assert!(t.register(target(k2, GAME, 0)));
    assert!(!t.register(target(k3, GAME, 0)));
    assert_eq!(t.overflows(), 1);
    // 已有的键仍可覆盖
    assert!(t.register(target(k1, GAME, 1)));
    assert_eq!(t.len(), 2);
    assert!(t.get(Network::Tcp, 50003, k3.remote).is_none());
    t.clear();
    assert!(t.is_empty());
    assert!(t.register(target(k3, GAME, 0)));
}

#[test]
fn bypass_records_leave_a_quarter_of_the_table_to_target_flows() {
    let t = FlowTable::new(8);
    for port in 0..6 {
        assert!(t.register(record(
            tcp(40000 + port, "203.0.113.24:443"),
            OTHER,
            FlowAction::Bypass
        )));
    }
    assert!(!t.register(record(
        tcp(40006, "203.0.113.24:443"),
        OTHER,
        FlowAction::Bypass
    )));
    assert!(t.register(target(tcp(50001, "203.0.113.24:443"), GAME, 0)));
    assert!(t.register(record(
        tcp(50002, "203.0.113.24:443"),
        GAME,
        FlowAction::Block
    )));
    assert_eq!(t.len(), 8);
    assert_eq!(t.overflows(), 1);
}

struct Targets(HashMap<ProcessKey, u16>);

impl FlowPolicy for Targets {
    fn target_group(&self, p: &ProcessKey) -> Option<u16> {
        self.0.get(p).copied()
    }
}

struct Pids(HashMap<u32, u64>);

impl ProcessResolver for Pids {
    fn resolve(&self, pid: u32) -> Option<ProcessKey> {
        self.0
            .get(&pid)
            .map(|&created_at| ProcessKey { pid, created_at })
    }
}

fn attributor(settings: InterceptSettings) -> Attributor {
    Attributor::new(
        settings,
        ExclusionSet::new([], [IpAddr::V4(PROXY)]),
        Arc::new(Targets(HashMap::from([(GAME, 2)]))),
        Arc::new(Pids(HashMap::from([
            (GAME.pid, GAME.created_at),
            (OTHER.pid, OTHER.created_at),
        ]))),
        Arc::new(FlowTable::default()),
        Arc::new(Counters::default()),
    )
}

fn connect(pid: u32, key: FlowKey) -> SocketEvent {
    SocketEvent::Connect { pid, key }
}

fn action_of(a: &Attributor, k: FlowKey) -> Option<FlowAction> {
    a.table()
        .get(k.network, k.local.port(), k.remote)
        .map(|r| r.action)
}

#[test]
fn target_connects_are_registered_with_their_group() {
    let a = attributor(InterceptSettings::default());
    let k = tcp(50001, "203.0.113.24:443");
    assert_eq!(
        a.handle(connect(GAME.pid, k)),
        Some(Verdict::Redirect { group: 2 })
    );
    assert_eq!(a.table().entries(), vec![target(k, GAME, 2)]);
    assert_eq!(a.counters.snapshot().redirected, 1);
}

#[test]
fn non_target_connects_are_recorded_as_bypass_and_replace_stale_entries() {
    // C-NET-02：非目标只记归属元数据，NETWORK 层据此立即放行
    let a = attributor(InterceptSettings::default());
    let k = tcp(50001, "203.0.113.24:443");
    assert_eq!(
        a.handle(connect(OTHER.pid, k)),
        Some(Verdict::Bypass(BypassReason::NotTarget))
    );
    assert_eq!(
        a.table().entries(),
        vec![record(k, OTHER, FlowAction::Bypass)]
    );

    // 目标进程的登记残留（CLOSE 事件丢失）后，同一端口与远端被非目标进程复用
    a.handle(connect(GAME.pid, k));
    assert_eq!(action_of(&a, k), Some(FlowAction::Redirect { group: 2 }));
    a.handle(connect(OTHER.pid, k));
    assert_eq!(action_of(&a, k), Some(FlowAction::Bypass));
    assert_eq!(a.table().len(), 1);
}

#[test]
fn excluded_remotes_are_never_redirected() {
    // C-NET-05：去往代理服务器的流量，即使来自目标进程
    let a = attributor(InterceptSettings::default());
    let k = tcp(50001, "198.51.100.7:8443");
    assert_eq!(
        a.handle(connect(GAME.pid, k)),
        Some(Verdict::Bypass(BypassReason::Excluded))
    );
    assert_eq!(action_of(&a, k), Some(FlowAction::Bypass));
}

#[test]
fn exclusion_updates_apply_to_the_next_connect() {
    let a = attributor(InterceptSettings::default());
    let new_proxy = tcp(50001, "203.0.113.99:443");
    a.handle(connect(GAME.pid, new_proxy));
    assert_eq!(
        action_of(&a, new_proxy),
        Some(FlowAction::Redirect { group: 2 })
    );

    a.set_exclusions(ExclusionSet::new([], ["203.0.113.99".parse().unwrap()]));
    let again = tcp(50002, "203.0.113.99:443");
    assert_eq!(
        a.handle(connect(GAME.pid, again)),
        Some(Verdict::Bypass(BypassReason::Excluded))
    );
    assert_eq!(action_of(&a, again), Some(FlowAction::Bypass));
}

#[test]
fn unresolvable_processes_count_as_attribution_miss() {
    // C-NET-04：进程已退出或打不开
    let a = attributor(InterceptSettings::default());
    let k = tcp(50001, "203.0.113.24:443");
    assert_eq!(
        a.handle(connect(5555, k)),
        Some(Verdict::Bypass(BypassReason::Unattributed))
    );
    assert_eq!(
        a.table().entries(),
        vec![FlowRecord {
            key: k,
            pid: 5555,
            process: None,
            action: FlowAction::Bypass,
        }]
    );
    assert_eq!(a.counters.snapshot().attribution_miss, 1);
}

#[test]
fn attribute_returns_the_verdict_and_the_record() {
    // NETWORK 层的兜底归属（端口反查到 PID 之后）走同一条路径
    let a = attributor(InterceptSettings::default());
    let k = tcp(50001, "203.0.113.24:443");
    let (verdict, rec) = a.attribute(GAME.pid, k);
    assert_eq!(verdict, Verdict::Redirect { group: 2 });
    assert_eq!(rec, target(k, GAME, 2));
    assert_eq!(a.table().entries(), vec![rec]);
}

#[test]
fn blocked_target_flows_are_registered_as_block() {
    let a = attributor(InterceptSettings {
        block_quic: true,
        fail_policy: FailPolicy::Block,
        ..InterceptSettings::default()
    });
    let quic = key(Network::Udp, "192.168.1.5:6000", "203.0.113.24:443");
    assert_eq!(a.handle(connect(GAME.pid, quic)), Some(Verdict::Block));
    assert_eq!(
        a.table().get(Network::Udp, 6000, quic.remote),
        Some(record(quic, GAME, FlowAction::Block))
    );
}

#[test]
fn close_events_forget_the_socket() {
    let a = attributor(InterceptSettings::default());
    let k = tcp(50001, "203.0.113.24:443");
    a.handle(connect(GAME.pid, k));
    assert_eq!(
        a.handle(SocketEvent::Close {
            pid: GAME.pid,
            key: k
        }),
        None
    );
    assert!(a.table().is_empty());

    // 未连接的 UDP 套接字：CLOSE 不带远端，撤销该端口上的全部登记
    let u1 = key(Network::Udp, "0.0.0.0:6000", "203.0.113.24:27015");
    let u2 = key(Network::Udp, "0.0.0.0:6000", "203.0.113.25:27015");
    a.handle(connect(GAME.pid, u1));
    a.handle(connect(GAME.pid, u2));
    assert_eq!(a.table().len(), 2);
    let close = key(Network::Udp, "0.0.0.0:6000", "0.0.0.0:0");
    a.handle(SocketEvent::Close {
        pid: GAME.pid,
        key: close,
    });
    assert!(a.table().is_empty());

    // 无法归属的流同样按 CONNECT 里的 PID 撤销
    a.handle(connect(5555, k));
    a.handle(SocketEvent::Close { pid: 5555, key: k });
    assert!(a.table().is_empty());
}

#[test]
fn the_system_resolver_identifies_this_process() {
    let me = std::process::id();
    let key = SystemProcesses.resolve(me).expect("resolve this process");
    assert_eq!(key.pid, me);
    assert_eq!(
        Some(key.created_at),
        process_creation_time(me).ok(),
        "same identity as procwatch uses"
    );
    assert_eq!(SystemProcesses.resolve(0), None);
}
