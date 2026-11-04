// SPDX-License-Identifier: GPL-3.0-or-later
//! 不加载驱动的测试：用手拼的包驱动引擎。真实收发在 `tests/redirect_vm.rs` 与 `tests/precise_vm.rs`。

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, sync_channel};

use procroute_proto::profile::FailPolicy;

use super::*;
use crate::divert::ffi::{Layer, WinDivert};

const GAME: ProcessKey = ProcessKey {
    pid: 4120,
    created_at: 10,
};
const OTHER: ProcessKey = ProcessKey {
    pid: 77,
    created_at: 3,
};
const IFACE: NetworkData = NetworkData {
    if_idx: 12,
    sub_if_idx: 0,
};

fn sock(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// 拼一个 TCP 包（IPv4 或 IPv6，取决于地址），20 字节 TCP 头，4 字节负载。
fn tcp(src: SocketAddr, dst: SocketAddr, flags: u8) -> Vec<u8> {
    let mut p = match (src.ip(), dst.ip()) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let mut p = vec![0u8; 20 + 20 + 4];
            p[0] = 0x45;
            p[2..4].copy_from_slice(&44u16.to_be_bytes());
            p[6] = 0x40;
            p[8] = 128;
            p[9] = 6;
            p[12..16].copy_from_slice(&s.octets());
            p[16..20].copy_from_slice(&d.octets());
            p
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let mut p = vec![0u8; 40 + 20 + 4];
            p[0] = 0x60;
            p[4..6].copy_from_slice(&24u16.to_be_bytes());
            p[6] = 6;
            p[7] = 64;
            p[8..24].copy_from_slice(&s.octets());
            p[24..40].copy_from_slice(&d.octets());
            p
        }
        _ => panic!("mixed families"),
    };
    let l4 = if src.is_ipv4() { 20 } else { 40 };
    p[l4..l4 + 2].copy_from_slice(&src.port().to_be_bytes());
    p[l4 + 2..l4 + 4].copy_from_slice(&dst.port().to_be_bytes());
    p[l4 + 12] = 5 << 4;
    p[l4 + 13] = flags;
    p
}

fn app_addr() -> Address {
    let mut a = Address::from_parts(Layer::Network as u32 | (1 << 17), [0; 64]);
    a.set_network(IFACE);
    a
}

fn relay_addr() -> Address {
    Address::from_parts(Layer::Network as u32 | (1 << 17) | (1 << 18), [0; 64])
}

fn inbound_addr() -> Address {
    Address::from_parts(Layer::Network as u32, [0; 64])
}

#[derive(Default)]
struct FakeMap {
    refuse: Mutex<bool>,
    mapped: Mutex<Vec<(u16, SocketAddr, ProcessKey, u16)>>,
    unmapped: Mutex<Vec<u16>>,
}

impl RedirectMap for FakeMap {
    fn map(
        &self,
        network: Network,
        port: u16,
        original: SocketAddr,
        p: ProcessKey,
        g: u16,
    ) -> bool {
        assert_eq!(network, Network::Tcp);
        if *self.refuse.lock().unwrap() {
            return false;
        }
        self.mapped.lock().unwrap().push((port, original, p, g));
        true
    }

    fn unmap(&self, network: Network, port: u16) {
        assert_eq!(network, Network::Tcp);
        self.unmapped.lock().unwrap().push(port);
    }
}

struct Rig {
    engine: Engine,
    map: Arc<FakeMap>,
    events: Receiver<FlowEvent>,
}

const RELAY4: &str = "127.0.0.1:7000";
const RELAY6: &str = "[::1]:7001";

fn rig_with(fail_policy: FailPolicy, v6: bool) -> Rig {
    rig_full(
        InterceptSettings {
            fail_policy,
            ..InterceptSettings::default()
        },
        v6,
        None,
    )
}

fn rig_full(settings: InterceptSettings, v6: bool, udp: Option<Arc<dyn UdpForward>>) -> Rig {
    let map = Arc::new(FakeMap::default());
    let (tx, events) = sync_channel(64);
    let engine = Engine::new(
        Arc::new(FlowTable::default()),
        Relays {
            v4: sock(RELAY4),
            v6: v6.then(|| sock(RELAY6)),
        },
        map.clone(),
        udp,
        settings,
        Arc::new(Counters::default()),
        tx,
    );
    Rig {
        engine,
        map,
        events,
    }
}

fn rig() -> Rig {
    rig_with(FailPolicy::Block, true)
}

impl Rig {
    fn register(&self, local: &str, remote: &str, process: ProcessKey, action: FlowAction) {
        self.engine.flows.register(FlowRecord {
            key: FlowKey {
                network: Network::Tcp,
                local: sock(local),
                remote: sock(remote),
            },
            pid: process.pid,
            process: Some(process),
            action,
        });
    }

    /// 处理一个包，返回结果、改写后的包与地址信息。
    fn send(
        &self,
        mut pkt: Vec<u8>,
        mut addr: Address,
        now: Instant,
    ) -> (Outcome, Vec<u8>, Address) {
        let out = self.engine.process(&mut pkt, &mut addr, now);
        (out, pkt, addr)
    }

    fn events(&self) -> Vec<FlowEvent> {
        self.events.try_iter().collect()
    }
}

fn addrs(pkt: &mut [u8]) -> (SocketAddr, SocketAddr) {
    let p = packet::parse(pkt).expect("parse");
    (p.src(), p.dst())
}

const APP: &str = "192.168.1.5:50001";
const REMOTE: &str = "203.0.113.24:443";

#[test]
fn a_target_connection_goes_to_the_relay_and_back() {
    let r = rig();
    let t0 = Instant::now();
    r.register(APP, REMOTE, GAME, FlowAction::Redirect { group: 2 });

    // 第一个 SYN：登记 NAT 后改写成发往回环中继
    let (out, mut syn, addr) = r.send(tcp(sock(APP), sock(REMOTE), tcp_flags::SYN), app_addr(), t0);
    assert_eq!(out, Outcome::Inject);
    assert_eq!(addrs(&mut syn), (sock("127.0.0.1:50001"), sock(RELAY4)));
    assert!(addr.outbound() && !addr.loopback());
    assert_eq!(
        *r.map.mapped.lock().unwrap(),
        vec![(50001, sock(REMOTE), GAME, 2)]
    );
    let key = FlowKey {
        network: Network::Tcp,
        local: sock(APP),
        remote: sock(REMOTE),
    };
    assert_eq!(
        r.events(),
        vec![FlowEvent::Redirected {
            key,
            process: GAME,
            group: 2
        }]
    );
    // 登记用完即移出
    assert!(r.engine.flows.is_empty());

    // 中继的 SYN-ACK（回环包）：改写成原始目标发来的入站包，回到应用原来的接口
    let (out, mut synack, addr) = r.send(
        tcp(
            sock(RELAY4),
            sock("127.0.0.1:50001"),
            tcp_flags::SYN | tcp_flags::ACK,
        ),
        relay_addr(),
        t0,
    );
    assert_eq!(out, Outcome::Inject);
    assert_eq!(addrs(&mut synack), (sock(REMOTE), sock(APP)));
    assert!(!addr.outbound() && !addr.loopback());
    assert_eq!(addr.network(), IFACE);

    // 之后的数据包按连接跟踪继续改写
    let (out, mut data, _) = r.send(tcp(sock(APP), sock(REMOTE), tcp_flags::ACK), app_addr(), t0);
    assert_eq!(out, Outcome::Inject);
    assert_eq!(addrs(&mut data), (sock("127.0.0.1:50001"), sock(RELAY4)));
    assert_eq!(r.engine.active(), 1);
    assert_eq!(r.engine.conn_info(50001), Some((key, GAME, 2)));
}

#[test]
fn non_target_traffic_is_passed_back_untouched() {
    // C-NET-02
    let r = rig();
    let t0 = Instant::now();
    r.register(APP, REMOTE, OTHER, FlowAction::Bypass);
    let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
    let (out, after, _) = r.send(syn.clone(), app_addr(), t0);
    assert_eq!(out, Outcome::Pass);
    assert_eq!(after, syn, "not a single byte changed");
    assert!(r.engine.flows.is_empty(), "the bypass record is used up");
    // 之后的包也原样放回
    let data = tcp(sock(APP), sock(REMOTE), tcp_flags::ACK);
    let (out, after, _) = r.send(data.clone(), app_addr(), t0);
    assert_eq!((out, after), (Outcome::Pass, data));
    assert!(r.map.mapped.lock().unwrap().is_empty());
    assert!(r.events().is_empty());
}

#[test]
fn an_unattributed_first_syn_is_held_and_other_packets_pass() {
    // C-NET-04：SYN 先于 SOCKET 事件到达
    let r = rig();
    let t0 = Instant::now();
    let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
    assert_eq!(r.send(syn, app_addr(), t0).0, Outcome::Hold);
    // 不是新连接的 SYN：不认识就放回
    for flags in [
        tcp_flags::ACK,
        tcp_flags::SYN | tcp_flags::ACK,
        tcp_flags::FIN | tcp_flags::ACK,
    ] {
        let pkt = tcp(sock(APP), sock(REMOTE), flags);
        assert_eq!(r.send(pkt, app_addr(), t0).0, Outcome::Pass, "{flags:#x}");
    }
    // 入站包（不在过滤器里，防御性地放回）
    let inbound = tcp(sock(REMOTE), sock(APP), tcp_flags::ACK);
    assert_eq!(r.send(inbound, inbound_addr(), t0).0, Outcome::Pass);
    // 登记到了之后重试就能处理
    r.register(APP, REMOTE, GAME, FlowAction::Redirect { group: 0 });
    let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
    assert_eq!(r.send(syn, app_addr(), t0).0, Outcome::Inject);
}

#[test]
fn blocked_flows_are_dropped_including_retransmitted_syns() {
    let r = rig();
    let t0 = Instant::now();
    r.register(APP, REMOTE, GAME, FlowAction::Block);
    for _ in 0..2 {
        let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
        assert_eq!(r.send(syn, app_addr(), t0).0, Outcome::Drop);
    }
    assert_eq!(r.events().len(), 2);
    assert!(r.map.mapped.lock().unwrap().is_empty());
}

#[test]
fn a_failed_nat_mapping_follows_fail_policy() {
    // C-NET-07：默认阻断，绝不静默放行
    let r = rig();
    *r.map.refuse.lock().unwrap() = true;
    r.register(APP, REMOTE, GAME, FlowAction::Redirect { group: 0 });
    let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
    assert_eq!(r.send(syn, app_addr(), Instant::now()).0, Outcome::Drop);
    assert!(matches!(r.events()[..], [FlowEvent::Blocked { .. }]));
    assert_eq!(r.engine.active(), 0);

    let allow = rig_with(FailPolicy::Allow, true);
    *allow.map.refuse.lock().unwrap() = true;
    allow.register(APP, REMOTE, GAME, FlowAction::Redirect { group: 0 });
    let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
    assert_eq!(allow.send(syn, app_addr(), Instant::now()).0, Outcome::Pass);
}

#[test]
fn ipv6_flows_use_the_ipv6_relay_or_fail_closed_without_one() {
    let app = "[2001:db8::5]:50001";
    let remote = "[2001:db8::1]:443";
    let r = rig();
    let t0 = Instant::now();
    r.register(app, remote, GAME, FlowAction::Redirect { group: 1 });
    let (out, mut syn, _) = r.send(tcp(sock(app), sock(remote), tcp_flags::SYN), app_addr(), t0);
    assert_eq!(out, Outcome::Inject);
    assert_eq!(addrs(&mut syn), (sock("[::1]:50001"), sock(RELAY6)));
    let (out, mut back, _) = r.send(
        tcp(
            sock(RELAY6),
            sock("[::1]:50001"),
            tcp_flags::SYN | tcp_flags::ACK,
        ),
        relay_addr(),
        t0,
    );
    assert_eq!(out, Outcome::Inject);
    assert_eq!(addrs(&mut back), (sock(remote), sock(app)));

    let no_v6 = rig_with(FailPolicy::Block, false);
    no_v6.register(app, remote, GAME, FlowAction::Redirect { group: 1 });
    let syn = tcp(sock(app), sock(remote), tcp_flags::SYN);
    assert_eq!(no_v6.send(syn, app_addr(), t0).0, Outcome::Drop);
    assert!(no_v6.map.mapped.lock().unwrap().is_empty());
}

#[test]
fn relay_packets_without_a_connection_are_dropped() {
    let r = rig();
    let t0 = Instant::now();
    // 映射端口上没有连接（已回收）
    let stray = tcp(sock(RELAY4), sock("127.0.0.1:50009"), tcp_flags::RST);
    assert_eq!(r.send(stray, relay_addr(), t0).0, Outcome::Drop);
    // 不是中继端口发出的回环包：与我们无关
    let other = tcp(
        sock("127.0.0.1:9999"),
        sock("127.0.0.1:50009"),
        tcp_flags::ACK,
    );
    assert_eq!(r.send(other, relay_addr(), t0).0, Outcome::Pass);
}

fn open(r: &Rig, t: Instant) {
    r.register(APP, REMOTE, GAME, FlowAction::Redirect { group: 0 });
    let syn = tcp(sock(APP), sock(REMOTE), tcp_flags::SYN);
    assert_eq!(r.send(syn, app_addr(), t).0, Outcome::Inject);
    r.events();
}

#[test]
fn connections_linger_after_both_fins_then_are_reclaimed() {
    let r = rig();
    let t0 = Instant::now();
    open(&r, t0);
    let fin = tcp(sock(APP), sock(REMOTE), tcp_flags::FIN | tcp_flags::ACK);
    r.send(fin, app_addr(), t0);
    let fin_back = tcp(
        sock(RELAY4),
        sock("127.0.0.1:50001"),
        tcp_flags::FIN | tcp_flags::ACK,
    );
    r.send(fin_back, relay_addr(), t0);
    // 收尾后迟到的 ACK 仍走中继，不会被当成陌生连接发往原始目标
    let late = tcp(sock(APP), sock(REMOTE), tcp_flags::ACK);
    assert_eq!(r.send(late, app_addr(), t0).0, Outcome::Inject);
    assert_eq!(r.engine.sweep(t0 + FIN_LINGER - Duration::from_secs(1)), 0);
    assert_eq!(r.engine.sweep(t0 + FIN_LINGER), 1);
    assert_eq!(*r.map.unmapped.lock().unwrap(), vec![50001]);
    assert!(matches!(r.events()[..], [FlowEvent::Closed { .. }]));
    // 回收之后再来的包不认识，放回
    let after = tcp(sock(APP), sock(REMOTE), tcp_flags::ACK);
    assert_eq!(r.send(after, app_addr(), t0).0, Outcome::Pass);
}

#[test]
fn reset_and_idle_connections_are_reclaimed() {
    let r = rig();
    let t0 = Instant::now();
    open(&r, t0);
    let rst = tcp(sock(RELAY4), sock("127.0.0.1:50001"), tcp_flags::RST);
    r.send(rst, relay_addr(), t0);
    assert_eq!(r.engine.sweep(t0 + RST_LINGER), 1);

    let idle = rig();
    open(&idle, t0);
    assert_eq!(
        idle.engine.sweep(t0 + IDLE_LIMIT - Duration::from_secs(1)),
        0
    );
    assert_eq!(idle.engine.sweep(t0 + IDLE_LIMIT), 1);
}

#[test]
fn a_new_connection_on_a_lingering_port_replaces_the_old_one() {
    let r = rig();
    let t0 = Instant::now();
    open(&r, t0);
    // 同一源端口连向另一个远端
    let remote2 = "203.0.113.25:443";
    r.register(APP, remote2, GAME, FlowAction::Redirect { group: 1 });
    let syn = tcp(sock(APP), sock(remote2), tcp_flags::SYN);
    assert_eq!(r.send(syn, app_addr(), t0).0, Outcome::Inject);
    assert_eq!(*r.map.unmapped.lock().unwrap(), vec![50001]);
    let events = r.events();
    assert!(matches!(
        events[..],
        [
            FlowEvent::Closed { .. },
            FlowEvent::Redirected { group: 1, .. }
        ]
    ));
    assert_eq!(r.engine.active(), 1);
    assert_eq!(
        r.engine.conn_info(50001).map(|(k, _, _)| k.remote),
        Some(sock(remote2))
    );
}

#[test]
fn clearing_reclaims_every_connection() {
    let r = rig();
    open(&r, Instant::now());
    r.engine.clear();
    assert_eq!(r.engine.active(), 0);
    assert_eq!(*r.map.unmapped.lock().unwrap(), vec![50001]);
    assert!(matches!(r.events()[..], [FlowEvent::Closed { .. }]));
}

#[test]
fn the_filter_compiles_at_the_network_layer() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert/bin");
    let wd = WinDivert::load(
        &dir.canonicalize()
            .expect("run `cargo xtask fetch-deps` first"),
    )
    .expect("load the locked WinDivert");
    for relays in [
        Relays {
            v4: sock(RELAY4),
            v6: Some(sock(RELAY6)),
        },
        Relays {
            v4: sock(RELAY4),
            v6: None,
        },
        Relays {
            v4: sock("127.0.0.1:7000"),
            v6: Some(sock("[::1]:7000")),
        },
    ] {
        let filter = relays.filter();
        wd.check_filter(&filter, Layer::Network)
            .unwrap_or_else(|e| panic!("{filter}: {e}"));
    }
}

/// 拼一个 IPv4 UDP 包，4 字节负载。
fn udp4(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let (IpAddr::V4(s), IpAddr::V4(d)) = (src.ip(), dst.ip()) else {
        panic!("IPv4 only");
    };
    let mut p = vec![0u8; 20 + 8 + 4];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&32u16.to_be_bytes());
    p[8] = 128;
    p[9] = 17;
    p[12..16].copy_from_slice(&s.octets());
    p[16..20].copy_from_slice(&d.octets());
    p[20..22].copy_from_slice(&src.port().to_be_bytes());
    p[22..24].copy_from_slice(&dst.port().to_be_bytes());
    p[24..26].copy_from_slice(&12u16.to_be_bytes());
    p
}

impl Rig {
    fn register_udp(&self, local: &str, remote: &str, process: ProcessKey, action: FlowAction) {
        self.engine.flows.register(FlowRecord {
            key: FlowKey {
                network: Network::Udp,
                local: sock(local),
                remote: sock(remote),
            },
            pid: process.pid,
            process: Some(process),
            action,
        });
    }
}

#[test]
fn target_udp_follows_fail_policy_until_the_udp_relay_lands() {
    // C-NET-07：中继接入之前，目标进程的 UDP 处理不了
    let game = "192.168.1.5:6000";
    let server = "203.0.113.24:27015";
    let dns = "8.8.8.8:53";
    let r = rig();
    let t0 = Instant::now();
    r.register_udp(game, server, GAME, FlowAction::Redirect { group: 0 });
    r.register_udp(game, dns, GAME, FlowAction::Redirect { group: 0 });
    for remote in [server, dns, server] {
        let (out, _, _) = r.send(udp4(sock(game), sock(remote)), app_addr(), t0);
        assert_eq!(out, Outcome::Drop, "{remote}");
    }
    // 登记不因数据报而消耗，也不发事件
    assert_eq!(r.engine.flows.len(), 2);
    assert!(r.events().is_empty());
    assert_eq!(r.engine.counters.snapshot().blocked, 3);

    let allow = rig_with(FailPolicy::Allow, true);
    allow.register_udp(game, server, GAME, FlowAction::Redirect { group: 0 });
    let (out, _, _) = allow.send(udp4(sock(game), sock(server)), app_addr(), t0);
    assert_eq!(out, Outcome::Pass);
}

#[test]
fn non_target_udp_passes_untouched() {
    let r = rig();
    let t0 = Instant::now();
    let (src, dst) = ("192.168.1.5:6001", "203.0.113.24:443");
    r.register_udp(src, dst, OTHER, FlowAction::Bypass);
    let pkt = udp4(sock(src), sock(dst));
    let (out, after, _) = r.send(pkt.clone(), app_addr(), t0);
    assert_eq!((out, after), (Outcome::Pass, pkt));
    // 入站 UDP 不在过滤器里，防御性地放回
    let inbound = udp4(sock("203.0.113.24:443"), sock("192.168.1.5:6001"));
    assert_eq!(r.send(inbound, inbound_addr(), t0).0, Outcome::Pass);
}

/// 交给中继的一个数据报：会话、进程组、目的地址、负载。
type Forwarded = (SocketAddr, u16, SocketAddr, Vec<u8>);

/// 假的 UDP 中继：记下交来的数据报；`refuse` 时拒收。
#[derive(Default)]
struct FakeUdp {
    refuse: bool,
    forwarded: Mutex<Vec<Forwarded>>,
}

impl UdpForward for FakeUdp {
    fn forward(&self, session: SocketAddr, group: u16, dst: SocketAddr, payload: &[u8]) -> bool {
        if self.refuse {
            return false;
        }
        self.forwarded
            .lock()
            .unwrap()
            .push((session, group, dst, payload.to_vec()));
        true
    }

    fn attach(&self, _: Option<Arc<dyn crate::divert::udp::UdpReplies>>) {}
}

fn udp_rig(settings: InterceptSettings) -> (Rig, Arc<FakeUdp>) {
    let udp = Arc::new(FakeUdp::default());
    (rig_full(settings, true, Some(udp.clone())), udp)
}

/// 带 4 字节负载 `ping` 的 UDP 包。
fn ping(src: &str, dst: &str) -> Vec<u8> {
    let mut p = udp4(sock(src), sock(dst));
    p[28..32].copy_from_slice(b"ping");
    p
}

const GAME_UDP: &str = "192.168.1.5:6000";
const SERVER: &str = "203.0.113.24:27015";

#[test]
fn target_udp_goes_to_the_udp_relay_and_the_original_is_dropped() {
    let (r, udp) = udp_rig(InterceptSettings::default());
    let t0 = Instant::now();
    r.register_udp(GAME_UDP, SERVER, GAME, FlowAction::Redirect { group: 2 });
    let (out, _, _) = r.send(ping(GAME_UDP, SERVER), app_addr(), t0);
    assert_eq!(out, Outcome::Drop);
    assert_eq!(
        *udp.forwarded.lock().unwrap(),
        vec![(sock(GAME_UDP), 2, sock(SERVER), b"ping".to_vec())]
    );
    // 套接字登记下来，回包知道往哪个接口注入
    assert_eq!(
        r.engine.udp_sockets().reply_target(6000),
        Some((sock(GAME_UDP), IFACE))
    );
    assert_eq!(r.engine.udp_sockets().owner(6000), Some((GAME, 2)));

    // 同一套接字发往新的远端：SOCKET 层的登记还没到，按套接字认出来
    let other = "203.0.113.25:27015";
    assert_eq!(
        r.send(ping(GAME_UDP, other), app_addr(), t0).0,
        Outcome::Drop
    );
    assert_eq!(udp.forwarded.lock().unwrap().len(), 2);
    assert!(r.events().is_empty(), "no event per datagram");
}

#[test]
fn a_datagram_ahead_of_its_socket_event_is_held_not_passed() {
    // C-NET-04：刚启动的目标进程的第一个数据报先于 CONNECT 事件，放回去就是泄漏
    let (r, udp) = udp_rig(InterceptSettings::default());
    let t0 = Instant::now();
    let pkt = ping(GAME_UDP, SERVER);
    let (out, after, _) = r.send(pkt.clone(), app_addr(), t0);
    assert_eq!((out, after), (Outcome::Hold, pkt.clone()));
    assert!(udp.forwarded.lock().unwrap().is_empty());
    // 暂存期间不消耗任何东西，归属到了再处理一次就进中继
    assert_eq!(r.send(pkt.clone(), app_addr(), t0).0, Outcome::Hold);
    r.register_udp(GAME_UDP, SERVER, GAME, FlowAction::Redirect { group: 0 });
    assert_eq!(r.send(pkt, app_addr(), t0).0, Outcome::Drop);
    assert_eq!(udp.forwarded.lock().unwrap().len(), 1);
}

#[test]
fn records_beat_the_socket_table() {
    // 目标套接字发往被排除的远端（例如代理服务器）：放行，不进中继（C-NET-05）
    let (r, udp) = udp_rig(InterceptSettings::default());
    let t0 = Instant::now();
    r.register_udp(GAME_UDP, SERVER, GAME, FlowAction::Redirect { group: 0 });
    r.send(ping(GAME_UDP, SERVER), app_addr(), t0);
    let proxy = "198.51.100.7:8443";
    r.register_udp(GAME_UDP, proxy, GAME, FlowAction::Bypass);
    let pkt = ping(GAME_UDP, proxy);
    let (out, after, _) = r.send(pkt.clone(), app_addr(), t0);
    assert_eq!((out, after), (Outcome::Pass, pkt));
    // 阻断的登记（QUIC）丢弃
    let quic = "203.0.113.24:443";
    r.register_udp(GAME_UDP, quic, GAME, FlowAction::Block);
    assert_eq!(
        r.send(ping(GAME_UDP, quic), app_addr(), t0).0,
        Outcome::Drop
    );
    assert_eq!(udp.forwarded.lock().unwrap().len(), 1);
}

#[test]
fn quic_blocking_and_udp_off_apply_to_known_target_sockets() {
    let t0 = Instant::now();
    let (r, udp) = udp_rig(InterceptSettings {
        block_quic: true,
        ..InterceptSettings::default()
    });
    r.register_udp(GAME_UDP, SERVER, GAME, FlowAction::Redirect { group: 0 });
    r.send(ping(GAME_UDP, SERVER), app_addr(), t0);
    // 没有登记、按套接字认出的 443：照样阻断
    assert_eq!(
        r.send(ping(GAME_UDP, "203.0.113.9:443"), app_addr(), t0).0,
        Outcome::Drop
    );
    assert_eq!(udp.forwarded.lock().unwrap().len(), 1);

    // 关了 UDP 代理：只劫持 53，其余照常直连
    let (r, udp) = udp_rig(InterceptSettings {
        udp_enabled: false,
        ..InterceptSettings::default()
    });
    r.register_udp(
        GAME_UDP,
        "8.8.8.8:53",
        GAME,
        FlowAction::Redirect { group: 0 },
    );
    assert_eq!(
        r.send(ping(GAME_UDP, "8.8.8.8:53"), app_addr(), t0).0,
        Outcome::Drop
    );
    let game = ping(GAME_UDP, SERVER);
    assert_eq!(r.send(game.clone(), app_addr(), t0).0, Outcome::Pass);
    assert_eq!(udp.forwarded.lock().unwrap().len(), 1);
}

#[test]
fn a_refused_datagram_is_dropped_never_sent_directly() {
    // C-NET-03：中继拒收（会话超限、队列满）也不直连
    let udp = Arc::new(FakeUdp {
        refuse: true,
        ..FakeUdp::default()
    });
    let r = rig_full(InterceptSettings::default(), true, Some(udp));
    r.register_udp(GAME_UDP, SERVER, GAME, FlowAction::Redirect { group: 0 });
    assert_eq!(
        r.send(ping(GAME_UDP, SERVER), app_addr(), Instant::now()).0,
        Outcome::Drop
    );
}

#[test]
fn idle_udp_sockets_are_swept_with_the_connections() {
    let (r, _) = udp_rig(InterceptSettings::default());
    let t0 = Instant::now();
    r.register_udp(GAME_UDP, SERVER, GAME, FlowAction::Redirect { group: 0 });
    r.send(ping(GAME_UDP, SERVER), app_addr(), t0);
    r.engine.sweep(t0 + crate::divert::udp::UDP_IDLE);
    assert!(r.engine.udp_sockets().is_empty());
    // 回收之后、又没有登记：不认识，暂存后重新归属，不能放回
    r.engine.flows.clear();
    assert_eq!(
        r.send(ping(GAME_UDP, SERVER), app_addr(), t0).0,
        Outcome::Hold
    );
}
