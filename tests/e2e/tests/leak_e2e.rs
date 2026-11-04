// SPDX-License-Identifier: GPL-3.0-or-later
//! 泄漏检测（T-080，C-TEST-02）：真实的服务、sing-box 与 WinDivert，泄漏检测器判定。**只在测试虚拟机里、以
//! 管理员身份运行**（C-TEST-04），经 `cargo xtask sandbox-test --only leak_e2e`。
//!
//! 先用已知会泄漏的场景证明检测器抓得到（没有会话时的直连），再对已知不该泄漏的场景要求计数为 0；后者同时
//! 确认流量确实走过（回显正确、节点见过目标），检测器也确实看得到拦截层放行的包（非目标进程的直连），
//! 否则计数为 0 说明不了什么。先结束观察再断言：应用层的失败往往就是泄漏造成的，报告要留下来。
#![cfg(all(windows, feature = "vm-tests"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::Command;
use std::time::{Duration, Instant};

use procroute_e2e::harness::{
    Client, Echo, EchoRun, Node, Reply, Service, TEST_NET, echo_target_exe, finish_echo,
    install_dir, launcher_exe, record, start_session,
};
use procroute_e2e::leak_detector::{Detector, Report, TCP, UDP};
use serde_json::json;

const TCP_PORT: u16 = 8080;
const UDP_PORT: u16 = 5353;
/// 非目标进程（本测试进程）连接的端口。
const BYSTANDER_PORT: u16 = 8081;
/// 只在「代理地址不算泄漏」里用的第二个公网地址（TEST-NET-2）。
const OTHER_NET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);

fn tcp_echo(rounds: u32, bytes: usize, timeout: Duration) -> Echo {
    Echo {
        protocol: "tcp",
        remote: SocketAddr::from((TEST_NET, TCP_PORT)),
        rounds,
        bytes,
        timeout,
    }
}

fn udp_echo(rounds: u32, bytes: usize, timeout: Duration) -> Echo {
    Echo {
        protocol: "udp",
        remote: SocketAddr::from((TEST_NET, UDP_PORT)),
        rounds,
        bytes,
        timeout,
    }
}

fn detector() -> Detector {
    Detector::start(&install_dir(), &[]).expect("start the leak detector")
}

/// 本测试进程（非目标）发一个 SYN：拦截层必须原样放行，检测器必须看得到。赶在系统重传 SYN（约 1 秒）之前
/// 放弃：重传的 SYN 到达时套接字已经关闭，反查不到进程，会被计入 `attribution_miss`。
fn bystander_connect() {
    let _ = TcpStream::connect_timeout(
        &SocketAddr::from((TEST_NET, BYSTANDER_PORT)),
        Duration::from_millis(300),
    );
}

/// 检测器确实看到了拦截层放行的包，发往观察地址的包也都归属到了本测试进程。
fn assert_detector_saw_only_the_bystander(report: &Report) {
    let me = std::process::id();
    let to_test_net = report.flows_to(TEST_NET.into());
    assert!(
        to_test_net
            .iter()
            .any(|f| f.owner == Some(me) && f.remote_port == Some(BYSTANDER_PORT)),
        "the detector never saw the bystander: {:?}",
        report.flows
    );
    assert!(
        to_test_net.iter().all(|f| f.owner == Some(me)),
        "packets to the target address from someone else: {to_test_net:?}"
    );
}

fn assert_no_leak(report: &Report, targets: &[u32]) {
    assert_eq!(
        report.leaked_packets(targets),
        0,
        "leaks of {targets:?}: {:?}",
        report.leaks(targets)
    );
}

/// C-TEST-02 的基线：这些场景里每条流都归属得上，所以是 0（2026-11-04 连续 3 次运行、15 个会话实测）。
fn assert_attribution_within_baseline(service: &Service) {
    assert_eq!(
        service.attribution_miss(),
        0,
        "attribution_miss over the baseline"
    );
}

fn pids_and_failures(runs: &[EchoRun]) -> (Vec<u32>, Vec<&EchoRun>) {
    (
        runs.iter().map(|r| r.pid).collect(),
        runs.iter().filter(|r| !r.ok).collect(),
    )
}

#[test]
fn traffic_without_a_session_is_reported_as_a_leak() {
    // 已知泄漏：没有会话，目标进程直连。连接与回显会失败（没有人应答），包照样发出去
    let d = detector();
    let short = Duration::from_millis(1500);
    let tcp = tcp_echo(1, 16, short).run();
    let udp = udp_echo(1, 16, short).run();
    bystander_connect();
    let report = d.finish().expect("the detector was working");

    let leaks = report.leaks(&[tcp.pid]);
    assert!(
        !leaks.is_empty(),
        "TCP was not detected: {:?}",
        report.flows
    );
    for f in &leaks {
        assert_eq!(f.protocol, TCP, "{f:?}");
        assert_eq!(f.remote, IpAddr::V4(TEST_NET), "{f:?}");
        assert_eq!(f.remote_port, Some(TCP_PORT), "{f:?}");
    }
    let leaks = report.leaks(&[udp.pid]);
    assert!(
        !leaks.is_empty(),
        "UDP was not detected: {:?}",
        report.flows
    );
    for f in &leaks {
        assert_eq!(f.protocol, UDP, "{f:?}");
        assert_eq!(f.remote_port, Some(UDP_PORT), "{f:?}");
    }
    // 别的进程的包不算在目标头上
    let me = std::process::id();
    assert!(
        report
            .leaks(&[tcp.pid, udp.pid])
            .iter()
            .all(|f| f.owner != Some(me) && f.remote_port != Some(BYSTANDER_PORT))
    );
    assert!(
        report
            .leaks(&[me])
            .iter()
            .any(|f| f.remote_port == Some(BYSTANDER_PORT)),
        "{:?}",
        report.flows
    );
}

#[test]
fn traffic_to_a_proxy_server_is_not_a_leak() {
    // 同一个目标进程：发往代理服务器地址的不算，发往别处的照算
    let d = Detector::start(&install_dir(), &[IpAddr::V4(OTHER_NET)]).expect("start");
    let short = Duration::from_millis(800);
    let to_proxy = Echo {
        remote: SocketAddr::from((OTHER_NET, TCP_PORT)),
        ..tcp_echo(1, 16, short)
    }
    .run();
    let elsewhere = tcp_echo(1, 16, short).run();
    let report = d.finish().expect("the detector was working");
    assert_no_leak(&report, &[to_proxy.pid]);
    assert!(report.flows_to(OTHER_NET.into()).is_empty());
    assert!(report.allowed >= 1, "{report:?}");
    assert!(report.leaked_packets(&[elsewhere.pid]) >= 1, "{report:?}");
}

#[test]
fn target_tcp_and_udp_through_the_session_do_not_leak() {
    let d = detector();
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session(&node, &echo_target_exe().to_string_lossy());

    // 16 KiB 一轮：TCP 分成多个段；UDP 取一个 MTU 以内（超过的见 datagrams_larger_than_the_mtu）
    let long = Duration::from_secs(5);
    let tcp = tcp_echo(20, 16 * 1024, long).run();
    let udp = udp_echo(20, 1000, long).run();
    bystander_connect();
    // 趁拦截层还在结束观察：观察窗口就是会话运行的时间
    let report = d.finish().expect("the detector was working");
    c.stop_session();
    let targets = node.targets();
    record(
        "target_tcp_and_udp",
        &format!("{tcp:?}\n{udp:?}\nnode: {targets:?}\n{report:#?}"),
    );

    assert_no_leak(&report, &[tcp.pid, udp.pid]);
    assert_detector_saw_only_the_bystander(&report);
    assert!(tcp.ok, "TCP echo: {}", tcp.output);
    assert!(udp.ok, "UDP echo: {}", udp.output);
    assert!(
        targets.contains(&format!("{TEST_NET}:{TCP_PORT}")),
        "{targets:?}"
    );
    assert!(
        targets.contains(&format!("udp {TEST_NET}:{UDP_PORT}")),
        "{targets:?}"
    );
    assert_attribution_within_baseline(&service);
}

#[test]
fn the_first_packets_of_short_lived_targets_do_not_leak() {
    // 首包竞态（C-NET-04）：进程一启动就发包，进程追踪和 SOCKET 事件都可能还没到。成批并发，让窗口叠起来
    let d = detector();
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session(&node, &echo_target_exe().to_string_lossy());

    let long = Duration::from_secs(5);
    let mut runs = Vec::new();
    for _ in 0..6 {
        let children: Vec<_> = (0..4)
            .flat_map(|_| [tcp_echo(1, 64, long).spawn(), udp_echo(1, 64, long).spawn()])
            .collect();
        runs.extend(children.into_iter().map(finish_echo));
    }
    assert_eq!(runs.len(), 48);
    bystander_connect();
    let report = d.finish().expect("the detector was working");
    c.stop_session();

    let (pids, failed) = pids_and_failures(&runs);
    record(
        "first_packets",
        &format!("failed: {failed:#?}\n{report:#?}"),
    );
    assert_no_leak(&report, &pids);
    assert_detector_saw_only_the_bystander(&report);
    assert!(failed.is_empty(), "{failed:#?}");
    assert_attribution_within_baseline(&service);
}

#[test]
fn children_of_a_target_do_not_leak_their_first_packets() {
    // 方案只命中启动器（F7）：echo_target 只因继承成为目标，一启动就发包
    let d = detector();
    let node = Node::start(Reply::Echo);
    let launcher = launcher_exe();
    let (service, mut c) = start_session(&node, &launcher.to_string_lossy());

    let long = Duration::from_secs(5);
    let mut runs = Vec::new();
    for _ in 0..10 {
        for echo in [tcp_echo(1, 64, long), udp_echo(1, 64, long)] {
            runs.push(finish_echo(echo.spawn_via(&launcher)));
        }
    }
    bystander_connect();
    let report = d.finish().expect("the detector was working");
    c.stop_session();

    let (pids, failed) = pids_and_failures(&runs);
    record("children", &format!("failed: {failed:#?}\n{report:#?}"));
    assert_no_leak(&report, &pids);
    assert_detector_saw_only_the_bystander(&report);
    assert!(failed.is_empty(), "{failed:#?}");
    assert_attribution_within_baseline(&service);
}

/// 反复杀 sing-box，直到超出重启上限、会话进入 `blocked`（C-NET-03）。
fn kill_kernel_until_blocked(c: &mut Client) {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let status = c.call("session.status", json!({}));
        if status["state"] == "blocked" {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the session never entered blocked: {status}"
        );
        let _ = Command::new("taskkill.exe")
            .args(["/F", "/IM", "sing-box.exe"])
            .output();
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn a_dead_kernel_fails_closed() {
    // 设计文档 12.2：强杀 sing-box 后目标进程的新连接失败而非直连
    let d = detector();
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session(&node, &echo_target_exe().to_string_lossy());

    let long = Duration::from_secs(5);
    let before = tcp_echo(1, 64, long).run();

    // 杀掉之后、重启的窗口里：连得上是内核已经回来，连不上是拦截层在拦；哪种都不能直连
    let _ = Command::new("taskkill.exe")
        .args(["/F", "/IM", "sing-box.exe"])
        .output();
    let short = Duration::from_millis(1500);
    let during_restart = [tcp_echo(1, 64, short).run(), udp_echo(1, 64, short).run()];

    kill_kernel_until_blocked(&mut c);
    // 中继连内核的端口要等系统重试完才知道连不上（回环上约 2 秒），再回 RST：超时留够，看得到连接被重置
    let blocked = [
        tcp_echo(1, 64, Duration::from_secs(5)).run(),
        udp_echo(1, 64, short).run(),
    ];
    bystander_connect();
    let report = d.finish().expect("the detector was working");
    c.stop_session();
    record(
        "dead_kernel",
        &format!("{before:?}\n{during_restart:#?}\n{blocked:#?}\n{report:#?}"),
    );

    let mut pids = vec![before.pid];
    pids.extend(during_restart.iter().map(|r| r.pid));
    pids.extend(blocked.iter().map(|r| r.pid));
    assert_no_leak(&report, &pids);
    assert_detector_saw_only_the_bystander(&report);
    assert!(before.ok, "before the kill: {}", before.output);
    for run in &blocked {
        assert!(!run.ok, "reached the remote while blocked: {}", run.output);
    }
    assert_attribution_within_baseline(&service);
}

#[test]
fn datagrams_larger_than_the_mtu_go_through_the_session() {
    // 拦截层在分片之前看到完整的数据报（2026-11-04 实测），大数据报和小的一样进中继
    let d = detector();
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session(&node, &echo_target_exe().to_string_lossy());

    let run = udp_echo(3, 4000, Duration::from_secs(5)).run();
    bystander_connect();
    let report = d.finish().expect("the detector was working");
    c.stop_session();
    let targets = node.targets();
    record(
        "large_datagrams",
        &format!(
            "{run:?}\nnode: {targets:?}\nmiss: {}\n{report:#?}",
            service.attribution_miss()
        ),
    );

    assert_no_leak(&report, &[run.pid]);
    assert_detector_saw_only_the_bystander(&report);
    assert!(run.ok, "{}", run.output);
    assert_eq!(
        targets.iter().filter(|t| t.starts_with("udp ")).count(),
        3,
        "{targets:?}"
    );
    assert_attribution_within_baseline(&service);
}
