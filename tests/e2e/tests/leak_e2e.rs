// SPDX-License-Identifier: GPL-3.0-or-later
//! 泄漏检测（T-080，C-TEST-02）：真实的服务、sing-box 与 WinDivert，泄漏检测器判定。**只在测试虚拟机里、以
//! 管理员身份运行**（C-TEST-04），经 `cargo xtask sandbox-test --only leak_e2e`。
//!
//! 先用已知会泄漏的场景证明检测器抓得到（没有会话时的直连），再对已知不该泄漏的场景要求计数为 0；后者同时
//! 确认流量确实走过（回显正确、节点见过目标），检测器也确实看得到拦截层放行的包（非目标进程的直连），
//! 否则计数为 0 说明不了什么。先结束观察再断言：应用层的失败往往就是泄漏造成的，报告要留下来。
#![cfg(all(windows, feature = "vm-tests"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use procroute_e2e::harness::{
    Client, Echo, EchoRun, Node, Reply, Service, TEST_NET, echo_target_exe, finish_echo,
    install_dir, launcher_exe, record, start_session, start_session_with,
};
use procroute_e2e::leak_detector::{Detector, Flow, Report, TCP, UDP};
use procroute_proto::profile::{FailPolicy, MatchType, Mode, Profile};
use serde_json::json;

const TCP_PORT: u16 = 8080;
const UDP_PORT: u16 = 5353;
/// 非目标进程（本测试进程）连接的端口。
const BYSTANDER_PORT: u16 = 8081;
/// 只在「代理地址不算泄漏」里用的第二个公网地址（TEST-NET-2）。
const OTHER_NET: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 1);
const ICMP: u8 = 1;
/// 留给实验用的协议号（RFC 3692）：代表拦截层不认识的协议。
const EXPERIMENTAL_PROTOCOL: u8 = 253;
const SYSTEM_PID: u32 = 4;

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

fn system32(file: &str) -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\{file}")
}

fn powershell_exe() -> String {
    system32(r"WindowsPowerShell\v1.0\powershell.exe")
}

/// 用系统 ping 接口发一个回显请求。回显没有人应答，退出码只对回环有意义。
fn system_ping(to: IpAddr) -> Output {
    Command::new(system32("PING.EXE"))
        .args(["-n", "1", "-w", "300", &to.to_string()])
        .output()
        .expect("run ping")
}

/// PowerShell 开一个原始套接字往 [`TEST_NET`] 发一个包。返回进程号与它有没有报错。
fn raw_socket_send(protocol: u8) -> (u32, bool) {
    let script = format!(
        "$s = New-Object Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork, \
         [Net.Sockets.SocketType]::Raw, [Net.Sockets.ProtocolType]{protocol}); \
         $b = [byte[]](8,0,0xF7,0xFF,0,0,0,0); \
         $e = New-Object Net.IPEndPoint([Net.IPAddress]::Parse('{TEST_NET}'), 0); \
         [void]$s.SendTo($b, $e); $s.Close()"
    );
    let mut child = Command::new(powershell_exe())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("run powershell");
    let pid = child.id();
    let ok = child.wait().expect("wait for powershell").success();
    (pid, ok)
}

/// 发往 [`TEST_NET`] 的 ICMP 流。
fn icmp_flows(report: &Report) -> Vec<Flow> {
    report
        .flows_to(TEST_NET.into())
        .into_iter()
        .filter(|f| f.protocol == ICMP)
        .collect()
}

fn assert_detector_saw_the_bystander(report: &Report) {
    let me = std::process::id();
    assert!(
        report
            .flows_to(TEST_NET.into())
            .iter()
            .any(|f| f.owner == Some(me) && f.remote_port == Some(BYSTANDER_PORT)),
        "the detector never saw the bystander: {:?}",
        report.flows
    );
}

/// 只命中 PowerShell 的方案。测试程序经 run.ps1 启动，是 PowerShell 的后代，所以不能开继承。
fn powershell_only(p: &mut Profile) {
    p.groups[0].include_children = false;
}

#[test]
fn icmp_is_attributed_to_whoever_the_system_reports() {
    // 没有会话时确认检测器如实报出来：`ping.exe` 走系统接口，事件和包都归 System；进程自己开原始套接字发的，
    // 归进程自己
    let d = detector();
    let mut ping = Command::new(system32("PING.EXE"))
        .args(["-n", "1", "-w", "300", &TEST_NET.to_string()])
        .stdout(Stdio::null())
        .spawn()
        .expect("run ping");
    let ping_pid = ping.id();
    let _ = ping.wait();
    let (raw_pid, sent) = raw_socket_send(ICMP);
    assert!(sent, "the raw socket failed");
    let report = d.finish().expect("the detector was working");

    let icmp = icmp_flows(&report);
    assert!(
        icmp.iter().any(|f| f.owner == Some(raw_pid)),
        "the raw socket's echo: {icmp:?}"
    );
    assert!(
        icmp.iter().any(|f| f.owner == Some(SYSTEM_PID)),
        "the ping API's echo goes out as System: {icmp:?}"
    );
    assert!(
        icmp.iter().all(|f| f.owner != Some(ping_pid)),
        "ping.exe itself is never reported: {icmp:?}"
    );
}

#[test]
fn block_sessions_stop_the_other_protocols_of_targets() {
    // C-NET-07：目标进程的原始套接字，ICMP 和拦截层不认识的协议都发不出去
    let d = detector();
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session_with(&node, &powershell_exe(), powershell_only);
    let (icmp, _) = raw_socket_send(ICMP);
    let (other, _) = raw_socket_send(EXPERIMENTAL_PROTOCOL);
    // 非目标进程不受影响（C-NET-02）：开关没开，系统 ping 接口的包照常发出
    let ping = system_ping(TEST_NET.into());
    bystander_connect();
    let report = d.finish().expect("the detector was working");
    c.stop_session();
    record(
        "block_raw_sockets",
        &format!(
            "raw pids {icmp} {other}\n{}\n{report:#?}",
            String::from_utf8_lossy(&ping.stdout)
        ),
    );

    assert_no_leak(&report, &[icmp, other]);
    assert!(
        report
            .flows_to(TEST_NET.into())
            .iter()
            .all(|f| f.protocol != EXPERIMENTAL_PROTOCOL),
        "{:?}",
        report.flows
    );
    assert!(
        icmp_flows(&report)
            .iter()
            .any(|f| f.owner == Some(SYSTEM_PID)),
        "ping from a non-target must still leave: {:?}",
        report.flows
    );
    assert_detector_saw_the_bystander(&report);
    assert_attribution_within_baseline(&service);
}

#[test]
fn allow_sessions_leave_raw_sockets_alone() {
    // `allow` 是用户选择的放行（C-NET-07）
    let d = detector();
    let node = Node::start(Reply::Echo);
    let (_service, mut c) = start_session_with(&node, &powershell_exe(), |p| {
        powershell_only(p);
        p.fail_policy = FailPolicy::Allow;
    });
    let (icmp, sent) = raw_socket_send(ICMP);
    let report = d.finish().expect("the detector was working");
    c.stop_session();
    assert!(sent, "the raw socket failed");
    assert!(report.leaked_packets(&[icmp]) >= 1, "{:?}", report.flows);
}

#[test]
fn blocking_all_ping_lasts_exactly_as_long_as_the_session() {
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session_with(&node, &echo_target_exe().to_string_lossy(), |p| {
        p.icmp.block_all_ping = true;
    });

    let d = detector();
    let outside = system_ping(TEST_NET.into());
    let loopback = system_ping(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let long = Duration::from_secs(5);
    let tcp = tcp_echo(3, 1024, long).run();
    let udp = udp_echo(3, 1000, long).run();
    bystander_connect();
    let during = d.finish().expect("the detector was working");
    c.stop_session();

    let d = detector();
    let _ = system_ping(TEST_NET.into());
    let after = d.finish().expect("the detector was working");
    record(
        "block_all_ping",
        &format!(
            "{}\n{}\n{tcp:?}\n{udp:?}\nduring {during:#?}\nafter {after:#?}",
            String::from_utf8_lossy(&outside.stdout),
            String::from_utf8_lossy(&loopback.stdout),
        ),
    );

    // 会话期间：发不出去，别的都不受影响
    assert!(icmp_flows(&during).is_empty(), "{:?}", during.flows);
    assert!(
        loopback.status.success(),
        "loopback ping: {}",
        String::from_utf8_lossy(&loopback.stdout)
    );
    assert!(tcp.ok, "TCP echo: {}", tcp.output);
    assert!(udp.ok, "UDP echo: {}", udp.output);
    assert_no_leak(&during, &[tcp.pid, udp.pid]);
    assert_detector_saw_the_bystander(&during);
    assert_attribution_within_baseline(&service);
    // 会话结束：恢复
    assert!(
        !icmp_flows(&after).is_empty(),
        "ping is still blocked: {:?}",
        after.flows
    );
}

#[test]
fn a_killed_service_leaves_no_ping_filter_behind() {
    // C-NET-06：服务崩溃后 3 秒内撤销全部过滤器
    let node = Node::start(Reply::Echo);
    let (service, c) = start_session_with(&node, &echo_target_exe().to_string_lossy(), |p| {
        p.icmp.block_all_ping = true;
    });
    let d = detector();
    let _ = system_ping(TEST_NET.into());
    let during = d.finish().expect("the detector was working");
    assert!(icmp_flows(&during).is_empty(), "{:?}", during.flows);

    drop(c);
    drop(service);
    let d = detector();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let _ = system_ping(TEST_NET.into());
    }
    let after = d.finish().expect("the detector was working");
    assert!(
        !icmp_flows(&after).is_empty(),
        "ping is still blocked 3 seconds after the service died: {:?}",
        after.flows
    );
}

#[test]
fn blocking_all_ping_also_works_in_tun_mode() {
    // 过滤器与模式无关。顺带确认收窄令牌之后 TUN 网卡确实建得起来（地址取自 `config_gen::TUN_ADDRESSES`）
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session_with(&node, &echo_target_exe().to_string_lossy(), |p| {
        p.mode = Mode::Tun;
        p.fail_policy = FailPolicy::Allow;
        p.icmp.block_all_ping = true;
    });
    let adapters = Command::new(system32("ipconfig.exe"))
        .arg("/all")
        .output()
        .expect("run ipconfig");
    let adapters = String::from_utf8_lossy(&adapters.stdout).into_owned();
    let d = detector();
    let _ = system_ping(TEST_NET.into());
    let during = d.finish().expect("the detector was working");
    c.stop_session();
    let d = detector();
    let _ = system_ping(TEST_NET.into());
    let after = d.finish().expect("the detector was working");
    drop(service);
    record("block_all_ping_tun", &adapters);

    assert!(
        adapters.contains("198.18.0.1"),
        "no TUN adapter: {adapters}"
    );
    assert!(icmp_flows(&during).is_empty(), "{:?}", during.flows);
    assert!(
        !icmp_flows(&after).is_empty(),
        "ping is still blocked: {:?}",
        after.flows
    );
}

#[test]
fn a_folder_rule_covers_programs_that_start_later() {
    // 「添加进程」的文件夹页生成的就是这种规则。会话启动时文件夹里的程序都没有运行，路径规则也没有写它们的名字
    let folder = std::env::temp_dir().join("procroute-e2e-folder");
    let nested = folder.join("bin").join("x64");
    std::fs::create_dir_all(&nested).expect("create the folder");
    let inside = nested.join("some-game.exe");
    std::fs::copy(echo_target_exe(), &inside).expect("copy echo_target");

    let d = detector();
    let node = Node::start(Reply::Echo);
    let (service, mut c) = start_session_with(&node, &folder.to_string_lossy(), |p| {
        p.groups[0].matchers[0].kind = MatchType::Dir;
        p.groups[0].matchers[0].recursive = true;
    });

    let long = Duration::from_secs(5);
    let tcp = tcp_echo(3, 1024, long).run_exe(&inside);
    let udp = udp_echo(3, 1000, long).run_exe(&inside);
    // 文件夹外面的同一个程序不受影响：直连，不经过节点（连不上，因为没有人应答）
    let outside = tcp_echo(1, 16, Duration::from_millis(800)).run();
    bystander_connect();
    let report = d.finish().expect("the detector was working");
    c.stop_session();
    let targets = node.targets();
    record(
        "folder_rule",
        &format!("{tcp:?}\n{udp:?}\n{outside:?}\nnode: {targets:?}"),
    );

    assert_no_leak(&report, &[tcp.pid, udp.pid]);
    assert!(tcp.ok, "TCP echo: {}", tcp.output);
    assert!(udp.ok, "UDP echo: {}", udp.output);
    assert_eq!(
        targets
            .iter()
            .filter(|t| **t == format!("{TEST_NET}:{TCP_PORT}"))
            .count(),
        1,
        "only the program inside the folder reaches the node: {targets:?}"
    );
    assert!(
        report.leaked_packets(&[outside.pid]) >= 1,
        "the program outside the folder goes direct: {:?}",
        report.flows
    );
    assert_attribution_within_baseline(&service);
}
