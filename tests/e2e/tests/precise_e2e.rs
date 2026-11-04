// SPDX-License-Identifier: GPL-3.0-or-later
//! 精确进程模式的端到端测试（T-078）：真实的服务、sing-box 与 WinDivert，**只在测试虚拟机里、以管理员
//! 身份运行**（C-TEST-04），经 `cargo xtask sandbox-test --only precise_e2e`。
//!
//! 测试经控制管道导入指向测试节点的 `socks5://` 节点、保存按 `curl.exe` 命中的精确模式方案、启动会话，然后：
//!
//! - `curl` 访问一个文档用地址，必须经 拦截 → 回环中继 → sing-box → 节点 拿到桩的响应；
//! - 本测试进程（非目标）访问同一地址不经过节点；
//! - 停止会话后 `curl` 不再经过节点；
//! - UDP（T-091）：`powershell.exe` 发往文档用地址的数据报经 UDP 中继 → sing-box → 节点的 UDP ASSOCIATE，
//!   节点的回包注入回应用；
//! - 子进程（F7）：方案只命中一个启动器（cmd.exe 的副本），它拉起后立即连接的 `curl` 同样经过节点。
#![cfg(all(windows, feature = "vm-tests"))]

use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::time::Duration;

use procroute_e2e::harness::{Node, Reply, TEST_NET, launcher_exe, start_session};

const TARGET_PORT: u16 = 8080;
const UDP_PORT: u16 = 5353;

fn curl_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\curl.exe")
}

/// 用 curl 访问文档用地址，返回响应体（失败时为空）。
fn curl() -> String {
    let out = Command::new(curl_exe())
        .args([
            "-s",
            "-m",
            "10",
            &format!("http://{TEST_NET}:{TARGET_PORT}/hello"),
        ])
        .output()
        .expect("run curl.exe");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn powershell_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// 用 PowerShell 发一个 UDP 数据报到文档用地址并等回包，返回回包内容（超时为空）。
fn powershell_udp() -> String {
    let script = format!(
        "$u = New-Object System.Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 10000; \
         $b = [Text.Encoding]::ASCII.GetBytes('ping'); [void]$u.Send($b, $b.Length, '{TEST_NET}', {UDP_PORT}); \
         $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0); \
         try {{ $r = $u.Receive([ref]$ep); [Text.Encoding]::ASCII.GetString($r) + ' from ' + $ep }} catch {{ 'timeout' }}"
    );
    let out = Command::new(powershell_exe())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("run powershell.exe");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn a_target_process_reaches_the_node_through_the_whole_path() {
    let node = Node::start(Reply::Describe);
    let (_service, mut c) = start_session(&node, &curl_exe());

    // 目标进程：经整条链路到达节点
    let target = format!("{TEST_NET}:{TARGET_PORT}");
    let body = curl();
    assert_eq!(
        body,
        format!("procroute-e2e {target}"),
        "curl through the session"
    );
    assert_eq!(node.targets(), vec![target.clone()]);

    // 非目标进程（本测试进程）：不经过节点
    let _ = TcpStream::connect_timeout(
        &SocketAddr::from((TEST_NET, TARGET_PORT)),
        Duration::from_secs(2),
    );
    assert_eq!(node.targets().len(), 1, "{:?}", node.targets());

    // 停止会话：撤下拦截，curl 不再经过节点
    c.stop_session();
    let after = curl();
    assert!(!after.starts_with("procroute-e2e"), "{after}");
    assert_eq!(node.targets().len(), 1, "{:?}", node.targets());
}

#[test]
fn target_udp_reaches_the_node_and_the_reply_comes_back() {
    let node = Node::start(Reply::Describe);
    let (_service, mut c) = start_session(&node, &powershell_exe());

    // 目标进程的 UDP：拦截 → UDP 中继 → sing-box → 节点的 UDP ASSOCIATE，回包注入回应用
    let target = format!("{TEST_NET}:{UDP_PORT}");
    let reply = powershell_udp();
    assert!(
        reply.starts_with(&format!("pong udp {target} from {target}")),
        "reply seen by the app: {reply:?}; node saw {:?}",
        node.targets()
    );
    assert!(node.targets().contains(&format!("udp {target}")));

    c.stop_session();
    // 停止之后不再经过节点
    let before = node.targets().len();
    let after = powershell_udp();
    assert!(!after.starts_with("pong"), "{after}");
    assert_eq!(
        node.targets()
            .iter()
            .filter(|t| t.starts_with("udp "))
            .count(),
        node.targets()[..before]
            .iter()
            .filter(|t| t.starts_with("udp "))
            .count()
    );
}

#[test]
fn a_child_connecting_right_after_start_inherits_the_target() {
    // F7：方案只命中启动器；它拉起的 curl 一启动就连接，进程追踪（ETW）还没报到，靠当场的继承判定
    let node = Node::start(Reply::Describe);
    let launcher = launcher_exe();
    let (_service, mut c) = start_session(&node, &launcher.to_string_lossy());
    let url = format!("http://{TEST_NET}:{TARGET_PORT}/child");
    let out = Command::new(&launcher)
        .args(["/c", &curl_exe(), "-s", "-m", "10", &url])
        .output()
        .expect("run the launcher");
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        body,
        format!("procroute-e2e {TEST_NET}:{TARGET_PORT}"),
        "the child went through the node"
    );
    // 测试进程直接运行的 curl 不是启动器的后代：不经过节点
    let direct = curl();
    assert!(!direct.starts_with("procroute-e2e"), "{direct}");
    assert_eq!(node.targets().len(), 1, "{:?}", node.targets());
    c.stop_session();
}
