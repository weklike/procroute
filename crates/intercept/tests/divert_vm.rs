// SPDX-License-Identifier: GPL-3.0-or-later
//! WinDivert 句柄的测试：会安装并加载驱动，**只在测试虚拟机里、以管理员身份运行**（C-TEST-04）：
//!
//! ```text
//! cargo xtask fetch-deps
//! cargo nextest run -p procroute-intercept --features vm-tests
//! ```
//!
//! 默认构建不编译本文件（不是跳过：开发机与 CI 宿主上禁止加载驱动）。
#![cfg(all(windows, feature = "vm-tests"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use procroute_intercept::divert::ffi::{Address, Layer, Param, Shutdown, WinDivert, event, flags};
use procroute_intercept::divert::socket::{
    Attributor, FlowAction, FlowTable, ProcessResolver, SocketMonitor, SystemProcesses,
};
use procroute_intercept::{Counters, ExclusionSet, FlowPolicy, InterceptSettings, ProcessKey};
use procroute_proto::event::Network;

/// 文档用地址（TEST-NET-1，RFC 5737），不是回环，CONNECT 事件不会被过滤器滤掉。通常没有人应答
/// （connect 挂到超时），但宿主网络上的透明代理会立即接受连接，测试对两种情况都成立。
const TEST_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// 设置后，[`child_connect_helper`] 连接这个地址（子进程入口）。
const CHILD_ENV: &str = "PROCROUTE_VM_CHILD_CONNECT";

/// `PROCROUTE_WINDIVERT_DIR`（`cargo xtask sandbox-test` 在沙盒里设置），否则用仓库里的 `bin/`。
fn load() -> Arc<WinDivert> {
    let dir = std::env::var_os("PROCROUTE_WINDIVERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert/bin")
        })
        .canonicalize()
        .expect("run `cargo xtask fetch-deps` first");
    WinDivert::load(&dir).expect("load the locked WinDivert")
}

#[test]
fn handles_open_report_the_locked_version_and_close() {
    let wd = load();
    // 「false」不匹配任何包：只验证驱动加载与句柄生命周期，不影响虚拟机的网络
    let h = wd
        .open("false", Layer::Network, 0, flags::SNIFF | flags::RECV_ONLY)
        .expect("open (needs an elevated prompt in the VM)");
    assert_eq!(h.param(Param::VersionMajor).expect("major"), 2);
    assert_eq!(h.param(Param::VersionMinor).expect("minor"), 2);
    h.shutdown(Shutdown::Both).expect("shutdown");
    drop(h);
    // 关闭后可以再次打开
    let again = wd
        .open("false", Layer::Network, 0, flags::SNIFF | flags::RECV_ONLY)
        .expect("reopen");
    drop(again);
}

#[test]
fn socket_layer_reports_this_process_connects() {
    let wd = load();
    let pid = std::process::id();
    let filter = format!("processId == {pid} and event == CONNECT and tcp");
    let h = wd
        .open(&filter, Layer::Socket, 0, flags::SNIFF | flags::RECV_ONLY)
        .expect("open socket layer");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let _client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).expect("connect");

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut addr = Address::default();
    loop {
        assert!(Instant::now() < deadline, "no SOCKET_CONNECT event seen");
        h.recv_event(&mut addr).expect("recv");
        let e = addr.endpoint();
        if addr.event() == event::SOCKET_CONNECT && e.remote_port == port {
            assert_eq!(e.process_id, pid);
            assert_eq!(e.remote_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
            assert_eq!(e.protocol, 6);
            assert!(addr.outbound());
            break;
        }
    }
}

/// 只把 `target` 当作目标进程（进程组 3），并记下每次被问到的进程。
struct Recorder {
    target: ProcessKey,
    asked: Mutex<Vec<ProcessKey>>,
}

impl FlowPolicy for Recorder {
    fn target_group(&self, p: &ProcessKey) -> Option<u16> {
        self.asked.lock().expect("recorder lock").push(*p);
        (*p == self.target).then_some(3)
    }
}

/// 子进程入口：设置了 [`CHILD_ENV`] 时连接那个地址；作为普通测试运行时什么也不做。
#[test]
fn child_connect_helper() {
    if let Ok(addr) = std::env::var(CHILD_ENV) {
        let addr: SocketAddr = addr.parse().expect("child address");
        let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(3));
    }
}

fn wait_until(what: &str, timeout: Duration, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn socket_monitor_redirects_only_target_connects() {
    let wd = load();
    let me = SystemProcesses
        .resolve(std::process::id())
        .expect("resolve this process");
    let policy = Arc::new(Recorder {
        target: me,
        asked: Mutex::new(Vec::new()),
    });
    let table = Arc::new(FlowTable::default());
    let counters = Arc::new(Counters::default());
    let attributor = Arc::new(Attributor::new(
        InterceptSettings::default(),
        ExclusionSet::default(),
        policy.clone(),
        Arc::new(SystemProcesses),
        table.clone(),
        counters.clone(),
    ));
    let monitor = SocketMonitor::start(&wd, attributor).expect("start the SOCKET layer monitor");

    // 目标进程（本测试进程）：connect 时登记。连上了就一直开着，等主线程放行再关闭
    let target_remote = SocketAddr::from((TEST_NET, 9));
    let connected = Arc::new(AtomicBool::new(false));
    let (release, released) = mpsc::channel::<()>();
    let pending = std::thread::spawn({
        let connected = connected.clone();
        move || {
            if let Ok(stream) = TcpStream::connect_timeout(&target_remote, Duration::from_secs(3)) {
                connected.store(true, Ordering::SeqCst);
                let _ = released.recv();
                drop(stream);
            }
        }
    });
    let find = |remote: SocketAddr| table.entries().into_iter().find(|f| f.key.remote == remote);
    wait_until(
        "the target connect to be registered",
        Duration::from_secs(5),
        || find(target_remote).is_some(),
    );
    let flow = find(target_remote).expect("registered");
    assert_eq!(flow.process, Some(me));
    assert_eq!(flow.pid, me.pid);
    assert_eq!(flow.action, FlowAction::Redirect { group: 3 });
    assert_eq!(flow.key.network, Network::Tcp);
    assert_ne!(flow.key.local.port(), 0, "{flow:?}");
    assert!(!flow.key.local.ip().is_loopback(), "{flow:?}");

    // 非目标进程（子进程）：事件被看到、被判定，只登记为放行（C-NET-02）
    let other_remote = SocketAddr::from((TEST_NET, 10));
    let mut child = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "child_connect_helper", "--test-threads=1"])
        .env(CHILD_ENV, other_remote.to_string())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn the child");
    let child_pid = child.id();
    wait_until(
        "the child's connect to be attributed",
        Duration::from_secs(5),
        || {
            policy
                .asked
                .lock()
                .unwrap()
                .iter()
                .any(|p| p.pid == child_pid)
        },
    );
    // 子进程的 CONNECT 可能已经随它的 CLOSE 被撤销；在的话只能是放行
    assert!(
        table
            .entries()
            .iter()
            .filter(|f| f.pid == child_pid || f.key.remote == other_remote)
            .all(|f| f.action == FlowAction::Bypass),
        "{:?}",
        table.entries()
    );
    assert!(child.wait().expect("wait for the child").success());

    // 连上的套接字开着期间登记一直在（子进程的事件不会误删它）
    if connected.load(Ordering::SeqCst) {
        assert!(find(target_remote).is_some(), "{:?}", table.entries());
    }
    // 套接字关闭（连上的在这里放行后关闭，连不上的超时后关闭）后，CLOSE 事件撤销登记
    drop(release);
    pending.join().expect("connect thread");
    wait_until(
        "the closed socket to be forgotten",
        Duration::from_secs(5),
        || find(target_remote).is_none(),
    );

    assert!(
        counters.snapshot().redirected >= 1,
        "{:?}",
        counters.snapshot()
    );
    assert!(monitor.is_running(), "{:?}", monitor.failure());
    monitor.stop();
}
