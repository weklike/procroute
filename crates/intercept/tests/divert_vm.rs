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

use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use procroute_intercept::divert::ffi::{Address, Layer, Param, Shutdown, WinDivert, event, flags};

fn load() -> Arc<WinDivert> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../third_party/windivert/bin")
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
