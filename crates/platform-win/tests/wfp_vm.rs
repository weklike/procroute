// SPDX-License-Identifier: GPL-3.0-or-later
//! 动态 WFP 过滤器的测试：会改变本进程的网络行为，**只在测试虚拟机里、以管理员身份运行**（C-TEST-04）：
//!
//! ```text
//! cargo nextest run -p procroute-platform-win --features vm-tests
//! ```
//!
//! 默认构建不编译本文件。测试只保护测试进程自己，会话是动态的，进程退出即全部撤销。
#![cfg(all(windows, feature = "vm-tests"))]

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use procroute_platform_win::wfp::{FailClosedFilters, TunRanges};

const TUN: TunRanges = TunRanges {
    v4: (Ipv4Addr::new(198, 18, 0, 1), 30),
    v6: (Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1), 126),
};

/// 连向 TEST-NET-1 的一个地址：没有 TUN 时走物理网卡（或无路由）。
fn outside() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::new(192, 0, 2, 1), 80))
}

#[test]
fn protected_executables_are_blocked_outside_the_tun_but_keep_loopback() {
    let exe = std::env::current_exe().expect("current exe");
    let mut filters = FailClosedFilters::open(TUN).expect("open (needs an elevated prompt)");
    filters.protect(&exe).expect("protect this test binary");

    // 回环仍然可用
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
    TcpStream::connect(listener.local_addr().expect("addr")).expect("loopback is permitted");

    // 不经 TUN 的连接被 WFP 立刻拒绝（WSAEACCES），而不是等到超时
    let err = TcpStream::connect_timeout(&outside(), Duration::from_secs(3)).expect_err("blocked");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err:?}");

    // 关闭会话后过滤器随之消失
    drop(filters);
    let after = TcpStream::connect_timeout(&outside(), Duration::from_secs(1));
    assert!(
        !matches!(&after, Err(e) if e.kind() == ErrorKind::PermissionDenied),
        "filters must be gone: {after:?}"
    );
}
