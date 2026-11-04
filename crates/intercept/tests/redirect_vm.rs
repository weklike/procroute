// SPDX-License-Identifier: GPL-3.0-or-later
//! NETWORK 层改道方式的验证（T-075）：会加载驱动，**只在测试虚拟机里、以管理员身份运行**（C-TEST-04），
//! 通常经 `cargo xtask sandbox-test --only redirect_vm`。
//!
//! 本测试进程充当「目标应用」，连接一个文档用地址；改写线程把它的包送进测试自己监听的「中继」，
//! 验证三次握手、双向数据，以及中继看到的对端地址（据此查 NAT 表）。两种方式：
//!
//! - 回环：应用的出站包改成 `127.0.0.1:源端口 → 127.0.0.1:中继端口` 出站注入，中继只监听回环；
//!   中继的回包（回环包）改成「原始目标 → 应用」按原接口入站注入；
//! - 反射（WinDivert 的 streamdump 示例）：交换源与目的地址、目的端口改成中继端口后按入站注入，
//!   中继监听本机网卡地址。
#![cfg(all(windows, feature = "vm-tests"))]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procroute_intercept::divert::ffi::{
    Address, Handle, Layer, MTU_MAX, NetworkData, Shutdown, WinDivert,
};
use procroute_intercept::packet;

/// 文档用地址（TEST-NET-1）。包在离开本机前就被改道，不会真的发出去。
const TEST_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

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

/// 改写线程：收到的包交给 `rewrite`，返回 `true` 就重算校验和后注入，否则丢弃。丢弃即停止并关闭句柄。
struct Rewriter {
    handle: Arc<Handle>,
    thread: Option<JoinHandle<u64>>,
}

impl Rewriter {
    fn start(
        wd: &Arc<WinDivert>,
        filter: &str,
        mut rewrite: impl FnMut(&mut [u8], &mut Address) -> bool + Send + 'static,
    ) -> Self {
        let handle = Arc::new(
            wd.open(filter, Layer::Network, 0, 0)
                .expect("open the NETWORK layer"),
        );
        let thread = {
            let wd = Arc::clone(wd);
            let handle = Arc::clone(&handle);
            std::thread::spawn(move || {
                let mut buf = vec![0u8; MTU_MAX];
                let mut addr = Address::default();
                let mut injected = 0;
                while let Ok(n) = handle.recv(&mut buf, &mut addr) {
                    let pkt = &mut buf[..n];
                    if rewrite(pkt, &mut addr) {
                        assert!(wd.calc_checksums(pkt, &mut addr), "recompute checksums");
                        handle
                            .send(pkt, &addr)
                            .expect("inject the rewritten packet");
                        injected += 1;
                    }
                }
                injected
            })
        };
        Self {
            handle,
            thread: Some(thread),
        }
    }

    /// 停止并返回注入的包数。
    fn stop(mut self) -> u64 {
        self.shutdown()
    }

    fn shutdown(&mut self) -> u64 {
        let _ = self.handle.shutdown(Shutdown::Recv);
        self.thread
            .take()
            .map_or(0, |t| t.join().expect("rewriter thread"))
    }
}

impl Drop for Rewriter {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 应用一侧：连接 `remote`，发 ping、收 pong，返回本地地址。
fn ping(remote: SocketAddr) -> JoinHandle<SocketAddr> {
    std::thread::spawn(move || {
        let mut s = TcpStream::connect_timeout(&remote, Duration::from_secs(5))
            .expect("connect through the relay");
        s.set_read_timeout(Some(Duration::from_secs(5)))
            .expect("timeout");
        s.write_all(b"ping").expect("send ping");
        let mut b = [0u8; 4];
        s.read_exact(&mut b).expect("receive pong");
        assert_eq!(&b, b"pong");
        s.local_addr().expect("local address")
    })
}

/// 中继一侧：接受一条连接，收 ping、回 pong，返回对端地址。
fn serve_once(listener: &TcpListener) -> SocketAddr {
    listener.set_nonblocking(true).expect("nonblocking");
    let deadline = Instant::now() + Duration::from_secs(10);
    let (mut s, peer) = loop {
        match listener.accept() {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "the redirected connection never reached the relay"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            accepted => break accepted.expect("accept"),
        }
    };
    s.set_nonblocking(false).expect("blocking");
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    let mut b = [0u8; 4];
    s.read_exact(&mut b).expect("receive ping");
    assert_eq!(&b, b"ping");
    s.write_all(b"pong").expect("send pong");
    peer
}

#[test]
fn outbound_tcp_can_be_redirected_to_a_loopback_relay() {
    let wd = load();
    let relay = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the relay");
    let relay_port = relay.local_addr().expect("relay address").port();
    let remote = SocketAddr::from((TEST_NET, 9));
    // 应用发往原始目标的包；中继的回包（回环包只出现在出站方向）
    let filter = format!(
        "tcp and ((outbound and !loopback and ip.DstAddr == {TEST_NET} and tcp.DstPort == 9) \
         or (loopback and tcp.SrcPort == {relay_port}))"
    );
    // 映射端口（应用的源端口）→ 应用的本地地址与接口
    let mut conns: HashMap<u16, (IpAddr, NetworkData)> = HashMap::new();
    let rewriter = Rewriter::start(&wd, &filter, move |pkt, addr| {
        let Ok(mut p) = packet::parse(pkt) else {
            return false;
        };
        if addr.loopback() {
            // 中继 → 应用：伪装成原始目标发来的入站包
            let dst = p.dst();
            let Some(&(local, network)) = conns.get(&dst.port()) else {
                return false;
            };
            if p.set_src(remote).is_err() || p.set_dst(SocketAddr::new(local, dst.port())).is_err()
            {
                return false;
            }
            addr.set_outbound(false);
            addr.set_loopback(false);
            addr.set_network(network);
        } else {
            // 应用 → 原始目标：改成从回环发往中继，映射端口沿用应用的源端口
            let src = p.src();
            conns.insert(src.port(), (src.ip(), addr.network()));
            if p.set_src(SocketAddr::new(LOCALHOST, src.port())).is_err()
                || p.set_dst(SocketAddr::new(LOCALHOST, relay_port)).is_err()
            {
                return false;
            }
        }
        true
    });

    let client = ping(remote);
    let peer = serve_once(&relay);
    let local = client.join().expect("client thread");
    assert_eq!(
        peer,
        SocketAddr::new(LOCALHOST, local.port()),
        "the relay sees the app's source port as the mapped port"
    );
    assert!(!local.ip().is_loopback(), "{local}");
    let injected = rewriter.stop();
    assert!(injected >= 6, "handshake and data both ways: {injected}");
}

#[test]
fn outbound_tcp_can_be_reflected_to_a_relay_on_the_local_interface() {
    let wd = load();
    let relay = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind the relay");
    let relay_port = relay.local_addr().expect("relay address").port();
    let remote = SocketAddr::from((TEST_NET, 10));
    // 中继发给「原始目标」的回包不是回环包，同样在出站方向
    let filter = format!(
        "tcp and outbound and !loopback and \
         ((ip.DstAddr == {TEST_NET} and tcp.DstPort == 10) or tcp.SrcPort == {relay_port})"
    );
    let rewriter = Rewriter::start(&wd, &filter, move |pkt, addr| {
        let Ok(mut p) = packet::parse(pkt) else {
            return false;
        };
        let (src, dst) = (p.src(), p.dst());
        let (new_src, new_dst) = if dst == remote {
            // 应用 → 原始目标：反射成「原始目标:源端口 → 本机:中继端口」
            (
                SocketAddr::new(dst.ip(), src.port()),
                SocketAddr::new(src.ip(), relay_port),
            )
        } else {
            // 中继 → 应用：反射成「原始目标 → 应用」
            (remote, SocketAddr::new(src.ip(), dst.port()))
        };
        if p.set_src(new_src).is_err() || p.set_dst(new_dst).is_err() {
            return false;
        }
        addr.set_outbound(false);
        true
    });

    let client = ping(remote);
    let peer = serve_once(&relay);
    let local = client.join().expect("client thread");
    assert_eq!(
        peer,
        SocketAddr::new(IpAddr::V4(TEST_NET), local.port()),
        "the relay sees the original target and the app's source port"
    );
    let injected = rewriter.stop();
    assert!(injected >= 6, "handshake and data both ways: {injected}");
}
