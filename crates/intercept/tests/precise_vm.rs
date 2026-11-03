// SPDX-License-Identifier: GPL-3.0-or-later
//! WinDivert 后端的端到端测试（T-075、T-076）：会加载驱动，**只在测试虚拟机里、以管理员身份运行**
//! （C-TEST-04），通常经 `cargo xtask sandbox-test --only precise_vm`。
//!
//! 本测试进程是目标进程，连接一个文档用地址；后端应当把连接改道到测试自己监听的「中继」，中继按
//! 对端端口查到测试实现的 NAT 映射，回 pong。子进程（非目标）的连接不应到达中继。
#![cfg(all(windows, feature = "vm-tests"))]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procroute_intercept::divert::network::{RedirectMap, Relays};
use procroute_intercept::divert::socket::{ProcessResolver, SystemProcesses};
use procroute_intercept::divert::{DivertConfig, DivertInterceptor};
use procroute_intercept::{
    ExclusionSet, FlowEvent, FlowPolicy, InterceptSettings, Interceptor, ProcessKey, StartContext,
};
use procroute_proto::event::Network;

/// 文档用地址（TEST-NET-1）。目标进程的包在离开本机前就被改道。
const TEST_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const GROUP: u16 = 5;
/// 设置后，[`child_connect_helper`] 连接这个地址（子进程入口）。
const CHILD_ENV: &str = "PROCROUTE_VM_PRECISE_CHILD";

fn windivert_dir() -> PathBuf {
    std::env::var_os("PROCROUTE_WINDIVERT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert/bin")
        })
        .canonicalize()
        .expect("run `cargo xtask fetch-deps` first")
}

/// 测试里的 NAT 表：映射端口 → 原始目标、进程、进程组。
#[derive(Default)]
struct Nat {
    entries: Mutex<HashMap<u16, (SocketAddr, ProcessKey, u16)>>,
    unmapped: Mutex<Vec<u16>>,
}

impl RedirectMap for Nat {
    fn map(
        &self,
        network: Network,
        port: u16,
        original: SocketAddr,
        p: ProcessKey,
        g: u16,
    ) -> bool {
        assert_eq!(network, Network::Tcp);
        self.entries
            .lock()
            .expect("nat")
            .insert(port, (original, p, g));
        true
    }

    fn unmap(&self, _: Network, port: u16) {
        self.unmapped.lock().expect("nat").push(port);
    }
}

struct Only(ProcessKey);

impl FlowPolicy for Only {
    fn target_group(&self, p: &ProcessKey) -> Option<u16> {
        (*p == self.0).then_some(GROUP)
    }
}

/// 「中继」：接受改道来的连接，按对端端口查 NAT，读 ping、回 `pong <原始目标端口>`。
fn relay(
    listener: TcpListener,
    nat: Arc<Nat>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<Vec<SocketAddr>> {
    std::thread::spawn(move || {
        listener.set_nonblocking(true).expect("nonblocking");
        let mut seen = Vec::new();
        while !stop.load(Ordering::SeqCst) {
            let (mut s, peer) = match listener.accept() {
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                accepted => accepted.expect("accept"),
            };
            seen.push(peer);
            let original = nat
                .entries
                .lock()
                .expect("nat")
                .get(&peer.port())
                .map(|e| e.0);
            let Some(original) = original else {
                continue;
            };
            s.set_nonblocking(false).expect("blocking");
            s.set_read_timeout(Some(Duration::from_secs(5)))
                .expect("timeout");
            let mut b = [0u8; 4];
            if s.read_exact(&mut b).is_ok() && &b == b"ping" {
                let _ = s.write_all(format!("pong {}", original.port()).as_bytes());
            }
        }
        seen
    })
}

/// 子进程入口：设置了 [`CHILD_ENV`] 时连接那个地址；作为普通测试运行时什么也不做。
#[test]
fn child_connect_helper() {
    if let Ok(addr) = std::env::var(CHILD_ENV) {
        let addr: SocketAddr = addr.parse().expect("child address");
        let _ = TcpStream::connect_timeout(&addr, Duration::from_secs(2));
    }
}

#[test]
fn target_tcp_reaches_the_relay_and_non_target_tcp_does_not() {
    let me = SystemProcesses
        .resolve(std::process::id())
        .expect("resolve this process");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the relay");
    let relays = Relays {
        v4: listener.local_addr().expect("relay address"),
        v6: None,
    };
    let nat = Arc::new(Nat::default());
    let stop = Arc::new(AtomicBool::new(false));
    let relay_thread = relay(listener, nat.clone(), stop.clone());

    let mut backend = DivertInterceptor::new(DivertConfig {
        dir: windivert_dir(),
        relays,
        map: nat.clone(),
        udp: None,
        resolver: Arc::new(SystemProcesses),
        receivers: 2,
    });
    let (events_tx, events) = sync_channel(1024);
    backend
        .start(StartContext {
            settings: InterceptSettings::default(),
            exclusions: ExclusionSet::default(),
            policy: Arc::new(Only(me)),
            events: events_tx,
        })
        .expect("start the WinDivert backend (elevated, in the VM)");

    // 目标进程：经中继往返
    let remote = SocketAddr::from((TEST_NET, 9));
    let started = Instant::now();
    let mut s = TcpStream::connect_timeout(&remote, Duration::from_secs(5))
        .expect("connect through the relay");
    let connect_time = started.elapsed();
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    s.write_all(b"ping").expect("send ping");
    let mut reply = String::new();
    let mut buf = [0u8; 16];
    let n = s.read(&mut buf).expect("receive pong");
    reply.push_str(std::str::from_utf8(&buf[..n]).expect("utf-8"));
    assert_eq!(reply, "pong 9", "the relay saw the original target port");
    let local = s.local_addr().expect("local address");
    let entry = nat.entries.lock().expect("nat").get(&local.port()).copied();
    assert_eq!(
        entry,
        Some((remote, me, GROUP)),
        "NAT entry for the app's port"
    );
    let redirected = events.try_iter().any(|e| {
        matches!(e, FlowEvent::Redirected { key, process, group }
            if key.local.port() == local.port() && key.remote == remote && process == me && group == GROUP)
    });
    assert!(redirected, "a Redirected event for the flow");
    assert_eq!(backend.active_connections(), 1);
    assert!(backend.failure().is_none(), "{:?}", backend.failure());

    // 非目标进程（子进程）：不经过中继
    let other = SocketAddr::from((TEST_NET, 10));
    let status = Command::new(std::env::current_exe().expect("test executable"))
        .args(["--exact", "child_connect_helper", "--test-threads=1"])
        .env(CHILD_ENV, other.to_string())
        .stdout(Stdio::null())
        .status()
        .expect("run the child");
    assert!(status.success());
    assert!(
        nat.entries
            .lock()
            .expect("nat")
            .values()
            .all(|e| e.0 != other),
        "the child's connection must not be mapped"
    );

    // 停止：撤销过滤器，回收连接（撤销 NAT 表项、发出 Closed）
    drop(s);
    backend.stop().expect("stop");
    assert!(!backend.is_active());
    assert!(nat.unmapped.lock().expect("nat").contains(&local.port()));
    assert!(
        events
            .try_iter()
            .any(|e| matches!(e, FlowEvent::Closed { key } if key.local.port() == local.port()))
    );
    let stats = backend.stats();
    assert!(stats.redirected >= 1, "{stats:?}");

    stop.store(true, Ordering::SeqCst);
    let seen = relay_thread.join().expect("relay thread");
    assert!(
        seen.iter().all(|p| p.port() == local.port()),
        "only the target connection reached the relay: {seen:?}"
    );
    println!("connect through the relay took {connect_time:?}");
}
