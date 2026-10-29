// SPDX-License-Identifier: GPL-3.0-or-later
//! 本地 TCP 中继（T-074，设计文档 6.1 第 4 步）。
//!
//! 拦截层把目标进程的连接改道到本中继的监听地址。中继用对端端口（映射端口）查 NAT 表
//! 取回原始目标，向 sing-box 的本地 SOCKS5 入口发起 CONNECT，用户名填进程组标签，
//! 然后双向转发。
//!
//! fail-closed（C-NET-03）：查不到映射、组标签无效、SOCKS 入口不可达、认证或 CONNECT
//! 失败，一律对应用侧连接回 RST。本模块没有直连原始目标的代码路径。
//!
//! 域名嗅探（T-092，设计文档 6.3）：在 [`SniffConfig`] 列出的端口上，先读客户端的首包，取出
//! TLS SNI / HTTP Host 后按域名发 CONNECT，让远端重新解析，绕开本地被污染的 DNS 结果；读到的
//! 字节在 CONNECT 成功后原样补发给上游。取不到域名或等待超时就按原始 IP 连接。客户端先发数据的
//! 协议（TLS、HTTP）首包几乎立刻就到，不增加可感知的延迟；服务端先发数据的协议最多多等一个超时，
//! 所以只在 Web 端口上嗅探。按 SNI 连接意味着以应用自己声明的域名为准（与 sing-box 旧版的
//! `sniff_override_destination` 行为一致）。
//!
//! NAT 表项不在这里移除：连接结束后拦截层仍要用它改写最后的 FIN/ACK，由拦截层的
//! `Closed` 事件或空闲超时回收。

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use procroute_proto::event::Network;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

use crate::nat::{NatEntry, NatTable};
use crate::sniff::{self, MAX_SNIFF_BYTES, Sniffed};
use crate::socks5::{self, Password, TargetAddr};

/// 服务、拦截层与中继共享的 NAT 表。锁只在查表时短暂持有，从不跨 `.await`。
pub type SharedNat = Arc<Mutex<NatTable>>;

/// 连接 sing-box 入口（含认证与 CONNECT）的默认超时。
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// 嗅探设置：在这些目标端口上先读客户端首包取域名。
#[derive(Debug, Clone)]
pub struct SniffConfig {
    pub ports: Arc<[u16]>,
    /// 等首包的最长时间；超时按原始 IP 连接。
    pub timeout: Duration,
}

impl SniffConfig {
    /// HTTP 与 HTTPS 端口，等待 300 ms（与 sing-box 嗅探的默认超时相同）。
    pub fn web() -> Self {
        Self {
            ports: Arc::from([80u16, 443]),
            timeout: Duration::from_millis(300),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpRelayConfig {
    /// 中继监听地址，必须是回环地址。
    pub listen: SocketAddr,
    /// sing-box 本地 SOCKS5 入口（只绑定回环，C-NET-08）。
    pub socks: SocketAddr,
    /// 本次启动随机生成的入口密码。
    pub password: Password,
    /// 进程组下标 → 组标签（即 SOCKS 用户名）。
    pub group_tags: Arc<[String]>,
    pub connect_timeout: Duration,
    /// 为空时不嗅探，一律按原始 IP 连接。
    pub sniff: Option<SniffConfig>,
}

/// 中继计数器。
#[derive(Debug, Default)]
pub struct TcpRelayStats {
    accepted: AtomicU64,
    forwarded: AtomicU64,
    /// 查不到映射或组标签无效而回 RST 的连接数。
    reset_no_route: AtomicU64,
    /// 上游（sing-box）不可用而回 RST 的连接数。
    reset_upstream: AtomicU64,
    /// 按嗅探到的域名转发的连接数。
    sniffed: AtomicU64,
}

/// 计数器快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpRelayCounts {
    pub accepted: u64,
    pub forwarded: u64,
    pub reset_no_route: u64,
    pub reset_upstream: u64,
    pub sniffed: u64,
}

impl TcpRelayStats {
    pub fn snapshot(&self) -> TcpRelayCounts {
        TcpRelayCounts {
            accepted: self.accepted.load(Ordering::Relaxed),
            forwarded: self.forwarded.load(Ordering::Relaxed),
            reset_no_route: self.reset_no_route.load(Ordering::Relaxed),
            reset_upstream: self.reset_upstream.load(Ordering::Relaxed),
            sniffed: self.sniffed.load(Ordering::Relaxed),
        }
    }
}

struct Ctx {
    config: TcpRelayConfig,
    nat: SharedNat,
    stats: Arc<TcpRelayStats>,
}

pub struct TcpRelay {
    listener: TcpListener,
    ctx: Arc<Ctx>,
}

impl TcpRelay {
    /// 绑定监听地址。非回环地址直接拒绝，避免把中继暴露给局域网。
    pub async fn bind(config: TcpRelayConfig, nat: SharedNat) -> io::Result<Self> {
        if !config.listen.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "relay must listen on a loopback address",
            ));
        }
        let listener = TcpListener::bind(config.listen).await?;
        Ok(Self {
            listener,
            ctx: Arc::new(Ctx {
                config,
                nat,
                stats: Arc::default(),
            }),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub fn stats(&self) -> Arc<TcpRelayStats> {
        Arc::clone(&self.ctx.stats)
    }

    /// 接受连接直到 `shutdown` 完成；返回时中止所有仍在转发的连接。
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => break,
                accepted = self.listener.accept() => {
                    let (stream, peer) = accepted?;
                    self.ctx.stats.accepted.fetch_add(1, Ordering::Relaxed);
                    tasks.spawn(handle(Arc::clone(&self.ctx), stream, peer));
                }
                // 回收已结束的任务，避免 JoinSet 无限增长
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            }
        }
        tasks.shutdown().await;
        Ok(())
    }
}

async fn handle(ctx: Arc<Ctx>, mut client: TcpStream, peer: SocketAddr) {
    let Some((entry, tag)) = route(&ctx, peer) else {
        ctx.stats.reset_no_route.fetch_add(1, Ordering::Relaxed);
        reset(client);
        return;
    };
    let (target, early) = match &ctx.config.sniff {
        Some(s) if s.ports.contains(&entry.original.port()) => {
            match sniff_target(&mut client, entry.original, s.timeout).await {
                Some(found) => found,
                // 客户端在发出任何数据前就断开了
                None => return,
            }
        }
        _ => (TargetAddr::Ip(entry.original), Vec::new()),
    };
    if matches!(target, TargetAddr::Domain(..)) {
        ctx.stats.sniffed.fetch_add(1, Ordering::Relaxed);
    }
    let upstream = tokio::time::timeout(
        ctx.config.connect_timeout,
        open_upstream(&ctx.config, tag, &target),
    )
    .await;
    let Ok(Ok(mut upstream)) = upstream else {
        ctx.stats.reset_upstream.fetch_add(1, Ordering::Relaxed);
        reset(client);
        return;
    };
    ctx.stats.forwarded.fetch_add(1, Ordering::Relaxed);
    if !early.is_empty() && upstream.write_all(&early).await.is_err() {
        reset(client);
        return;
    }
    // 任一方向出错都只是结束这条连接
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
}

/// 读客户端首包取域名；返回 CONNECT 的目标与已经读到的字节。客户端什么都没发就断开时返回 `None`。
async fn sniff_target(
    client: &mut TcpStream,
    original: SocketAddr,
    timeout: Duration,
) -> Option<(TargetAddr, Vec<u8>)> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut buf = Vec::with_capacity(2048);
    loop {
        match tokio::time::timeout_at(deadline, client.read_buf(&mut buf)).await {
            // 超时：多半是服务端先发数据的协议
            Err(_) => break,
            Ok(Ok(0)) if buf.is_empty() => return None,
            // 客户端已半关闭：把收到的照常转发
            Ok(Ok(0)) => break,
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return None,
        }
        match sniff::sniff_host(&buf) {
            Sniffed::Host(host) => return Some((TargetAddr::Domain(host, original.port()), buf)),
            Sniffed::NeedMore if buf.len() < MAX_SNIFF_BYTES => {}
            Sniffed::NeedMore | Sniffed::Unknown => break,
        }
    }
    Some((TargetAddr::Ip(original), buf))
}

fn route(ctx: &Ctx, peer: SocketAddr) -> Option<(NatEntry, &str)> {
    let entry = ctx
        .nat
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .lookup(Network::Tcp, peer.port(), Instant::now())?;
    let tag = ctx.config.group_tags.get(usize::from(entry.group))?;
    Some((entry, tag.as_str()))
}

async fn open_upstream(
    config: &TcpRelayConfig,
    username: &str,
    target: &TargetAddr,
) -> Result<TcpStream, socks5::Socks5Error> {
    let mut stream = TcpStream::connect(config.socks).await?;
    stream.set_nodelay(true)?;
    socks5::handshake(&mut stream, username, &config.password).await?;
    socks5::connect(&mut stream, target).await?;
    Ok(stream)
}

/// 以 RST 关闭应用侧连接，让应用立刻感知失败而不是等超时。
fn reset(stream: TcpStream) {
    // 设置失败时退化为普通关闭，同样不会直连
    let _ = stream.set_zero_linger();
    drop(stream);
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use procroute_proto::profile::FailPolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpSocket;
    use tokio::sync::oneshot;

    use super::*;
    use crate::nat::NatConfig;
    use crate::testutil::{FakeSocks, PASSWORD, spawn_tcp_echo};

    struct Harness {
        relay_addr: SocketAddr,
        nat: SharedNat,
        stats: Arc<TcpRelayStats>,
        stop: Option<oneshot::Sender<()>>,
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
        }
    }

    async fn start_relay(socks: SocketAddr, password: &str) -> Harness {
        start_relay_with(socks, password, None).await
    }

    async fn start_relay_with(
        socks: SocketAddr,
        password: &str,
        sniff: Option<SniffConfig>,
    ) -> Harness {
        let nat: SharedNat = Arc::new(Mutex::new(NatTable::new(NatConfig {
            fail_policy: FailPolicy::Block,
            ..NatConfig::default()
        })));
        let relay = TcpRelay::bind(
            TcpRelayConfig {
                listen: "127.0.0.1:0".parse().unwrap(),
                socks,
                password: Password::new(password.to_owned()),
                group_tags: Arc::from(vec!["game".to_owned(), "browser".to_owned()]),
                connect_timeout: Duration::from_secs(2),
                sniff,
            },
            Arc::clone(&nat),
        )
        .await
        .unwrap();
        let relay_addr = relay.local_addr().unwrap();
        let stats = relay.stats();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(relay.serve(async {
            let _ = rx.await;
        }));
        Harness {
            relay_addr,
            nat,
            stats,
            stop: Some(tx),
        }
    }

    /// 先拿到本地端口登记 NAT，再连接中继，模拟拦截层的改道。
    async fn redirected_client(h: &Harness, original: SocketAddr, group: u16) -> TcpStream {
        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let port = socket.local_addr().unwrap().port();
        h.nat
            .lock()
            .unwrap()
            .insert(
                Network::Tcp,
                port,
                NatEntry {
                    original,
                    pid: 4120,
                    process_created_at: 10,
                    group,
                },
                Instant::now(),
            )
            .unwrap();
        socket.connect(h.relay_addr).await.unwrap()
    }

    async fn expect_reset(mut client: TcpStream) {
        let mut buf = [0u8; 16];
        let _ = client.write_all(b"hello").await;
        match client.read(&mut buf).await {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::ConnectionReset),
            Ok(n) => assert_eq!(n, 0, "relay must not forward anything"),
        }
    }

    #[tokio::test]
    async fn forwards_through_socks_with_group_tag_as_username() {
        let (echo, _echo_hits) = spawn_tcp_echo().await;
        let socks = FakeSocks::spawn().await;
        let h = start_relay(socks.addr, PASSWORD).await;

        let mut client = redirected_client(&h, echo, 1).await;
        client.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        assert_eq!(socks.usernames(), vec!["browser".to_owned()]);
        assert_eq!(socks.connect_targets(), vec![echo]);
        assert_eq!(h.stats.snapshot().forwarded, 1);
    }

    #[tokio::test]
    async fn socks_unreachable_resets_and_never_connects_directly() {
        // C-NET-03：sing-box 不可达时 fail-closed
        let (original, direct_hits) = spawn_tcp_echo().await;
        let dead = {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let h = start_relay(dead, PASSWORD).await;
        let client = redirected_client(&h, original, 0).await;
        expect_reset(client).await;
        assert_eq!(
            direct_hits.load(Ordering::SeqCst),
            0,
            "leaked to original target"
        );
        assert_eq!(h.stats.snapshot().reset_upstream, 1);
    }

    #[tokio::test]
    async fn wrong_password_resets() {
        let (original, direct_hits) = spawn_tcp_echo().await;
        let socks = FakeSocks::spawn().await;
        let h = start_relay(socks.addr, "not-the-password").await;
        let client = redirected_client(&h, original, 0).await;
        expect_reset(client).await;
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(h.stats.snapshot().reset_upstream, 1);
    }

    #[tokio::test]
    async fn connection_without_nat_entry_is_reset() {
        let socks = FakeSocks::spawn().await;
        let h = start_relay(socks.addr, PASSWORD).await;
        let client = TcpStream::connect(h.relay_addr).await.unwrap();
        expect_reset(client).await;
        assert_eq!(h.stats.snapshot().reset_no_route, 1);
        assert!(socks.usernames().is_empty());
    }

    #[tokio::test]
    async fn unknown_group_index_is_reset() {
        let (original, direct_hits) = spawn_tcp_echo().await;
        let socks = FakeSocks::spawn().await;
        let h = start_relay(socks.addr, PASSWORD).await;
        let client = redirected_client(&h, original, 9).await;
        expect_reset(client).await;
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(h.stats.snapshot().reset_no_route, 1);
    }

    #[tokio::test]
    async fn refuses_non_loopback_listen_address() {
        let nat: SharedNat = Arc::default();
        let err = TcpRelay::bind(
            TcpRelayConfig {
                listen: "0.0.0.0:0".parse().unwrap(),
                socks: "127.0.0.1:1".parse().unwrap(),
                password: Password::new("x".to_owned()),
                group_tags: Arc::from(Vec::<String>::new()),
                connect_timeout: DEFAULT_CONNECT_TIMEOUT,
                sniff: Some(SniffConfig::web()),
            },
            nat,
        )
        .await
        .err()
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[tokio::test]
    async fn nat_entry_survives_connection_close() {
        let (echo, _) = spawn_tcp_echo().await;
        let socks = FakeSocks::spawn().await;
        let h = start_relay(socks.addr, PASSWORD).await;
        let mut client = redirected_client(&h, echo, 0).await;
        let port = client.local_addr().unwrap().port();
        client.write_all(b"x").await.unwrap();
        let mut b = [0u8; 1];
        client.read_exact(&mut b).await.unwrap();
        drop(client);
        tokio::time::sleep(Duration::from_millis(50)).await;
        // 由拦截层的 Closed 事件或空闲超时回收
        assert!(
            h.nat
                .lock()
                .unwrap()
                .touch(Network::Tcp, port, Instant::now())
        );
    }

    #[tokio::test]
    async fn many_concurrent_connections() {
        let (echo, _) = spawn_tcp_echo().await;
        let socks = FakeSocks::spawn().await;
        let h = start_relay(socks.addr, PASSWORD).await;
        let done = Arc::new(AtomicUsize::new(0));
        let mut set = JoinSet::new();
        for i in 0..32u8 {
            let client = redirected_client(&h, echo, 0).await;
            let done = Arc::clone(&done);
            set.spawn(async move {
                let mut client = client;
                client.write_all(&[i; 64]).await.unwrap();
                let mut buf = [0u8; 64];
                client.read_exact(&mut buf).await.unwrap();
                assert_eq!(buf, [i; 64]);
                done.fetch_add(1, Ordering::SeqCst);
            });
        }
        while set.join_next().await.is_some() {}
        assert_eq!(done.load(Ordering::SeqCst), 32);
    }

    /// 回显服务只能按域名 game.example.com 找到。`sniff_echo_port` 为真时在回显服务的端口上嗅探，
    /// 否则只在一个无关端口上嗅探。
    async fn sniffing_setup(sniff_echo_port: bool) -> (Harness, FakeSocks, SocketAddr) {
        let (echo, _) = spawn_tcp_echo().await;
        let socks = FakeSocks::spawn_resolving(std::collections::HashMap::from([(
            "game.example.com".to_owned(),
            echo,
        )]))
        .await;
        let ports: Arc<[u16]> = if sniff_echo_port {
            Arc::from([echo.port()])
        } else {
            Arc::from([1u16])
        };
        let sniff = SniffConfig {
            ports,
            timeout: Duration::from_millis(200),
        };
        let h = start_relay_with(socks.addr, PASSWORD, Some(sniff)).await;
        (h, socks, echo)
    }

    /// 本地 DNS 给出的「被污染」地址：TEST-NET，端口与回显服务相同，没有服务在听。
    fn poisoned(echo: SocketAddr) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], echo.port()))
    }

    async fn round_trip(client: &mut TcpStream, data: &[u8]) {
        client.write_all(data).await.unwrap();
        let mut back = vec![0u8; data.len()];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(
            back, data,
            "the upstream received exactly what the client sent"
        );
    }

    #[tokio::test]
    async fn tls_sni_replaces_the_poisoned_address() {
        let (h, socks, echo) = sniffing_setup(true).await;
        let mut client = redirected_client(&h, poisoned(echo), 0).await;
        let hello = crate::sniff::tests::client_hello(Some("Game.Example.com"));
        round_trip(&mut client, &hello).await;
        assert_eq!(
            socks.connect_requests(),
            vec![TargetAddr::Domain("game.example.com".into(), echo.port())]
        );
        assert_eq!(h.stats.snapshot().sniffed, 1);
    }

    #[tokio::test]
    async fn http_host_replaces_the_poisoned_address() {
        let (h, socks, echo) = sniffing_setup(true).await;
        let mut client = redirected_client(&h, poisoned(echo), 0).await;
        // 请求分两次发出：先到的半个请求不够取 Host
        client.write_all(b"GET / HTTP/1.1\r\nHo").await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        client
            .write_all(b"st: game.example.com\r\n\r\n")
            .await
            .unwrap();
        let expected = b"GET / HTTP/1.1\r\nHost: game.example.com\r\n\r\n";
        let mut back = vec![0u8; expected.len()];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back[..], &expected[..]);
        assert_eq!(
            socks.connect_requests(),
            vec![TargetAddr::Domain("game.example.com".into(), echo.port())]
        );
    }

    #[tokio::test]
    async fn without_a_name_the_original_address_is_used() {
        let (h, socks, echo) = sniffing_setup(true).await;
        let mut client = redirected_client(&h, echo, 0).await;
        round_trip(&mut client, b"\x00\x01 not tls or http").await;
        assert_eq!(socks.connect_requests(), vec![TargetAddr::Ip(echo)]);
        assert_eq!(h.stats.snapshot().sniffed, 0);
    }

    #[tokio::test]
    async fn server_first_protocols_fall_back_after_the_timeout() {
        let (h, socks, echo) = sniffing_setup(true).await;
        let mut client = redirected_client(&h, echo, 0).await;
        let started = std::time::Instant::now();
        // 客户端先什么都不发，像 SSH / SMTP 一样等服务端开口
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(socks.connect_requests(), vec![TargetAddr::Ip(echo)]);
        round_trip(&mut client, b"after the greeting").await;
        assert!(started.elapsed() >= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn ports_outside_the_list_are_not_sniffed() {
        let (h, socks, echo) = sniffing_setup(false).await;
        let mut client = redirected_client(&h, echo, 0).await;
        let hello = crate::sniff::tests::client_hello(Some("game.example.com"));
        round_trip(&mut client, &hello).await;
        assert_eq!(socks.connect_requests(), vec![TargetAddr::Ip(echo)]);
        assert_eq!(h.stats.snapshot().sniffed, 0);
    }
}
