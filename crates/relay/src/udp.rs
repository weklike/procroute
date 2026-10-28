// SPDX-License-Identifier: GPL-3.0-or-later
//! UDP 会话表与中继（T-090，设计文档 6.2）。
//!
//! - 会话按应用的「本地地址 + 本地端口」建立，而不是按五元组：一个本地端口对多个远端
//!   仍走同一个会话，保持 full-cone 语义；
//! - 每个会话对应 sing-box 的一个 UDP ASSOCIATE（用户名为进程组标签）；
//! - 拦截层把目标进程的数据报（含原始目的地址）交给 [`UdpRelay::send`]，回包经
//!   [`UdpReplySink::deliver`] 交回拦截层，由它按会话改写源地址后注入；
//! - sing-box 不可达、会话建立失败、队列满或会话数超限时一律丢弃，绝不直连（C-NET-03）；
//! - 会话空闲超过超时（默认 60 s，C-PERF-04）后关闭。
//!
//! 每个会话的编码缓冲区在建立时分配一次，收发数据报不再分配（回包以借用切片交付）。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::runtime::Handle;
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::task::AbortHandle;
use tokio::time::{Instant, sleep_until};

use crate::nat::{DEFAULT_CAPACITY, DEFAULT_UDP_IDLE};
use crate::socks5::{self, MAX_UDP_HEADER, Password, TargetAddr};

/// 单个 UDP 数据报负载的上限（IPv4 理论最大值）。
pub const MAX_PAYLOAD: usize = 65_507;
/// 每个会话待发送队列的默认长度。
pub const DEFAULT_QUEUE: usize = 256;

#[derive(Debug, Clone)]
pub struct UdpRelayConfig {
    /// sing-box 本地 SOCKS5 入口（只绑定回环，C-NET-08）。
    pub socks: SocketAddr,
    pub password: Password,
    /// 进程组下标 → 组标签（即 SOCKS 用户名）。
    pub group_tags: Arc<[String]>,
    pub idle_timeout: Duration,
    pub max_sessions: usize,
    pub queue: usize,
    pub connect_timeout: Duration,
}

impl UdpRelayConfig {
    pub fn new(socks: SocketAddr, password: Password, group_tags: Arc<[String]>) -> Self {
        Self {
            socks,
            password,
            group_tags,
            idle_timeout: DEFAULT_UDP_IDLE,
            max_sessions: DEFAULT_CAPACITY,
            queue: DEFAULT_QUEUE,
            connect_timeout: crate::tcp::DEFAULT_CONNECT_TIMEOUT,
        }
    }
}

/// 拦截层交来的一个数据报。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// 应用的本地地址与端口，即会话键。
    pub session: SocketAddr,
    /// 进程组下标。
    pub group: u16,
    /// 应用原本要发往的目的地址。
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

/// 回包出口，由拦截层实现：把 `src → session` 的数据报注入回应用。
///
/// 在会话任务里同步调用，实现必须快且不阻塞（C-CODE-05）。
pub trait UdpReplySink: Send + Sync + 'static {
    fn deliver(&self, session: SocketAddr, src: SocketAddr, payload: &[u8]);
}

/// 数据报被丢弃的原因。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// 组下标无效。
    NoRoute,
    /// 负载过大。
    TooLarge,
    /// 会话数已达上限。
    SessionLimit,
    /// 会话队列已满或会话已关闭。
    Backpressure,
}

#[derive(Debug, Default)]
struct Stats {
    sessions_opened: AtomicU64,
    sent: AtomicU64,
    received: AtomicU64,
    dropped: AtomicU64,
    /// 会话建立失败（sing-box 不可达等）连带丢弃的数据报。
    dropped_upstream: AtomicU64,
}

/// 计数器快照。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UdpRelayCounts {
    pub sessions_opened: u64,
    pub sent: u64,
    pub received: u64,
    pub dropped: u64,
    pub dropped_upstream: u64,
}

struct SessionHandle {
    id: u64,
    group: u16,
    tx: mpsc::Sender<Datagram>,
    task: AbortHandle,
}

struct Inner {
    config: UdpRelayConfig,
    sink: Arc<dyn UdpReplySink>,
    sessions: Mutex<HashMap<SocketAddr, SessionHandle>>,
    next_id: AtomicU64,
    stats: Stats,
    runtime: Handle,
}

impl Inner {
    fn sessions(&self) -> MutexGuard<'_, HashMap<SocketAddr, SessionHandle>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn drop_one(&self) {
        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
    }

    /// 会话任务结束时移除自己；同一键上的新会话不受影响。
    fn forget(&self, key: SocketAddr, id: u64) {
        let mut sessions = self.sessions();
        if sessions.get(&key).is_some_and(|s| s.id == id) {
            sessions.remove(&key);
        }
    }
}

pub struct UdpRelay {
    inner: Arc<Inner>,
}

impl UdpRelay {
    /// 必须在 tokio 运行时内调用；会话任务在该运行时上运行。
    pub fn new(config: UdpRelayConfig, sink: Arc<dyn UdpReplySink>) -> Self {
        Self {
            inner: Arc::new(Inner {
                config,
                sink,
                sessions: Mutex::default(),
                next_id: AtomicU64::new(0),
                stats: Stats::default(),
                runtime: Handle::current(),
            }),
        }
    }

    /// 发送一个数据报。不阻塞：需要时建立会话，数据报进入会话队列后立即返回。
    pub fn send(&self, d: Datagram) -> Result<(), DropReason> {
        let result = self.enqueue(d);
        if result.is_err() {
            self.inner.drop_one();
        }
        result
    }

    fn enqueue(&self, d: Datagram) -> Result<(), DropReason> {
        let inner = &self.inner;
        if d.payload.len() > MAX_PAYLOAD {
            return Err(DropReason::TooLarge);
        }
        let Some(tag) = inner.config.group_tags.get(usize::from(d.group)) else {
            return Err(DropReason::NoRoute);
        };
        let mut sessions = inner.sessions();
        // 同一本地端口换了进程组（端口被别的进程复用）：旧会话作废
        if sessions.get(&d.session).is_some_and(|s| s.group != d.group)
            && let Some(old) = sessions.remove(&d.session)
        {
            old.task.abort();
        }
        if !sessions.contains_key(&d.session) {
            if sessions.len() >= inner.config.max_sessions {
                return Err(DropReason::SessionLimit);
            }
            let handle = self.open(d.session, d.group, tag.clone());
            sessions.insert(d.session, handle);
        }
        let Some(session) = sessions.get(&d.session) else {
            return Err(DropReason::Backpressure);
        };
        match session.tx.try_send(d) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_) | TrySendError::Closed(_)) => Err(DropReason::Backpressure),
        }
    }

    fn open(&self, key: SocketAddr, group: u16, tag: String) -> SessionHandle {
        let inner = &self.inner;
        let id = inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(inner.config.queue.max(1));
        inner.stats.sessions_opened.fetch_add(1, Ordering::Relaxed);
        let task = inner
            .runtime
            .spawn(run_session(Arc::clone(inner), key, id, tag, rx))
            .abort_handle();
        SessionHandle {
            id,
            group,
            tx,
            task,
        }
    }

    pub fn session_count(&self) -> usize {
        self.inner.sessions().len()
    }

    pub fn counts(&self) -> UdpRelayCounts {
        let s = &self.inner.stats;
        UdpRelayCounts {
            sessions_opened: s.sessions_opened.load(Ordering::Relaxed),
            sent: s.sent.load(Ordering::Relaxed),
            received: s.received.load(Ordering::Relaxed),
            dropped: s.dropped.load(Ordering::Relaxed),
            dropped_upstream: s.dropped_upstream.load(Ordering::Relaxed),
        }
    }

    /// 关闭全部会话。
    pub fn shutdown(&self) {
        for (_, s) in self.inner.sessions().drain() {
            s.task.abort();
        }
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// 已建立的关联：控制连接必须保持打开，关闭即结束关联。
struct Association {
    control: TcpStream,
    socket: UdpSocket,
    relay: SocketAddr,
}

async fn associate(config: &UdpRelayConfig, tag: &str) -> Result<Association, socks5::Socks5Error> {
    let mut control = TcpStream::connect(config.socks).await?;
    socks5::handshake(&mut control, tag, &config.password).await?;
    let bind_ip: IpAddr = match config.socks {
        SocketAddr::V4(_) => [127, 0, 0, 1].into(),
        SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
    };
    let socket = UdpSocket::bind(SocketAddr::new(bind_ip, 0)).await?;
    let relay = match socks5::udp_associate(&mut control, socket.local_addr()?).await? {
        // 服务端回未指定地址时表示「与控制连接同一地址」
        TargetAddr::Ip(a) if a.ip().is_unspecified() => {
            SocketAddr::new(config.socks.ip(), a.port())
        }
        TargetAddr::Ip(a) => a,
        TargetAddr::Domain(..) => {
            return Err(socks5::Socks5Error::Protocol(
                "UDP relay address must be an IP",
            ));
        }
    };
    Ok(Association {
        control,
        socket,
        relay,
    })
}

async fn run_session(
    inner: Arc<Inner>,
    key: SocketAddr,
    id: u64,
    tag: String,
    mut rx: mpsc::Receiver<Datagram>,
) {
    let setup =
        tokio::time::timeout(inner.config.connect_timeout, associate(&inner.config, &tag)).await;
    if let Ok(Ok(mut assoc)) = setup {
        // 收发错误只结束本会话；之后的数据报会建立新会话
        let _ = pump(&inner, key, &mut rx, &mut assoc).await;
    }
    inner.forget(key, id);
    // fail-closed：会话没建起来或已结束，队列里剩下的数据报全部丢弃
    rx.close();
    while rx.try_recv().is_ok() {
        inner.stats.dropped_upstream.fetch_add(1, Ordering::Relaxed);
    }
}

async fn pump(
    inner: &Inner,
    key: SocketAddr,
    rx: &mut mpsc::Receiver<Datagram>,
    assoc: &mut Association,
) -> io::Result<()> {
    let idle = inner.config.idle_timeout;
    let mut out = vec![0u8; MAX_UDP_HEADER + MAX_PAYLOAD];
    let mut inbound = vec![0u8; MAX_UDP_HEADER + MAX_PAYLOAD];
    let mut ctl = [0u8; 1];
    let sleep = sleep_until(Instant::now() + idle);
    tokio::pin!(sleep);
    loop {
        tokio::select! {
            () = &mut sleep => return Ok(()),
            d = rx.recv() => {
                let Some(d) = d else { return Ok(()) };
                let header = socks5::encode_udp_header(&TargetAddr::Ip(d.dst), &mut out)
                    .map_err(|_| io::Error::other("encode UDP header"))?;
                let len = header + d.payload.len();
                out[header..len].copy_from_slice(&d.payload);
                assoc.socket.send_to(&out[..len], assoc.relay).await?;
                inner.stats.sent.fetch_add(1, Ordering::Relaxed);
                sleep.as_mut().reset(Instant::now() + idle);
            }
            r = assoc.socket.recv_from(&mut inbound) => {
                let (n, from) = r?;
                if from != assoc.relay {
                    continue;
                }
                let Ok((TargetAddr::Ip(src), payload)) = socks5::decode_udp(&inbound[..n]) else {
                    continue;
                };
                inner.sink.deliver(key, src, payload);
                inner.stats.received.fetch_add(1, Ordering::Relaxed);
                sleep.as_mut().reset(Instant::now() + idle);
            }
            r = assoc.control.read(&mut ctl) => {
                // sing-box 关闭了控制连接：关联失效
                if matches!(r, Ok(0) | Err(_)) {
                    return Ok(());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc::UnboundedSender;
    use tokio::time::timeout;

    use super::*;
    use crate::testutil::{FakeSocks, PASSWORD, spawn_udp_echo};

    struct ChannelSink(UnboundedSender<(SocketAddr, SocketAddr, Vec<u8>)>);

    impl UdpReplySink for ChannelSink {
        fn deliver(&self, session: SocketAddr, src: SocketAddr, payload: &[u8]) {
            let _ = self.0.send((session, src, payload.to_vec()));
        }
    }

    type Replies = mpsc::UnboundedReceiver<(SocketAddr, SocketAddr, Vec<u8>)>;

    fn relay(socks: SocketAddr, password: &str, idle: Duration) -> (UdpRelay, Replies) {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut config = UdpRelayConfig::new(
            socks,
            Password::new(password.to_owned()),
            Arc::from(vec!["game".to_owned()]),
        );
        config.idle_timeout = idle;
        config.connect_timeout = Duration::from_secs(2);
        (UdpRelay::new(config, Arc::new(ChannelSink(tx))), rx)
    }

    fn dgram(session: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Datagram {
        Datagram {
            session,
            group: 0,
            dst,
            payload: payload.to_vec(),
        }
    }

    const APP: &str = "192.168.1.5:50000";

    #[tokio::test]
    async fn one_local_port_to_many_remotes_uses_one_session() {
        let (a, _) = spawn_udp_echo(b"A:").await;
        let (b, _) = spawn_udp_echo(b"B:").await;
        let socks = FakeSocks::spawn().await;
        let (relay, mut replies) = relay(socks.addr, PASSWORD, DEFAULT_UDP_IDLE);
        let app: SocketAddr = APP.parse().unwrap();

        relay.send(dgram(app, a, b"one")).unwrap();
        relay.send(dgram(app, b, b"two")).unwrap();

        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(
                timeout(Duration::from_secs(2), replies.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        got.sort_by(|x, y| x.2.cmp(&y.2));
        assert_eq!(got[0], (app, a, b"A:one".to_vec()));
        assert_eq!(got[1], (app, b, b"B:two".to_vec()));
        assert_eq!(
            socks.associates(),
            1,
            "full-cone: one ASSOCIATE per local port"
        );
        assert_eq!(socks.usernames(), vec!["game".to_owned()]);
        assert_eq!(relay.session_count(), 1);
        let c = relay.counts();
        assert_eq!((c.sessions_opened, c.sent, c.received), (1, 2, 2));
    }

    #[tokio::test]
    async fn different_local_ports_get_separate_sessions() {
        let (a, _) = spawn_udp_echo(b"A:").await;
        let socks = FakeSocks::spawn().await;
        let (relay, mut replies) = relay(socks.addr, PASSWORD, DEFAULT_UDP_IDLE);
        let p1: SocketAddr = "192.168.1.5:50000".parse().unwrap();
        let p2: SocketAddr = "192.168.1.5:50001".parse().unwrap();
        relay.send(dgram(p1, a, b"1")).unwrap();
        relay.send(dgram(p2, a, b"2")).unwrap();
        let mut sessions = Vec::new();
        for _ in 0..2 {
            let (s, _, _) = timeout(Duration::from_secs(2), replies.recv())
                .await
                .unwrap()
                .unwrap();
            sessions.push(s);
        }
        sessions.sort();
        assert_eq!(sessions, vec![p1, p2]);
        assert_eq!(socks.associates(), 2);
    }

    #[tokio::test]
    async fn socks_unreachable_drops_and_never_sends_directly() {
        // C-NET-03
        let (target, direct_hits) = spawn_udp_echo(b"X:").await;
        let dead = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap()
        };
        let (relay, mut replies) = relay(dead, PASSWORD, DEFAULT_UDP_IDLE);
        let app: SocketAddr = APP.parse().unwrap();
        relay.send(dgram(app, target, b"leak?")).unwrap();
        assert!(
            timeout(Duration::from_millis(300), replies.recv())
                .await
                .is_err()
        );
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(relay.counts().dropped_upstream, 1);
        assert_eq!(relay.session_count(), 0);
    }

    #[tokio::test]
    async fn wrong_password_drops() {
        let (target, direct_hits) = spawn_udp_echo(b"X:").await;
        let socks = FakeSocks::spawn().await;
        let (relay, mut replies) = relay(socks.addr, "wrong", DEFAULT_UDP_IDLE);
        relay
            .send(dgram(APP.parse().unwrap(), target, b"x"))
            .unwrap();
        assert!(
            timeout(Duration::from_millis(300), replies.recv())
                .await
                .is_err()
        );
        assert_eq!(direct_hits.load(Ordering::SeqCst), 0);
        assert_eq!(relay.counts().dropped_upstream, 1);
    }

    #[tokio::test]
    async fn idle_session_is_closed_and_reopened_on_demand() {
        let (a, _) = spawn_udp_echo(b"A:").await;
        let socks = FakeSocks::spawn().await;
        let (relay, mut replies) = relay(socks.addr, PASSWORD, Duration::from_millis(100));
        let app: SocketAddr = APP.parse().unwrap();
        relay.send(dgram(app, a, b"1")).unwrap();
        timeout(Duration::from_secs(2), replies.recv())
            .await
            .unwrap()
            .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert_eq!(relay.session_count(), 0);
        relay.send(dgram(app, a, b"2")).unwrap();
        timeout(Duration::from_secs(2), replies.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(socks.associates(), 2);
    }

    #[tokio::test]
    async fn invalid_group_oversized_payload_and_session_limit_are_dropped() {
        let socks = FakeSocks::spawn().await;
        let (tx, _rx) = mpsc::unbounded_channel();
        let mut config = UdpRelayConfig::new(
            socks.addr,
            Password::new(PASSWORD.to_owned()),
            Arc::from(vec!["game".to_owned()]),
        );
        config.max_sessions = 1;
        let relay = UdpRelay::new(config, Arc::new(ChannelSink(tx)));
        let dst: SocketAddr = "203.0.113.24:27015".parse().unwrap();

        let mut bad_group = dgram(APP.parse().unwrap(), dst, b"x");
        bad_group.group = 7;
        assert_eq!(relay.send(bad_group), Err(DropReason::NoRoute));

        let big = Datagram {
            payload: vec![0; MAX_PAYLOAD + 1],
            ..dgram(APP.parse().unwrap(), dst, b"")
        };
        assert_eq!(relay.send(big), Err(DropReason::TooLarge));

        relay.send(dgram(APP.parse().unwrap(), dst, b"x")).unwrap();
        let other: SocketAddr = "192.168.1.5:50001".parse().unwrap();
        assert_eq!(
            relay.send(dgram(other, dst, b"x")),
            Err(DropReason::SessionLimit)
        );
        assert_eq!(relay.counts().dropped, 3);
    }

    #[tokio::test]
    async fn shutdown_closes_every_session() {
        let (a, _) = spawn_udp_echo(b"A:").await;
        let socks = FakeSocks::spawn().await;
        let (relay, mut replies) = relay(socks.addr, PASSWORD, DEFAULT_UDP_IDLE);
        relay.send(dgram(APP.parse().unwrap(), a, b"1")).unwrap();
        timeout(Duration::from_secs(2), replies.recv())
            .await
            .unwrap()
            .unwrap();
        relay.shutdown();
        assert_eq!(relay.session_count(), 0);
    }
}
