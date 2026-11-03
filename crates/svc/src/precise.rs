// SPDX-License-Identifier: GPL-3.0-or-later
//! 精确进程模式的会话组件（T-078，设计文档 6.1）。
//!
//! - [`Targets`]：拦截层问「这个进程是不是目标」的答案（`FlowPolicy`）。进程追踪（T-079）报来的目标进程
//!   与进程组为准；还没报到的新进程（ETW 约 100 ms 的延迟内）在它第一次 connect 时当场按规则判定，免得
//!   新启动的目标进程头几个连接直连。当场判定只看自身规则，继承来的子进程要等追踪报到。ProcRoute 自身
//!   （服务、界面、sing-box）永远不是目标（C-NET-05），否则 sing-box 去代理服务器的连接会被改道成环；
//! - 回环中继：IPv4 与（可用时）IPv6 各一个，共用一张 NAT 表，[`NatMap`] 把改道登记进去；中继只连 sing-box
//!   的本地 SOCKS 入口，没有直连的代码路径（C-NET-03）；
//! - 拦截后端经 [`BackendFactory`] 创建：正式实现是 WinDivert，测试里换成假后端（开发机上不加载驱动）；
//! - 后端的流事件转成连接面板的事件。只有被改道的连接会出现（C-NET-02）。

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread::JoinHandle;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use procroute_intercept::divert::network::{RedirectMap, Relays};
use procroute_intercept::divert::socket::SystemProcesses;
use procroute_intercept::divert::{DivertConfig, DivertInterceptor};
use procroute_intercept::{FlowEvent, FlowPolicy, Interceptor, ProcessKey};
use procroute_platform_win::secret::Secret;
use procroute_procwatch::Change;
use procroute_procwatch::snapshot::image_path;
use procroute_proto::event::{ConnEvent, ConnPhase, Network};
use procroute_relay::nat::{NatEntry, NatTable};
use procroute_relay::tcp::{
    DEFAULT_CONNECT_TIMEOUT, SharedNat, SniffConfig, TcpRelay, TcpRelayConfig,
};
use procroute_rules::engine::RuleEngine;
use procroute_rules::matcher::NormalizedProcess;
use procroute_rules::path::normalize_path;
use tokio::sync::watch;

use crate::events::EventHub;

/// WinDivert 后端的收包线程数。
const RECEIVERS: usize = 2;
/// 当场判定结果的缓存上限，满了整体清空（只是缓存，清掉的进程下次连接时重新判定）。
const CHECKED_LIMIT: usize = 4096;

/// 创建拦截后端（未启动）。
pub trait BackendFactory: Send + Sync + 'static {
    fn create(&self, relays: Relays, map: Arc<dyn RedirectMap>) -> Box<dyn Interceptor>;
}

/// 正式实现：安装目录里按哈希锁定的 WinDivert（C-DRV-01）。
#[derive(Debug, Clone)]
pub struct DivertFactory {
    pub dir: PathBuf,
}

impl BackendFactory for DivertFactory {
    fn create(&self, relays: Relays, map: Arc<dyn RedirectMap>) -> Box<dyn Interceptor> {
        Box::new(DivertInterceptor::new(DivertConfig {
            dir: self.dir.clone(),
            relays,
            map,
            resolver: Arc::new(SystemProcesses),
            receivers: RECEIVERS,
        }))
    }
}

#[derive(Debug, Clone)]
struct Target {
    group: u16,
    name: String,
}

/// 目标集合。见模块文档。
pub struct Targets {
    known: RwLock<HashMap<ProcessKey, Target>>,
    /// 追踪还没报到的进程的当场判定结果。
    checked: Mutex<HashMap<ProcessKey, Option<u16>>>,
    engine: RuleEngine,
    /// ProcRoute 自身的可执行文件，规范化后的路径。
    self_paths: Vec<String>,
}

impl std::fmt::Debug for Targets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Targets")
            .field("known", &self.read().len())
            .finish_non_exhaustive()
    }
}

impl Targets {
    pub fn new(engine: RuleEngine, self_paths: &[String]) -> Self {
        Self {
            known: RwLock::default(),
            checked: Mutex::default(),
            engine,
            self_paths: self_paths.iter().map(|p| normalize_path(p)).collect(),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<ProcessKey, Target>> {
        self.known.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn is_self(&self, path: &str) -> bool {
        let path = normalize_path(path);
        self.self_paths.contains(&path)
    }

    /// 进程追踪报来的变化。
    pub fn apply(&self, changes: &[Change]) {
        let mut known = self.known.write().unwrap_or_else(PoisonError::into_inner);
        for change in changes {
            match change {
                Change::Targeted {
                    key,
                    group,
                    name,
                    path,
                    ..
                } => {
                    let key = ProcessKey {
                        pid: key.pid,
                        created_at: key.created_at,
                    };
                    let group = u16::try_from(*group).ok();
                    match group {
                        Some(group) if !path.as_deref().is_some_and(|p| self.is_self(p)) => {
                            known.insert(
                                key,
                                Target {
                                    group,
                                    name: name.clone(),
                                },
                            );
                        }
                        _ => {
                            known.remove(&key);
                        }
                    }
                }
                Change::Released { key } => {
                    known.remove(&ProcessKey {
                        pid: key.pid,
                        created_at: key.created_at,
                    });
                }
            }
        }
    }

    /// 目标进程的可执行文件名（连接面板显示用）。
    pub fn name_of(&self, key: &ProcessKey) -> Option<String> {
        self.read().get(key).map(|t| t.name.clone())
    }

    /// 追踪还没报到的进程：按映像路径当场判定。查不到路径（已退出、打不开）的不是目标。
    fn decide_now(&self, key: ProcessKey) -> Option<u16> {
        let path = image_path(procroute_procwatch::ProcessKey {
            pid: key.pid,
            created_at: key.created_at,
        })?;
        if self.is_self(&path) {
            return None;
        }
        let group = self
            .engine
            .decide(&NormalizedProcess::new("", &path))
            .group()?;
        u16::try_from(group).ok()
    }
}

impl FlowPolicy for Targets {
    fn target_group(&self, p: &ProcessKey) -> Option<u16> {
        if let Some(t) = self.read().get(p) {
            return Some(t.group);
        }
        let cached = self
            .checked
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(p)
            .copied();
        if let Some(decided) = cached {
            return decided;
        }
        let decided = self.decide_now(*p);
        let mut checked = self.checked.lock().unwrap_or_else(PoisonError::into_inner);
        if checked.len() >= CHECKED_LIMIT {
            checked.clear();
        }
        checked.insert(*p, decided);
        decided
    }
}

/// 把改道登记进中继的 NAT 表（拦截层的 `RedirectMap`）。
pub struct NatMap(pub SharedNat);

impl RedirectMap for NatMap {
    fn map(
        &self,
        network: Network,
        mapped_port: u16,
        original: SocketAddr,
        process: ProcessKey,
        group: u16,
    ) -> bool {
        let entry = NatEntry {
            original,
            pid: process.pid,
            process_created_at: process.created_at,
            group,
        };
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(network, mapped_port, entry, Instant::now())
            .is_ok()
    }

    fn unmap(&self, network: Network, mapped_port: u16) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(network, mapped_port);
    }
}

/// 运行中的回环中继。
pub struct RelaySet {
    pub relays: Relays,
    stop: watch::Sender<bool>,
    tasks: Vec<tokio::task::JoinHandle<io::Result<()>>>,
}

impl std::fmt::Debug for RelaySet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RelaySet")
            .field("relays", &self.relays)
            .finish_non_exhaustive()
    }
}

impl RelaySet {
    /// 在 127.0.0.1 与（可用时）::1 的随机端口上起中继，转给 sing-box 的本地 SOCKS 入口。
    pub async fn start(
        socks: SocketAddr,
        password: Secret<String>,
        group_tags: Arc<[String]>,
        nat: SharedNat,
    ) -> io::Result<Self> {
        let config = |listen: SocketAddr| TcpRelayConfig {
            listen,
            socks,
            password: password.clone(),
            group_tags: Arc::clone(&group_tags),
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            sniff: Some(SniffConfig::web()),
        };
        let v4 = TcpRelay::bind(
            config(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))),
            Arc::clone(&nat),
        )
        .await?;
        // 没有 IPv6 回环时只有 IPv4 中继，IPv6 目标流按 fail_policy 处理
        let v6 = match TcpRelay::bind(
            config(SocketAddr::from((Ipv6Addr::LOCALHOST, 0))),
            Arc::clone(&nat),
        )
        .await
        {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error = %e, "no IPv6 loopback relay; IPv6 targets follow fail_policy");
                None
            }
        };
        let relays = Relays {
            v4: v4.local_addr()?,
            v6: v6.as_ref().map(TcpRelay::local_addr).transpose()?,
        };
        let (stop, rx) = watch::channel(false);
        let mut tasks = Vec::new();
        for relay in std::iter::once(v4).chain(v6) {
            let mut rx = rx.clone();
            tasks.push(tokio::spawn(relay.serve(async move {
                let _ = rx.wait_for(|stop| *stop).await;
            })));
        }
        Ok(Self {
            relays,
            stop,
            tasks,
        })
    }

    /// 停止接受新连接并中止转发中的连接。
    pub async fn stop(self) {
        let _ = self.stop.send(true);
        for t in self.tasks {
            match t.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!(error = %e, "relay stopped with an error"),
                Err(e) => tracing::error!(error = %e, "relay task failed"),
            }
        }
    }
}

/// 新建会话用的 NAT 表：表满时的新流按方案的 fail_policy 处理（C-PERF-04）。
pub fn new_nat(fail_policy: procroute_proto::profile::FailPolicy) -> SharedNat {
    Arc::new(Mutex::new(NatTable::new(procroute_relay::nat::NatConfig {
        fail_policy,
        ..Default::default()
    })))
}

/// 进程组下标 → （组标签, 出站显示名）。
pub type GroupLabels = Arc<[(String, String)]>;

/// 把后端的流事件转成连接面板事件，直到后端停止（事件通道的发送端全部丢弃）。
pub fn spawn_conn_events(
    events: Receiver<FlowEvent>,
    hub: Arc<EventHub>,
    targets: Arc<Targets>,
    groups: GroupLabels,
) -> io::Result<JoinHandle<()>> {
    std::thread::Builder::new()
        .name("conn-events".to_owned())
        .spawn(move || {
            let mut open: HashMap<procroute_intercept::FlowKey, ConnEvent> = HashMap::new();
            let mut next_id = 0u64;
            for event in events {
                match event {
                    FlowEvent::Redirected {
                        key,
                        process,
                        group,
                    } => {
                        next_id += 1;
                        let (tag, outbound) =
                            groups.get(usize::from(group)).cloned().unwrap_or_default();
                        let conn = ConnEvent {
                            conn_id: next_id,
                            phase: ConnPhase::Opened,
                            pid: process.pid,
                            process: targets.name_of(&process).unwrap_or_default(),
                            target: key.remote.to_string(),
                            network: key.network,
                            group: tag,
                            outbound,
                            upload_bytes: 0,
                            download_bytes: 0,
                            started_at_ms: now_ms(),
                        };
                        hub.publish_conn(conn.clone());
                        open.insert(key, conn);
                    }
                    FlowEvent::Closed { key } => {
                        if let Some(mut conn) = open.remove(&key) {
                            conn.phase = ConnPhase::Closed;
                            hub.publish_conn(conn);
                        }
                    }
                    FlowEvent::Blocked { key, process } => {
                        tracing::debug!(
                            pid = process.map(|p| p.pid),
                            network = ?key.network,
                            "target flow blocked by fail_policy"
                        );
                    }
                }
            }
            // 后端停了：剩下的连接都已结束
            for (_, mut conn) in open.drain() {
                conn.phase = ConnPhase::Closed;
                hub.publish_conn(conn);
            }
        })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 解析节点服务器地址，写进排除表（C-NET-05）。sing-box 自身已按进程排除，这里是第二道防线：
/// 解析失败的跳过。域名解析可能很慢，调用方应在阻塞线程上调用并加超时。
pub fn resolve_servers(servers: &[(String, u16)]) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    let mut ips: Vec<IpAddr> = servers
        .iter()
        .filter_map(|(host, port)| (host.as_str(), *port).to_socket_addrs().ok())
        .flatten()
        .map(|a| a.ip())
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

#[cfg(test)]
mod tests {
    use procroute_proto::profile::Profile;

    use super::*;
    use crate::store::tests::sample;

    /// 本测试进程的身份。
    fn me() -> ProcessKey {
        use procroute_intercept::divert::socket::ProcessResolver;
        SystemProcesses
            .resolve(std::process::id())
            .expect("resolve this process")
    }

    /// 只有一个组、按本测试程序的完整路径命中的方案。
    fn profile_for_this_exe() -> Profile {
        let mut p = sample("p1", "x");
        let exe = std::env::current_exe().expect("exe");
        p.groups[0].matchers[0].value = exe.to_string_lossy().into_owned();
        p.groups[0].matchers[0].kind = procroute_proto::profile::MatchType::Path;
        p
    }

    fn targets(p: &Profile, self_paths: &[String]) -> Targets {
        Targets::new(RuleEngine::compile(p).expect("compile"), self_paths)
    }

    #[test]
    fn processes_not_yet_reported_are_decided_on_the_spot() {
        let t = targets(&profile_for_this_exe(), &[]);
        assert_eq!(t.target_group(&me()), Some(0));
        // 不存在的进程：不是目标
        let ghost = ProcessKey {
            pid: 0x7fff_fff0,
            created_at: 1,
        };
        assert_eq!(t.target_group(&ghost), None);
    }

    #[test]
    fn procroute_itself_is_never_a_target() {
        let exe = std::env::current_exe()
            .expect("exe")
            .to_string_lossy()
            .into_owned();
        let t = targets(&profile_for_this_exe(), &[exe.to_uppercase()]);
        assert_eq!(
            t.target_group(&me()),
            None,
            "self paths are compared normalized"
        );
        // 追踪报来的同样被挡掉
        let key = me();
        t.apply(&[Change::Targeted {
            key: procroute_procwatch::ProcessKey {
                pid: key.pid,
                created_at: key.created_at,
            },
            group: 0,
            inherited: false,
            name: "x.exe".into(),
            path: Some(exe),
        }]);
        assert_eq!(t.name_of(&key), None);
    }

    #[test]
    fn reported_targets_win_and_release_removes_them() {
        // 方案不命中本进程，但追踪报来它是继承来的目标（组 3）
        let t = targets(&sample("p1", "x"), &[]);
        let key = me();
        let pw = procroute_procwatch::ProcessKey {
            pid: key.pid,
            created_at: key.created_at,
        };
        assert_eq!(t.target_group(&key), None);
        t.apply(&[Change::Targeted {
            key: pw,
            group: 3,
            inherited: true,
            name: "child.exe".into(),
            path: None,
        }]);
        assert_eq!(
            t.target_group(&key),
            Some(3),
            "known targets beat the cache"
        );
        assert_eq!(t.name_of(&key).as_deref(), Some("child.exe"));
        t.apply(&[Change::Released { key: pw }]);
        assert_eq!(t.name_of(&key), None);
    }

    #[test]
    fn nat_map_registers_and_removes_entries() {
        let nat = new_nat(procroute_proto::profile::FailPolicy::Block);
        let map = NatMap(Arc::clone(&nat));
        let original: SocketAddr = "203.0.113.24:443".parse().expect("addr");
        let key = me();
        assert!(map.map(Network::Tcp, 50001, original, key, 2));
        let entry = nat
            .lock()
            .expect("nat")
            .lookup(Network::Tcp, 50001, Instant::now())
            .expect("entry");
        assert_eq!(entry.original, original);
        assert_eq!(
            (entry.pid, entry.process_created_at, entry.group),
            (key.pid, key.created_at, 2)
        );
        // 端口被一条活跃的流占着：拒绝，拦截层按 fail_policy 处理
        assert!(!map.map(Network::Tcp, 50001, original, key, 2));
        map.unmap(Network::Tcp, 50001);
        assert!(map.map(Network::Tcp, 50001, original, key, 2));
    }

    #[test]
    fn server_names_resolve_and_failures_are_skipped() {
        let ips = resolve_servers(&[
            ("127.0.0.1".into(), 443),
            ("::1".into(), 443),
            ("127.0.0.1".into(), 8443),
            ("name.invalid".into(), 443),
        ]);
        assert_eq!(
            ips,
            vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST)
            ]
        );
    }

    #[tokio::test]
    async fn relays_listen_on_loopback_and_stop() {
        let nat = new_nat(procroute_proto::profile::FailPolicy::Block);
        let relays = RelaySet::start(
            "127.0.0.1:9".parse().expect("addr"),
            Secret::new("s".repeat(32)),
            Arc::from(vec!["g".to_owned()]),
            nat,
        )
        .await
        .expect("start");
        assert!(relays.relays.v4.ip().is_loopback());
        assert_ne!(relays.relays.v4.port(), 0);
        if let Some(v6) = relays.relays.v6 {
            assert!(v6.ip().is_loopback());
        }
        // 查不到映射的连接被重置，不会被转发
        let mut s = tokio::net::TcpStream::connect(relays.relays.v4)
            .await
            .expect("connect");
        let mut buf = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(&mut s, &mut buf).await;
        assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
        relays.stop().await;
    }
}
