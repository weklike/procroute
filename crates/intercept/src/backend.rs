// SPDX-License-Identifier: GPL-3.0-or-later
//! `Interceptor` trait 与所有后端共用的判定逻辑。
//!
//! 一条新流的判定顺序（[`decide`]）：
//!
//! 1. 目标地址在排除表里（回环、链路本地、代理服务器）→ 放行（C-NET-05）；
//! 2. 暂存与端口反查后仍无法归属 → 按非目标放行，`attribution_miss` 加一（C-NET-04）；
//! 3. 进程是 ProcRoute 自身 → 放行（C-NET-05）；
//! 4. 进程不在目标集合 → 放行，且不改写任何东西（C-NET-02）；
//! 5. 目标进程的 UDP：开启 QUIC 阻断时 443 端口阻断；开启 53 劫持时 53 端口改道；
//!    方案关闭了 UDP 代理时放行；
//! 6. 其余改道到本地中继。
//!
//! 后端处理不了的目标进程数据包（分片重组失败、不支持的协议等）按 [`unprocessable`]
//! 处理，绝不静默放行（C-NET-07）。

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};

use procroute_proto::event::Network;
use procroute_proto::profile::FailPolicy;
use thiserror::Error;

use crate::exclude::ExclusionSet;
use crate::flow::{FlowEvent, NewFlow, ProcessKey};

const PORT_DNS: u16 = 53;
const PORT_QUIC: u16 = 443;

/// 由方案派生、后端运行期间不变的设置。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterceptSettings {
    pub fail_policy: FailPolicy,
    /// 是否代理目标进程的 UDP。
    pub udp_enabled: bool,
    /// 阻断目标进程的 UDP 443。
    pub block_quic: bool,
    /// 目标进程直发的 53 端口查询交给内核的 DNS。
    pub hijack_port53: bool,
}

impl Default for InterceptSettings {
    /// 与方案的默认值一致：fail-closed、代理 UDP、劫持 53。
    fn default() -> Self {
        Self {
            fail_policy: FailPolicy::Block,
            udp_enabled: true,
            block_quic: false,
            hijack_port53: true,
        }
    }
}

/// 判断进程属于哪个进程组。由 svc 基于规则引擎与进程追踪器实现。
///
/// 后端在每条新流上调用一次，实现必须快且不阻塞（C-CODE-04）。
pub trait FlowPolicy: Send + Sync {
    /// 目标进程返回进程组下标，否则返回 `None`。
    fn target_group(&self, process: &ProcessKey) -> Option<u16>;
}

/// 放行的原因，用于统计与调试。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BypassReason {
    /// 命中永久排除表。
    Excluded,
    /// 无法归属到任何进程。
    Unattributed,
    /// 不是目标进程。
    NotTarget,
    /// 方案关闭了 UDP 代理。
    UdpDisabled,
    /// 用户显式选择 `fail_policy = allow` 后的回落。
    FailOpen,
}

/// 对一条新流的判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// 改道到本地中继，`group` 为进程组下标。
    Redirect { group: u16 },
    /// 原样放行，不改写。
    Bypass(BypassReason),
    /// 阻断：TCP 回 RST、UDP 丢弃。
    Block,
}

/// 新流的判定。所有后端都必须用它，保证行为一致。
pub fn decide(
    flow: &NewFlow,
    settings: &InterceptSettings,
    exclusions: &ExclusionSet,
    policy: &dyn FlowPolicy,
    counters: &Counters,
) -> Verdict {
    let verdict = classify(flow, settings, exclusions, policy);
    counters.record(&verdict);
    verdict
}

fn classify(
    flow: &NewFlow,
    settings: &InterceptSettings,
    exclusions: &ExclusionSet,
    policy: &dyn FlowPolicy,
) -> Verdict {
    if exclusions.excludes_ip(flow.key.remote.ip()) {
        return Verdict::Bypass(BypassReason::Excluded);
    }
    let Some(process) = flow.process else {
        return Verdict::Bypass(BypassReason::Unattributed);
    };
    if exclusions.excludes_process(&process) {
        return Verdict::Bypass(BypassReason::Excluded);
    }
    let Some(group) = policy.target_group(&process) else {
        return Verdict::Bypass(BypassReason::NotTarget);
    };
    if flow.key.network == Network::Udp {
        let port = flow.key.remote.port();
        if settings.block_quic && port == PORT_QUIC {
            return Verdict::Block;
        }
        if !(settings.udp_enabled || (settings.hijack_port53 && port == PORT_DNS)) {
            return Verdict::Bypass(BypassReason::UdpDisabled);
        }
    }
    Verdict::Redirect { group }
}

/// 目标进程的数据包无法正确处理时的判定（C-NET-07）。
///
/// 只对目标进程调用；非目标进程的包无论如何都原样放行（C-NET-02）。
pub fn unprocessable(fail_policy: FailPolicy, counters: &Counters) -> Verdict {
    let verdict = match fail_policy {
        FailPolicy::Block => Verdict::Block,
        FailPolicy::Allow => Verdict::Bypass(BypassReason::FailOpen),
    };
    counters.record(&verdict);
    verdict
}

/// 后端计数器。只用原子操作，可以在逐包路径上更新（C-CODE-04）。
#[derive(Debug, Default)]
pub struct Counters {
    redirected: AtomicU64,
    bypassed: AtomicU64,
    blocked: AtomicU64,
    attribution_miss: AtomicU64,
    events_dropped: AtomicU64,
}

impl Counters {
    fn record(&self, verdict: &Verdict) {
        let counter = match verdict {
            Verdict::Redirect { .. } => &self.redirected,
            Verdict::Block => &self.blocked,
            Verdict::Bypass(reason) => {
                if *reason == BypassReason::Unattributed {
                    self.attribution_miss.fetch_add(1, Ordering::Relaxed);
                }
                &self.bypassed
            }
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> InterceptStats {
        InterceptStats {
            redirected: self.redirected.load(Ordering::Relaxed),
            bypassed: self.bypassed.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            attribution_miss: self.attribution_miss.load(Ordering::Relaxed),
            events_dropped: self.events_dropped.load(Ordering::Relaxed),
        }
    }
}

/// 计数器快照。`attribution_miss` 纳入泄漏测试判据（C-NET-04、C-TEST-02）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InterceptStats {
    pub redirected: u64,
    pub bypassed: u64,
    pub blocked: u64,
    pub attribution_miss: u64,
    /// 事件通道满时丢弃的事件数。丢掉的 `Closed` 由 NAT 表的空闲超时兜底回收。
    pub events_dropped: u64,
}

/// 非阻塞地发出事件；通道满或已关闭时丢弃并计数，绝不阻塞收包线程（C-CODE-05）。
pub fn emit(events: &SyncSender<FlowEvent>, event: FlowEvent, counters: &Counters) {
    match events.try_send(event) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => {
            counters.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// 启动后端所需的全部输入。
pub struct StartContext {
    pub settings: InterceptSettings,
    pub exclusions: ExclusionSet,
    pub policy: Arc<dyn FlowPolicy>,
    /// 有界通道（C-CODE-05）。
    pub events: SyncSender<FlowEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InterceptError {
    #[error("拦截后端已在运行")]
    AlreadyRunning,
    #[error("拦截后端未运行")]
    NotRunning,
    #[error("驱动不可用：{0}")]
    DriverUnavailable(String),
    #[error("拦截后端出错：{0}")]
    Backend(String),
}

/// 拦截后端。新增后端必须实现本 trait，并通过同一套 e2e 泄漏测试（C-DRV-06）。
///
/// 实现约定：
///
/// - 新流一律用 [`decide`] 判定，处理不了的目标进程数据包用 [`unprocessable`]；
/// - [`Interceptor::stop`] 与 `Drop` 都必须撤销本后端安装的全部过滤器，
///   不得留下持久化的过滤器、路由或防火墙规则（C-NET-06）；
/// - 收发包在专用 OS 线程，与异步部分只经有界通道交互（C-CODE-05）。
pub trait Interceptor: Send {
    /// 后端名，用于日志，例如 `divert`、`mock`。
    fn name(&self) -> &'static str;

    fn start(&mut self, ctx: StartContext) -> Result<(), InterceptError>;

    /// 停止并撤销全部过滤器。已停止时返回 [`InterceptError::NotRunning`]。
    fn stop(&mut self) -> Result<(), InterceptError>;

    fn is_active(&self) -> bool;

    /// 整体替换排除表。代理服务器地址变化后 svc 调用，新表必须在 1 秒内生效（C-NET-05）。
    fn update_exclusions(&mut self, exclusions: ExclusionSet) -> Result<(), InterceptError>;

    fn stats(&self) -> InterceptStats;
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::*;
    use crate::flow::FlowKey;

    struct Targets(HashMap<ProcessKey, u16>);

    impl FlowPolicy for Targets {
        fn target_group(&self, p: &ProcessKey) -> Option<u16> {
            self.0.get(p).copied()
        }
    }

    const GAME: ProcessKey = ProcessKey {
        pid: 4120,
        created_at: 10,
    };
    const OTHER: ProcessKey = ProcessKey {
        pid: 77,
        created_at: 3,
    };
    const PROXY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

    fn policy() -> Targets {
        Targets(HashMap::from([(GAME, 2)]))
    }

    fn flow(network: Network, remote: &str, process: Option<ProcessKey>) -> NewFlow {
        NewFlow {
            key: FlowKey {
                network,
                local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), 50000),
                remote: remote.parse().unwrap(),
            },
            process,
        }
    }

    fn run(f: &NewFlow, s: &InterceptSettings) -> (Verdict, InterceptStats) {
        let counters = Counters::default();
        let ex = ExclusionSet::new([], [IpAddr::V4(PROXY)]);
        let v = decide(f, s, &ex, &policy(), &counters);
        (v, counters.snapshot())
    }

    #[test]
    fn target_tcp_is_redirected_to_its_group() {
        let (v, stats) = run(
            &flow(Network::Tcp, "203.0.113.24:443", Some(GAME)),
            &InterceptSettings::default(),
        );
        assert_eq!(v, Verdict::Redirect { group: 2 });
        assert_eq!(stats.redirected, 1);
    }

    #[test]
    fn non_target_is_bypassed() {
        let (v, _) = run(
            &flow(Network::Tcp, "203.0.113.24:443", Some(OTHER)),
            &InterceptSettings::default(),
        );
        assert_eq!(v, Verdict::Bypass(BypassReason::NotTarget));
    }

    #[test]
    fn traffic_to_proxy_server_and_loopback_is_never_redirected() {
        // C-NET-05：即使是目标进程
        for remote in [
            "198.51.100.7:8443",
            "127.0.0.1:1080",
            "[::1]:1080",
            "169.254.1.1:80",
        ] {
            let (v, _) = run(
                &flow(Network::Tcp, remote, Some(GAME)),
                &InterceptSettings::default(),
            );
            assert_eq!(v, Verdict::Bypass(BypassReason::Excluded), "{remote}");
        }
    }

    #[test]
    fn self_processes_are_excluded_even_if_rules_match() {
        let counters = Counters::default();
        let ex = ExclusionSet::new([GAME], []);
        let v = decide(
            &flow(Network::Tcp, "203.0.113.24:443", Some(GAME)),
            &InterceptSettings::default(),
            &ex,
            &policy(),
            &counters,
        );
        assert_eq!(v, Verdict::Bypass(BypassReason::Excluded));
    }

    #[test]
    fn unattributed_flows_pass_and_count_as_attribution_miss() {
        // C-NET-04
        let (v, stats) = run(
            &flow(Network::Tcp, "203.0.113.24:443", None),
            &InterceptSettings::default(),
        );
        assert_eq!(v, Verdict::Bypass(BypassReason::Unattributed));
        assert_eq!(stats.attribution_miss, 1);
        assert_eq!(stats.bypassed, 1);
    }

    #[test]
    fn quic_is_blocked_only_when_enabled() {
        let quic = flow(Network::Udp, "203.0.113.24:443", Some(GAME));
        let off = InterceptSettings::default();
        assert_eq!(run(&quic, &off).0, Verdict::Redirect { group: 2 });
        let on = InterceptSettings {
            block_quic: true,
            ..off
        };
        assert_eq!(run(&quic, &on).0, Verdict::Block);
        // TCP 443 不受影响
        let tcp = flow(Network::Tcp, "203.0.113.24:443", Some(GAME));
        assert_eq!(run(&tcp, &on).0, Verdict::Redirect { group: 2 });
    }

    #[test]
    fn udp_disabled_still_hijacks_dns_when_asked() {
        let s = InterceptSettings {
            udp_enabled: false,
            ..InterceptSettings::default()
        };
        let game_udp = flow(Network::Udp, "203.0.113.24:27015", Some(GAME));
        assert_eq!(
            run(&game_udp, &s).0,
            Verdict::Bypass(BypassReason::UdpDisabled)
        );
        let dns = flow(Network::Udp, "8.8.8.8:53", Some(GAME));
        assert_eq!(run(&dns, &s).0, Verdict::Redirect { group: 2 });
        let no_hijack = InterceptSettings {
            hijack_port53: false,
            ..s
        };
        assert_eq!(
            run(&dns, &no_hijack).0,
            Verdict::Bypass(BypassReason::UdpDisabled)
        );
    }

    #[test]
    fn unprocessable_packets_follow_fail_policy() {
        // C-NET-07：默认 block，绝不静默放行
        let counters = Counters::default();
        assert_eq!(unprocessable(FailPolicy::Block, &counters), Verdict::Block);
        assert_eq!(
            unprocessable(FailPolicy::Allow, &counters),
            Verdict::Bypass(BypassReason::FailOpen)
        );
        let s = counters.snapshot();
        assert_eq!((s.blocked, s.bypassed), (1, 1));
        assert_eq!(InterceptSettings::default().fail_policy, FailPolicy::Block);
    }

    #[test]
    fn emit_never_blocks_and_counts_drops() {
        let counters = Counters::default();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let key = flow(Network::Tcp, "203.0.113.24:443", None).key;
        emit(&tx, FlowEvent::Closed { key }, &counters);
        emit(&tx, FlowEvent::Closed { key }, &counters);
        assert_eq!(counters.snapshot().events_dropped, 1);
        drop(rx);
        emit(&tx, FlowEvent::Closed { key }, &counters);
        assert_eq!(counters.snapshot().events_dropped, 2);
    }
}
