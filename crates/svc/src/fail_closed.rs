// SPDX-License-Identifier: GPL-3.0-or-later
//! TUN 模式 + `fail_policy = block` 的阻断（C-NET-03，2026-10-29 定为服务持有的动态 WFP 过滤器）。
//!
//! 会话启动时、内核启动之前装好过滤器：sing-box 不在时目标进程的连接不经 TUN，被阻断而不是直连
//! （过滤规则见 `procroute-platform-win::wfp`）。保护对象是目标进程的可执行文件：
//!
//! - 完整路径规则直接给出；
//! - 名称、目录、通配、正则规则要看实际运行的进程：启动时扫一遍，之后每 [`RESCAN_INTERVAL`] 扫一次，
//!   新出现的命中进程补上。**已知窗口**：内核不在、且命中进程刚启动还没被扫到的这段时间（最多一个扫描
//!   间隔）没有保护；进程追踪（T-079，ETW）接入后可以消除。
//!
//! 排除规则命中的进程不保护（与路由判定一致）。丢弃句柄即关闭 WFP 会话，过滤器随之消失（C-NET-06）。

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use procroute_core_mgr::config_gen::TUN_ADDRESSES;
use procroute_platform_win::process::{list_processes, process_image_path};
use procroute_platform_win::wfp::{FailClosedFilters, TunRanges};
use procroute_proto::profile::{MatchType, Profile};
use procroute_rules::engine::RuleEngine;
use procroute_rules::matcher::NormalizedProcess;
use procroute_rules::path::normalize_path;

/// 补扫运行中进程的间隔。
pub const RESCAN_INTERVAL: Duration = Duration::from_millis(500);

/// 为方案安装阻断。
pub trait FailClosedGuard: Send + Sync + 'static {
    /// 装好过滤器并开始跟进新进程。阻塞调用，异步代码应经 `spawn_blocking` 调用。
    fn install(&self, profile: &Profile) -> Result<Box<dyn GuardHandle>, String>;
}

/// 已安装的阻断。
pub trait GuardHandle: Send {
    /// 撤销过滤器并等后台线程结束。阻塞调用。
    fn stop(self: Box<Self>);
}

/// 正式实现：WFP 动态会话。
#[derive(Debug, Default)]
pub struct WfpGuard;

impl FailClosedGuard for WfpGuard {
    fn install(&self, profile: &Profile) -> Result<Box<dyn GuardHandle>, String> {
        let engine = RuleEngine::compile(profile).map_err(|e| e.to_string())?;
        let filters = FailClosedFilters::open(tun_ranges()?).map_err(|e| e.to_string())?;
        let mut tracker = Tracker {
            engine,
            filters,
            protected: HashSet::new(),
            seen: HashSet::new(),
        };
        for path in path_rules(profile) {
            tracker.protect_if_target("", &path);
        }
        tracker.scan();
        let (stop, stopped) = mpsc::channel::<()>();
        let thread = std::thread::Builder::new()
            .name("fail-closed-rescan".to_owned())
            .spawn(move || {
                // 收到停止信号或发送端被丢弃都结束；过滤器随 `tracker` 一起丢弃
                while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(RESCAN_INTERVAL) {
                    tracker.scan();
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(Box::new(Running { stop, thread }))
    }
}

struct Running {
    stop: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

impl GuardHandle for Running {
    fn stop(self: Box<Self>) {
        let _ = self.stop.send(());
        let _ = self.thread.join();
    }
}

struct Tracker {
    engine: RuleEngine,
    filters: FailClosedFilters,
    /// 已保护的可执行文件（规范化路径）。
    protected: HashSet<String>,
    /// 已经判定过的进程（PID + 进程名），避免每轮都查路径。
    seen: HashSet<(u32, String)>,
}

impl Tracker {
    fn scan(&mut self) {
        let Ok(processes) = list_processes() else {
            return;
        };
        let current: HashSet<(u32, String)> =
            processes.iter().map(|p| (p.pid, p.name.clone())).collect();
        for p in &processes {
            let key = (p.pid, p.name.clone());
            if self.seen.contains(&key) {
                continue;
            }
            if let Ok(path) = process_image_path(p.pid) {
                self.protect_if_target(&p.name, &path);
            }
            self.seen.insert(key);
        }
        self.seen.retain(|k| current.contains(k));
    }

    /// 命中某个进程组（且没有被排除）的可执行文件装上过滤器。
    fn protect_if_target(&mut self, name: &str, path: &str) {
        let process = NormalizedProcess::new(name, path);
        if self.engine.decide(&process).group().is_none() {
            return;
        }
        let key = normalize_path(path);
        if self.protected.contains(&key) {
            return;
        }
        match self.filters.protect(Path::new(path)) {
            Ok(()) => {
                tracing::debug!(exe = %process.name, "fail-closed filters added");
                self.protected.insert(key);
            }
            // 文件不存在（规则里写的路径还没安装）等情况：之后进程真的运行时会被扫描补上
            Err(e) => tracing::debug!(exe = %process.name, error = %e, "cannot protect executable"),
        }
    }
}

/// 完整路径规则给出的可执行文件。
fn path_rules(profile: &Profile) -> Vec<String> {
    profile
        .groups
        .iter()
        .flat_map(|g| &g.matchers)
        .filter(|r| r.kind == MatchType::Path)
        .map(|r| r.value.clone())
        .collect()
}

/// TUN 网段，取自配置生成用的同一组常量。
fn tun_ranges() -> Result<TunRanges, String> {
    let [v4, v6] = TUN_ADDRESSES;
    Ok(TunRanges {
        v4: parse_cidr::<Ipv4Addr>(v4)?,
        v6: parse_cidr::<Ipv6Addr>(v6)?,
    })
}

fn parse_cidr<A: std::str::FromStr>(s: &str) -> Result<(A, u8), String> {
    let (addr, len) = s.split_once('/').ok_or_else(|| format!("bad CIDR {s}"))?;
    let addr = addr.parse().map_err(|_| format!("bad CIDR {s}"))?;
    let len = len.parse().map_err(|_| format!("bad CIDR {s}"))?;
    Ok((addr, len))
}

#[cfg(test)]
mod tests {
    use procroute_proto::profile::{
        DnsSettings, FailPolicy, Group, MatchRule, Mode, PROFILE_SCHEMA_VERSION, UdpSettings,
    };

    use super::*;

    #[test]
    fn tun_ranges_match_the_generated_tun_addresses() {
        let r = tun_ranges().expect("ranges");
        assert_eq!(r.v4, (Ipv4Addr::new(198, 18, 0, 1), 30));
        assert_eq!(r.v6.1, 126);
    }

    #[test]
    fn path_rules_are_collected_from_every_group() {
        let rule = |kind, value: &str| MatchRule {
            kind,
            value: value.into(),
            recursive: false,
        };
        let p = Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: "p".into(),
            name: "p".into(),
            mode: Mode::Tun,
            fail_policy: FailPolicy::Block,
            dns: DnsSettings::default(),
            udp: UdpSettings::default(),
            groups: vec![
                Group {
                    tag: "a".into(),
                    outbound: "o".into(),
                    include_children: false,
                    matchers: vec![
                        rule(MatchType::Path, r"C:\Games\a.exe"),
                        rule(MatchType::Name, "b.exe"),
                    ],
                },
                Group {
                    tag: "c".into(),
                    outbound: "o".into(),
                    include_children: false,
                    matchers: vec![rule(MatchType::Path, r"D:\c.exe")],
                },
            ],
            exclude: vec![rule(MatchType::Path, r"C:\Games\updater.exe")],
        };
        assert_eq!(path_rules(&p), [r"C:\Games\a.exe", r"D:\c.exe"]);
    }
}
