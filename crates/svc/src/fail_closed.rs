// SPDX-License-Identifier: GPL-3.0-or-later
//! TUN 模式 + `fail_policy = block` 的阻断（C-NET-03，2026-10-29 定为服务持有的动态 WFP 过滤器）。
//!
//! 会话启动时、内核启动之前装好过滤器：sing-box 不在时目标进程的连接不经 TUN，被阻断而不是直连
//! （过滤规则见 `procroute-platform-win::wfp`）。保护对象是目标进程的可执行文件：
//!
//! - 完整路径规则直接给出；
//! - 名称、目录、通配、正则规则要看实际运行的进程：由 `procroute-procwatch` 追踪（T-079），启动时快照
//!   一遍，之后靠 ETW 进程事件（约 100 ms 延迟）补上新出现的命中进程；ETW 不可用时退回每 500 ms 一次快照。
//!   **已知窗口**：内核不在、且命中进程刚启动、事件还没送到的这段时间没有保护。
//!
//! 只保护自身命中规则的进程：TUN 模式按可执行文件分流，`include_children` 不生效，继承来的子进程本来就
//! 不经 TUN，也就不阻断。排除规则命中的进程不保护（与路由判定一致）。丢弃句柄即关闭 WFP 会话，
//! 过滤器随之消失（C-NET-06）。

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;

use procroute_core_mgr::config_gen::TUN_ADDRESSES;
use procroute_platform_win::wfp::{FailClosedFilters, TunRanges};
use procroute_procwatch::Change;
use procroute_procwatch::watcher::{Options, Watcher};
use procroute_proto::profile::{MatchType, Profile};
use procroute_rules::engine::RuleEngine;
use procroute_rules::path::normalize_path;

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

/// 正式实现：WFP 动态会话 + 进程追踪。
#[derive(Debug, Default)]
pub struct WfpGuard;

impl FailClosedGuard for WfpGuard {
    fn install(&self, profile: &Profile) -> Result<Box<dyn GuardHandle>, String> {
        let engine = RuleEngine::compile(profile).map_err(|e| e.to_string())?;
        let mut protector = Protector {
            filters: FailClosedFilters::open(tun_ranges()?).map_err(|e| e.to_string())?,
            protected: HashSet::new(),
        };
        for path in path_rules(profile) {
            protector.protect(&path);
        }
        // 第一次快照在 start 里同步完成：返回时已运行的命中进程都已保护
        let watcher = Watcher::start(engine, Options::default(), move |changes| {
            for change in changes {
                if let Change::Targeted {
                    inherited: false,
                    path: Some(path),
                    ..
                } = change
                {
                    protector.protect(path);
                }
            }
        })
        .map_err(|e| e.to_string())?;
        Ok(Box::new(Running { watcher }))
    }
}

struct Running {
    /// 持有过滤器；停止追踪时随回调一起丢弃。
    watcher: Watcher,
}

impl GuardHandle for Running {
    fn stop(self: Box<Self>) {
        self.watcher.stop();
    }
}

struct Protector {
    filters: FailClosedFilters,
    /// 已保护的可执行文件（规范化路径）。
    protected: HashSet<String>,
}

impl Protector {
    fn protect(&mut self, path: &str) {
        let key = normalize_path(path);
        if self.protected.contains(&key) {
            return;
        }
        let exe = Path::new(path)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match self.filters.protect(Path::new(path)) {
            Ok(()) => {
                tracing::debug!(exe = %exe, "fail-closed filters added");
                self.protected.insert(key);
            }
            // 文件不存在（规则里写的路径还没安装）等情况：之后进程真的运行时会被追踪补上
            Err(e) => tracing::debug!(exe = %exe, error = %e, "cannot protect executable"),
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
