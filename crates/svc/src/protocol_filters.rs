// SPDX-License-Identifier: GPL-3.0-or-later
//! 拦截层管不到的协议：会话期间由服务持有的动态 WFP 过滤器（规则见 `procroute-platform-win::wfp`）。
//!
//! 拦截层只改道 TCP 与 UDP，其他协议从拦截层旁边直接发出去。这里分两件事：
//!
//! - **目标进程的其他协议**（精确模式 + `block`，C-NET-07）：原始套接字发的 ICMP 等按可执行文件挡住。TUN 模式由
//!   TUN 入站和 [`crate::fail_closed`] 负责；`allow` 是用户显式选择的放行，不挡。完整路径规则在会话启动时就装好；
//!   名称、目录、通配、正则规则和继承来的子进程要等进程追踪报到（约 100 ms），这段时间没有保护，与 TUN 的
//!   fail-closed 是同一个已知窗口。按可执行文件而不是进程判定，所以同一个文件的非目标进程也一起挡了，
//!   进程退出后也不撤销，直到会话结束。这只影响用原始套接字的程序。
//! - **全局 ping 阻断**（`icmp.block_all_ping`，用户选择，C-NET-02 的例外，docs/adr/0003）：系统 ping 接口发的包
//!   在过滤层的进程是 System，分不出是谁发的，只能全部一起挡。
//!
//! 过滤器装不上就不启动会话：用户要求的保护不能悄悄失效。丢弃句柄即关闭 WFP 会话，过滤器随之消失（C-NET-06）。

use std::collections::HashSet;
use std::path::Path;

use procroute_platform_win::wfp::ProtocolFilters;
use procroute_proto::profile::{FailPolicy, Mode, Profile};
use procroute_rules::engine::RuleEngine;
use procroute_rules::matcher::NormalizedProcess;

use crate::fail_closed::{apply_once, path_rules};

/// 一个方案要装哪些过滤器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Plan {
    /// 挡住目标进程 TCP、UDP 以外的协议。
    pub block_targets: bool,
    /// 挡住所有进程发往外部的回显请求。
    pub block_all_ping: bool,
}

impl Plan {
    pub fn for_profile(p: &Profile) -> Self {
        Self {
            block_targets: p.mode == Mode::Precise && p.fail_policy == FailPolicy::Block,
            block_all_ping: p.icmp.block_all_ping,
        }
    }

    pub fn is_empty(self) -> bool {
        !self.block_targets && !self.block_all_ping
    }
}

/// 打开一组过滤器。
pub trait ProtocolGuard: Send + Sync + 'static {
    /// `block_all_ping` 时立即挡住 ping。阻塞调用，异步代码应经 `spawn_blocking` 调用。
    fn open(&self, block_all_ping: bool) -> Result<Box<dyn ProtocolHandle>, String>;
}

/// 打开着的过滤器。丢弃时全部撤销，可能短暂阻塞。
pub trait ProtocolHandle: Send {
    /// 挡住这个目标可执行文件的其他协议。挡过的不重复加；加不上（文件不存在等）只记日志，进程真的运行时
    /// 进程追踪会再报一次。阻塞调用。
    fn block_target(&mut self, path: &str);
}

/// 正式实现：WFP 动态会话。
#[derive(Debug, Default)]
pub struct WfpProtocolGuard;

impl ProtocolGuard for WfpProtocolGuard {
    fn open(&self, block_all_ping: bool) -> Result<Box<dyn ProtocolHandle>, String> {
        let mut filters = ProtocolFilters::open().map_err(|e| e.to_string())?;
        if block_all_ping {
            filters.block_ping().map_err(|e| e.to_string())?;
            tracing::info!("blocking ping from every process for this session");
        }
        Ok(Box::new(Open {
            filters,
            blocked: HashSet::new(),
        }))
    }
}

struct Open {
    filters: ProtocolFilters,
    /// 已经挡过的可执行文件（规范化路径）。
    blocked: HashSet<String>,
}

impl ProtocolHandle for Open {
    fn block_target(&mut self, path: &str) {
        let Self { filters, blocked } = self;
        apply_once(blocked, path, |exe: &Path| {
            filters.block_other_protocols(exe)
        });
    }
}

/// 完整路径规则给出、按规则确实是目标的可执行文件（同一路径也可能被排除规则命中）。
pub fn target_path_rules(profile: &Profile, engine: &RuleEngine) -> Vec<String> {
    path_rules(profile)
        .into_iter()
        .filter(|path| {
            engine
                .decide(&NormalizedProcess::new("", path))
                .group()
                .is_some()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use procroute_proto::profile::{Group, MatchRule, MatchType, PROFILE_SCHEMA_VERSION};

    use super::*;

    fn rule(kind: MatchType, value: &str) -> MatchRule {
        MatchRule {
            kind,
            value: value.into(),
            recursive: false,
        }
    }

    fn profile(mode: Mode, fail_policy: FailPolicy, block_all_ping: bool) -> Profile {
        Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: "p".into(),
            name: "p".into(),
            mode,
            fail_policy,
            dns: Default::default(),
            udp: Default::default(),
            icmp: procroute_proto::profile::IcmpSettings { block_all_ping },
            groups: vec![Group {
                tag: "g".into(),
                outbound: "o".into(),
                include_children: true,
                matchers: vec![
                    rule(MatchType::Path, r"C:\Games\a.exe"),
                    rule(MatchType::Path, r"C:\Games\updater.exe"),
                    rule(MatchType::Name, "b.exe"),
                ],
            }],
            exclude: vec![rule(MatchType::Path, r"C:\Games\updater.exe")],
        }
    }

    #[test]
    fn only_precise_block_sessions_block_the_targets_other_protocols() {
        let plan = |mode, policy| Plan::for_profile(&profile(mode, policy, false));
        assert!(plan(Mode::Precise, FailPolicy::Block).block_targets);
        // `allow` 是用户选择的放行（C-NET-07）；TUN 模式不经过这里
        assert!(plan(Mode::Precise, FailPolicy::Allow).is_empty());
        assert!(plan(Mode::Tun, FailPolicy::Block).is_empty());
        assert!(plan(Mode::Tun, FailPolicy::Allow).is_empty());
    }

    #[test]
    fn blocking_all_ping_is_the_users_choice_and_ignores_the_fail_policy() {
        for mode in [Mode::Precise, Mode::Tun] {
            for policy in [FailPolicy::Block, FailPolicy::Allow] {
                assert!(Plan::for_profile(&profile(mode, policy, true)).block_all_ping);
                assert!(!Plan::for_profile(&profile(mode, policy, false)).block_all_ping);
            }
        }
    }

    #[test]
    fn excluded_paths_are_not_targets() {
        let p = profile(Mode::Precise, FailPolicy::Block, false);
        let engine = RuleEngine::compile(&p).expect("compile");
        assert_eq!(target_path_rules(&p, &engine), [r"C:\Games\a.exe"]);
    }
}
