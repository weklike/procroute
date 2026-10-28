// SPDX-License-Identifier: GPL-3.0-or-later
//! 子进程继承判定（T-033，F7）。
//!
//! 子进程自身命中规则时按自身判定（排除依然最优先）；否则在父进程属于某组、
//! 该组开启 `include_children`、且父进程确实早于子进程创建时继承父进程的组。
//! 最后一个条件用于防止 PID 复用：记录里的「父 PID」若属于更晚创建的进程，
//! 说明真正的父进程已经退出、PID 被复用了（C-DRV-04）。

use crate::engine::{Decision, RuleEngine};
use crate::matcher::NormalizedProcess;

/// 父进程的判定与创建时间。时间单位由调用方决定，只要单调可比即可。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentInfo {
    pub decision: Decision,
    pub created_at: u64,
}

/// 只回答「是否继承」这一个问题。
pub fn should_inherit(
    parent_decision: Decision,
    group_include_children: bool,
    parent_created_at: u64,
    child_created_at: u64,
) -> bool {
    matches!(parent_decision, Decision::Group(_))
        && group_include_children
        && parent_created_at <= child_created_at
}

/// 子进程的最终判定。
pub fn decide_child(
    engine: &RuleEngine,
    child: &NormalizedProcess,
    child_created_at: u64,
    parent: Option<ParentInfo>,
) -> Decision {
    let own = engine.decide(child);
    if own != Decision::Direct {
        return own;
    }
    let Some(parent) = parent else {
        return Decision::Direct;
    };
    let Some(index) = parent.decision.group() else {
        return Decision::Direct;
    };
    let include_children = engine
        .group(index)
        .map(|g| g.include_children)
        .unwrap_or(false);
    if should_inherit(
        parent.decision,
        include_children,
        parent.created_at,
        child_created_at,
    ) {
        Decision::Group(index)
    } else {
        Decision::Direct
    }
}

#[cfg(test)]
mod tests {
    use procroute_proto::profile::{
        DnsSettings, FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION,
        Profile, UdpSettings,
    };

    use super::*;

    fn engine(include_children: bool) -> RuleEngine {
        let p = Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: "p".into(),
            name: "t".into(),
            mode: Mode::Precise,
            fail_policy: FailPolicy::Block,
            dns: DnsSettings::default(),
            udp: UdpSettings::default(),
            groups: vec![Group {
                tag: "game".into(),
                outbound: "hk-auto".into(),
                include_children,
                matchers: vec![MatchRule {
                    kind: MatchType::Name,
                    value: "mygame.exe".into(),
                    recursive: false,
                }],
            }],
            exclude: vec![MatchRule {
                kind: MatchType::Name,
                value: "updater.exe".into(),
                recursive: false,
            }],
        };
        RuleEngine::compile(&p).unwrap()
    }

    fn child(name: &str) -> NormalizedProcess {
        NormalizedProcess::new("", &format!(r"C:\tmp\{name}"))
    }

    const IN_GAME: ParentInfo = ParentInfo {
        decision: Decision::Group(0),
        created_at: 100,
    };

    #[test]
    fn child_inherits_when_enabled_and_parent_is_older() {
        let e = engine(true);
        assert_eq!(
            decide_child(&e, &child("crash.exe"), 200, Some(IN_GAME)),
            Decision::Group(0)
        );
    }

    #[test]
    fn no_inheritance_when_group_disables_it() {
        let e = engine(false);
        assert_eq!(
            decide_child(&e, &child("crash.exe"), 200, Some(IN_GAME)),
            Decision::Direct
        );
    }

    #[test]
    fn reused_parent_pid_does_not_leak_group() {
        // 「父进程」比子进程还晚创建：PID 被复用了
        let e = engine(true);
        let reused = ParentInfo {
            decision: Decision::Group(0),
            created_at: 300,
        };
        assert_eq!(
            decide_child(&e, &child("crash.exe"), 200, Some(reused)),
            Decision::Direct
        );
    }

    #[test]
    fn exclusion_still_wins_for_children() {
        let e = engine(true);
        assert_eq!(
            decide_child(&e, &child("updater.exe"), 200, Some(IN_GAME)),
            Decision::Excluded
        );
    }

    #[test]
    fn excluded_or_direct_parent_passes_nothing_down() {
        let e = engine(true);
        for decision in [Decision::Excluded, Decision::Direct] {
            let parent = ParentInfo {
                decision,
                created_at: 100,
            };
            assert_eq!(
                decide_child(&e, &child("crash.exe"), 200, Some(parent)),
                Decision::Direct
            );
        }
        assert_eq!(
            decide_child(&e, &child("crash.exe"), 200, None),
            Decision::Direct
        );
    }

    #[test]
    fn should_inherit_truth_table() {
        assert!(should_inherit(Decision::Group(0), true, 1, 2));
        assert!(should_inherit(Decision::Group(0), true, 2, 2));
        assert!(!should_inherit(Decision::Group(0), true, 3, 2));
        assert!(!should_inherit(Decision::Group(0), false, 1, 2));
        assert!(!should_inherit(Decision::Direct, true, 1, 2));
        assert!(!should_inherit(Decision::Excluded, true, 1, 2));
    }
}
