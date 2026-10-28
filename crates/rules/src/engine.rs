// SPDX-License-Identifier: GPL-3.0-or-later
//! 规则引擎：判定一个进程走哪个进程组（T-032）。
//!
//! 优先级（设计文档 6.4）：排除 > 完整路径 > 目录 > 进程名 > 通配符 / 正则。
//! 同一优先级内按进程组在方案里的顺序取第一个命中的组。

use std::fmt;

use procroute_proto::profile::{MatchType, Profile};
use thiserror::Error;

use crate::matcher::{Matcher, NormalizedProcess, RuleError};

/// 各优先级包含的规则类型，从高到低。
const PRECEDENCE: [&[MatchType]; 4] = [
    &[MatchType::Path],
    &[MatchType::Dir],
    &[MatchType::Name],
    &[MatchType::Glob, MatchType::Regex],
];

/// 判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// 没有命中任何组：不改道。
    Direct,
    /// 命中排除规则：不改道，且子进程也不会继承。
    Excluded,
    /// 命中第 n 个进程组。
    Group(usize),
}

impl Decision {
    pub fn group(self) -> Option<usize> {
        match self {
            Decision::Group(i) => Some(i),
            _ => None,
        }
    }
}

/// 规则在方案中的位置，用于定位错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleLocation {
    Exclude { index: usize },
    Group { group: usize, index: usize },
}

impl fmt::Display for RuleLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleLocation::Exclude { index } => write!(f, "exclude[{index}]"),
            RuleLocation::Group { group, index } => write!(f, "groups[{group}].match[{index}]"),
        }
    }
}

/// 编译方案时遇到的第一个无效规则。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{location}: {source}")]
pub struct CompileError {
    pub location: RuleLocation,
    #[source]
    pub source: RuleError,
}

/// 编译好的进程组。
#[derive(Debug, Clone)]
pub struct CompiledGroup {
    pub tag: String,
    pub outbound: String,
    pub include_children: bool,
    matchers: Vec<Matcher>,
}

/// 由一个方案编译出的引擎。
#[derive(Debug, Clone)]
pub struct RuleEngine {
    exclude: Vec<Matcher>,
    groups: Vec<CompiledGroup>,
}

impl RuleEngine {
    pub fn compile(profile: &Profile) -> Result<Self, CompileError> {
        let exclude = profile
            .exclude
            .iter()
            .enumerate()
            .map(|(index, r)| {
                Matcher::compile(r).map_err(|source| CompileError {
                    location: RuleLocation::Exclude { index },
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut groups = Vec::with_capacity(profile.groups.len());
        for (gi, g) in profile.groups.iter().enumerate() {
            let matchers = g
                .matchers
                .iter()
                .enumerate()
                .map(|(index, r)| {
                    Matcher::compile(r).map_err(|source| CompileError {
                        location: RuleLocation::Group { group: gi, index },
                        source,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            groups.push(CompiledGroup {
                tag: g.tag.clone(),
                outbound: g.outbound.clone(),
                include_children: g.include_children,
                matchers,
            });
        }
        Ok(Self { exclude, groups })
    }

    /// 只看进程自身的判定（不考虑父进程）。
    pub fn decide(&self, p: &NormalizedProcess) -> Decision {
        if self.exclude.iter().any(|m| m.matches(p)) {
            return Decision::Excluded;
        }
        for tier in PRECEDENCE {
            for (gi, g) in self.groups.iter().enumerate() {
                if g.matchers
                    .iter()
                    .any(|m| tier.contains(&m.kind()) && m.matches(p))
                {
                    return Decision::Group(gi);
                }
            }
        }
        Decision::Direct
    }

    pub fn groups(&self) -> &[CompiledGroup] {
        &self.groups
    }

    pub fn group(&self, index: usize) -> Option<&CompiledGroup> {
        self.groups.get(index)
    }
}

#[cfg(test)]
mod tests {
    use procroute_proto::profile::{
        DnsSettings, FailPolicy, Group, MatchRule, Mode, PROFILE_SCHEMA_VERSION, UdpSettings,
    };
    use proptest::prelude::*;

    use super::*;

    fn r(kind: MatchType, value: &str) -> MatchRule {
        MatchRule {
            kind,
            value: value.into(),
            recursive: kind == MatchType::Dir,
        }
    }

    fn group(tag: &str, matchers: Vec<MatchRule>) -> Group {
        Group {
            tag: tag.into(),
            outbound: format!("{tag}-out"),
            include_children: true,
            matchers,
        }
    }

    fn profile(groups: Vec<Group>, exclude: Vec<MatchRule>) -> Profile {
        Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: "p".into(),
            name: "test".into(),
            mode: Mode::Precise,
            fail_policy: FailPolicy::Block,
            dns: DnsSettings::default(),
            udp: UdpSettings::default(),
            groups,
            exclude,
        }
    }

    fn decide(p: &Profile, path: &str) -> Decision {
        RuleEngine::compile(p)
            .unwrap()
            .decide(&NormalizedProcess::new("", path))
    }

    #[test]
    fn unmatched_process_goes_direct() {
        let p = profile(
            vec![group("game", vec![r(MatchType::Name, "game.exe")])],
            vec![],
        );
        assert_eq!(decide(&p, r"C:\x\other.exe"), Decision::Direct);
    }

    #[test]
    fn exclusion_beats_every_group_rule() {
        let p = profile(
            vec![group("game", vec![r(MatchType::Dir, r"D:\Games")])],
            vec![r(MatchType::Name, "updater.exe")],
        );
        assert_eq!(
            decide(&p, r"D:\Games\MyGame\updater.exe"),
            Decision::Excluded
        );
        assert_eq!(
            decide(&p, r"D:\Games\MyGame\MyGame.exe"),
            Decision::Group(0)
        );
    }

    #[test]
    fn precedence_is_path_then_dir_then_name_then_pattern() {
        let p = profile(
            vec![
                group("by-glob", vec![r(MatchType::Glob, r"D:\**\*.exe")]),
                group("by-name", vec![r(MatchType::Name, "mygame.exe")]),
                group("by-dir", vec![r(MatchType::Dir, r"D:\Games")]),
                group(
                    "by-path",
                    vec![r(MatchType::Path, r"D:\Games\MyGame\MyGame.exe")],
                ),
            ],
            vec![],
        );
        assert_eq!(
            decide(&p, r"D:\Games\MyGame\MyGame.exe"),
            Decision::Group(3)
        );
        assert_eq!(decide(&p, r"D:\Games\Other\MyGame.exe"), Decision::Group(2));
        assert_eq!(decide(&p, r"D:\Tools\MyGame.exe"), Decision::Group(1));
        assert_eq!(decide(&p, r"D:\Tools\x.exe"), Decision::Group(0));
    }

    #[test]
    fn earlier_group_wins_within_the_same_tier() {
        let p = profile(
            vec![
                group("a", vec![r(MatchType::Name, "x.exe")]),
                group("b", vec![r(MatchType::Name, "x.exe")]),
            ],
            vec![],
        );
        assert_eq!(decide(&p, r"C:\x.exe"), Decision::Group(0));
    }

    #[test]
    fn compile_error_points_at_the_rule() {
        let p = profile(
            vec![group(
                "a",
                vec![r(MatchType::Name, "ok.exe"), r(MatchType::Regex, "(")],
            )],
            vec![],
        );
        let err = RuleEngine::compile(&p).unwrap_err();
        assert_eq!(err.location, RuleLocation::Group { group: 0, index: 1 });
        assert_eq!(err.location.to_string(), "groups[0].match[1]");
    }

    proptest! {
        #[test]
        fn excluded_process_is_never_proxied(stem in "[a-z0-9_]{1,12}", dir in "[a-z]{1,8}") {
            let name = format!("{stem}.exe");
            let path = format!(r"C:\{dir}\{name}");
            let p = profile(
                vec![
                    group("by-name", vec![r(MatchType::Name, &name)]),
                    group("by-path", vec![r(MatchType::Path, &path)]),
                    group("by-dir", vec![r(MatchType::Dir, &format!(r"C:\{dir}"))]),
                    group("by-glob", vec![r(MatchType::Glob, r"C:\**")]),
                ],
                vec![r(MatchType::Name, &name)],
            );
            prop_assert_eq!(decide(&p, &path), Decision::Excluded);
        }
    }
}
