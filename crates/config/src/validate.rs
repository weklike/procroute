// SPDX-License-Identifier: GPL-3.0-or-later
//! 方案校验（T-021）。
//!
//! 一次返回全部问题，而不是遇到第一个就停，方便界面把错误标到对应字段上。
//! 规则能否编译直接复用 `procroute-rules` 的编译器，保证「校验通过」与「引擎能用」一致。

use std::collections::HashSet;

use procroute_proto::error::{ErrorCode, FieldIssue, FieldIssueCode, IpcError};
use procroute_proto::profile::{MatchRule, PROFILE_SCHEMA_VERSION, Profile};
use procroute_rules::matcher::{Matcher, RuleError};
use thiserror::Error;

use crate::dns::{DnsServerError, parse_remote};

pub const MAX_ID_LEN: usize = 64;
pub const MAX_NAME_LEN: usize = 64;
pub const MAX_TAG_LEN: usize = 32;
pub const MAX_OUTBOUND_LEN: usize = 64;
pub const MAX_GROUPS: usize = 64;
pub const MAX_RULES_PER_LIST: usize = 256;

/// 一个校验问题。`path` 指向出问题的字段，例如 `groups[1].match[0].value`。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{path}: {kind}")]
pub struct ValidationIssue {
    pub path: String,
    pub kind: IssueKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IssueKind {
    #[error("schema_version 应为 {expected}，实际为 {found}")]
    SchemaVersion { expected: u32, found: u32 },
    #[error("不能为空")]
    Empty,
    #[error("过长：{len} 个字符，上限 {max}")]
    TooLong { len: usize, max: usize },
    #[error("数量过多：{count} 项，上限 {max}")]
    TooMany { count: usize, max: usize },
    #[error("只能包含字母、数字、- 和 _")]
    InvalidId,
    #[error("组标签只能包含小写字母、数字、- 和 _")]
    InvalidTag,
    #[error("不能包含控制字符")]
    ControlChar,
    #[error("组标签重复：{0}")]
    DuplicateTag(String),
    #[error("进程组至少需要一条匹配规则")]
    NoMatchers,
    #[error("DNS 服务器地址无效：{0}")]
    DnsServer(DnsServerError),
    #[error(transparent)]
    Rule(#[from] RuleError),
}

impl IssueKind {
    /// 对应的 IPC 字段问题码。
    pub fn code(&self) -> FieldIssueCode {
        match self {
            IssueKind::SchemaVersion { .. } => FieldIssueCode::SchemaVersion,
            IssueKind::Empty => FieldIssueCode::Empty,
            IssueKind::TooLong { .. } => FieldIssueCode::TooLong,
            IssueKind::TooMany { .. } => FieldIssueCode::TooMany,
            IssueKind::InvalidId => FieldIssueCode::InvalidId,
            IssueKind::InvalidTag => FieldIssueCode::InvalidTag,
            IssueKind::ControlChar => FieldIssueCode::ControlChar,
            IssueKind::DuplicateTag(_) => FieldIssueCode::DuplicateTag,
            IssueKind::NoMatchers => FieldIssueCode::NoMatchers,
            IssueKind::DnsServer(_) => FieldIssueCode::InvalidDnsServer,
            IssueKind::Rule(_) => FieldIssueCode::InvalidRule,
        }
    }
}

/// 把校验问题转成 `profile.invalid_schema` 错误，界面据此把问题标到对应字段上。
pub fn to_ipc_error(issues: &[ValidationIssue]) -> IpcError {
    let fields = issues
        .iter()
        .map(|i| FieldIssue {
            path: i.path.clone(),
            code: i.kind.code(),
            message: i.kind.to_string(),
        })
        .collect();
    IpcError::new(
        ErrorCode::ProfileInvalidSchema,
        format!("{} 个字段未通过校验", issues.len()),
    )
    .with_fields(fields)
}

/// 校验整个方案；没有问题时返回 `Ok(())`。
pub fn validate(p: &Profile) -> Result<(), Vec<ValidationIssue>> {
    let mut issues = Vec::new();
    let mut push = |path: String, kind: IssueKind| issues.push(ValidationIssue { path, kind });

    if p.schema_version != PROFILE_SCHEMA_VERSION {
        push(
            "schema_version".into(),
            IssueKind::SchemaVersion {
                expected: PROFILE_SCHEMA_VERSION,
                found: p.schema_version,
            },
        );
    }
    if let Some(kind) =
        check_text(&p.id, MAX_ID_LEN).or_else(|| (!is_id(&p.id)).then_some(IssueKind::InvalidId))
    {
        push("id".into(), kind);
    }
    if let Some(kind) = check_text(&p.name, MAX_NAME_LEN) {
        push("name".into(), kind);
    }

    if p.groups.len() > MAX_GROUPS {
        push(
            "groups".into(),
            IssueKind::TooMany {
                count: p.groups.len(),
                max: MAX_GROUPS,
            },
        );
    }
    let mut tags = HashSet::new();
    for (gi, g) in p.groups.iter().enumerate() {
        let base = format!("groups[{gi}]");
        match check_text(&g.tag, MAX_TAG_LEN) {
            Some(kind) => push(format!("{base}.tag"), kind),
            None if !is_tag(&g.tag) => push(format!("{base}.tag"), IssueKind::InvalidTag),
            None if !tags.insert(g.tag.as_str()) => {
                push(
                    format!("{base}.tag"),
                    IssueKind::DuplicateTag(g.tag.clone()),
                );
            }
            None => {}
        }
        if let Some(kind) = check_text(&g.outbound, MAX_OUTBOUND_LEN) {
            push(format!("{base}.outbound"), kind);
        }
        if g.matchers.is_empty() {
            push(format!("{base}.match"), IssueKind::NoMatchers);
        }
        check_rules(&g.matchers, &format!("{base}.match"), &mut push);
    }
    check_rules(&p.exclude, "exclude", &mut push);
    if let Some(server) = &p.dns.remote_server
        && let Err(e) = parse_remote(server)
    {
        push("dns.remote_server".into(), IssueKind::DnsServer(e));
    }

    if issues.is_empty() {
        Ok(())
    } else {
        Err(issues)
    }
}

fn check_rules(rules: &[MatchRule], base: &str, push: &mut impl FnMut(String, IssueKind)) {
    if rules.len() > MAX_RULES_PER_LIST {
        push(
            base.to_owned(),
            IssueKind::TooMany {
                count: rules.len(),
                max: MAX_RULES_PER_LIST,
            },
        );
    }
    for (i, r) in rules.iter().enumerate() {
        if let Err(e) = Matcher::compile(r) {
            push(format!("{base}[{i}].value"), IssueKind::Rule(e));
        }
    }
}

/// 非空、不超长、不含控制字符。
fn check_text(s: &str, max: usize) -> Option<IssueKind> {
    if s.trim().is_empty() {
        return Some(IssueKind::Empty);
    }
    let len = s.chars().count();
    if len > max {
        return Some(IssueKind::TooLong { len, max });
    }
    if s.chars().any(char::is_control) {
        return Some(IssueKind::ControlChar);
    }
    None
}

fn is_id(s: &str) -> bool {
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// 组标签同时用作本地 SOCKS 用户名，只允许小写 ASCII 字母、数字、`-`、`_`。
pub fn is_tag(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use procroute_proto::profile::{DnsSettings, FailPolicy, Group, MatchType, Mode, UdpSettings};
    use proptest::prelude::*;

    use super::*;

    fn rule(kind: MatchType, value: &str) -> MatchRule {
        MatchRule {
            kind,
            value: value.into(),
            recursive: false,
        }
    }

    fn valid() -> Profile {
        Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: "01JBX7Q3K2M8T5W9Y4C6N0R1PZ".into(),
            name: "游戏加速".into(),
            mode: Mode::Precise,
            fail_policy: FailPolicy::Block,
            dns: DnsSettings::default(),
            udp: UdpSettings::default(),
            groups: vec![Group {
                tag: "game".into(),
                outbound: "hk-auto".into(),
                include_children: true,
                matchers: vec![rule(MatchType::Name, "launcher.exe")],
            }],
            exclude: vec![rule(MatchType::Name, "updater.exe")],
        }
    }

    fn paths(p: &Profile) -> Vec<String> {
        validate(p)
            .unwrap_err()
            .into_iter()
            .map(|i| i.path)
            .collect()
    }

    #[test]
    fn a_valid_profile_passes() {
        assert_eq!(validate(&valid()), Ok(()));
    }

    #[test]
    fn reports_every_problem_with_its_field() {
        let mut p = valid();
        p.name = " ".into();
        p.groups[0].matchers.push(rule(MatchType::Regex, "("));
        p.groups.push(Group {
            tag: "game".into(),
            outbound: String::new(),
            include_children: true,
            matchers: vec![],
        });
        p.exclude.push(rule(MatchType::Glob, "a["));
        assert_eq!(
            paths(&p),
            vec![
                "name",
                "groups[0].match[1].value",
                "groups[1].tag",
                "groups[1].outbound",
                "groups[1].match",
                "exclude[1].value",
            ]
        );
    }

    #[test]
    fn issues_convert_to_an_ipc_error_with_field_codes() {
        let mut p = valid();
        p.name = String::new();
        p.groups.push(p.groups[0].clone());
        let issues = validate(&p).unwrap_err();
        let e = to_ipc_error(&issues);
        assert_eq!(e.code, ErrorCode::ProfileInvalidSchema);
        let fields = e.fields.unwrap();
        assert!(
            fields
                .iter()
                .any(|f| f.path == "name" && f.code == FieldIssueCode::Empty)
        );
        assert!(
            fields
                .iter()
                .any(|f| f.path == "groups[1].tag" && f.code == FieldIssueCode::DuplicateTag)
        );
    }

    #[test]
    fn duplicate_tags_are_reported() {
        let mut p = valid();
        p.groups.push(p.groups[0].clone());
        let issues = validate(&p).unwrap_err();
        assert_eq!(issues[0].kind, IssueKind::DuplicateTag("game".into()));
    }

    #[test]
    fn remote_dns_servers_are_checked() {
        let mut p = valid();
        p.dns.remote_server = Some("tls://198.51.100.53:853".into());
        assert_eq!(validate(&p), Ok(()));
        p.dns.remote_server = Some("quic://dns.example".into());
        let issues = validate(&p).unwrap_err();
        assert_eq!(issues[0].path, "dns.remote_server");
        assert_eq!(issues[0].kind.code(), FieldIssueCode::InvalidDnsServer);
        p.dns.remote_server = Some(String::new());
        assert_eq!(paths(&p), vec!["dns.remote_server"]);
    }

    #[test]
    fn wrong_schema_version_is_reported() {
        let mut p = valid();
        p.schema_version = 99;
        assert_eq!(paths(&p), vec!["schema_version"]);
    }

    #[test]
    fn rejects_bad_ids_and_control_chars() {
        let mut p = valid();
        p.id = "a b".into();
        p.groups[0].outbound = "hk\u{0}".into();
        assert_eq!(paths(&p), vec!["id", "groups[0].outbound"]);
    }

    proptest! {
        #[test]
        fn lowercase_ascii_tags_are_accepted(tag in "[a-z0-9_-]{1,32}") {
            prop_assert!(is_tag(&tag));
            let mut p = valid();
            p.groups[0].tag = tag;
            prop_assert_eq!(validate(&p), Ok(()));
        }

        #[test]
        fn tags_with_other_characters_are_rejected(
            prefix in "[a-z]{0,4}",
            bad in "[A-Z :/@\u{4e00}-\u{4e10}]",
            suffix in "[a-z]{0,4}",
        ) {
            let tag = format!("{prefix}{bad}{suffix}");
            prop_assert!(!is_tag(&tag));
        }
    }
}
