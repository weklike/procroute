// SPDX-License-Identifier: GPL-3.0-or-later
//! 诊断包的测试：存储放在临时目录，日志是手写的文件。

use std::path::Path;

use procroute_core_mgr::node::Tls;
use procroute_platform_win::secret::Secret;
use procroute_proto::node::NodeProtocol;
use procroute_proto::profile::{Group, MatchType};
use procroute_proto::session::SessionState;

use super::*;
use crate::node_store::StoredSubscription;
use crate::node_store::tests::trojan;
use crate::store::tests::sample;

/// 测试数据里的敏感文本：任何一个出现在导出结果里都算泄漏。
const PASSWORD: &str = "hunter2-very-secret";
const SHORT_USERNAME: &str = "bob";
const SNI: &str = "sni.example.com";
const SUB_URL: &str = "https://sub.example.org/api/v1?token=tok-abcdef";
const DNS_ACCOUNT: &str = "https://dns.example/abc123";
const LEAKS: &[&str] = &[
    "tj.example.com",
    SNI,
    PASSWORD,
    "sub.example.org",
    "tok-abcdef",
    "abc123",
    "dns.example",
    "203.0.113.7",
    "alice",
    "节点",
    "我的订阅",
];

struct Fixture {
    dir: PathBuf,
    profiles: ProfileStore,
    nodes: NodeStore,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("procroute-diag-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Fixture {
        profiles: ProfileStore::open(dir.join("profiles")).expect("profiles"),
        nodes: NodeStore::open(dir.join("nodes.json")).expect("nodes"),
        dir,
    }
}

impl Fixture {
    fn collect(&self, sources: &DiagSources) -> DiagReport {
        let session = SessionStatus {
            state: SessionState::Running,
            ..SessionStatus::default()
        };
        collect(
            &self.profiles,
            &self.nodes,
            sources,
            session,
            1_700_000_000_000,
        )
    }

    fn write_log(&self, text: &str) -> PathBuf {
        let path = self.dir.join("svc.log");
        std::fs::write(&path, text).expect("log");
        path
    }

    /// 两个节点（一个来自订阅）、一个订阅、一个方案：进程组引用其中一个节点和一个不存在的出站。
    fn populate(&self) {
        let mut direct = trojan("n1", PASSWORD);
        if let Some(tls) = tls_mut(&mut direct.node.settings) {
            tls.server_name = Some(SNI.into());
        }
        let mut subscribed = trojan("n2", "another-long-password");
        subscribed.subscription_id = Some("s1".into());
        subscribed.credentials.username = Some(Secret::new(SHORT_USERNAME.into()));
        self.nodes
            .update_all(|d| {
                d.nodes = vec![direct, subscribed];
                d.subscriptions = vec![StoredSubscription {
                    id: "s1".into(),
                    name: "我的订阅".into(),
                    url: Secret::new(SUB_URL.into()),
                    updated_at_ms: Some(1),
                }];
            })
            .expect("nodes");

        let mut p = sample("p1", "游戏加速");
        p.groups[0].outbound = "n1".into();
        p.groups[0].matchers.push(MatchRule {
            kind: MatchType::Path,
            value: r"C:\Users\alice\Games\a.exe".into(),
            recursive: false,
        });
        p.groups.push(Group {
            tag: "other".into(),
            outbound: "gone".into(),
            include_children: false,
            matchers: vec![MatchRule {
                kind: MatchType::Glob,
                value: r"C:\Users\*\Tools\*.exe".into(),
                recursive: false,
            }],
        });
        p.dns.remote_server = Some(DNS_ACCOUNT.into());
        self.profiles.save(&p).expect("profile");
    }
}

fn tls_mut(settings: &mut procroute_core_mgr::node::Settings) -> Option<&mut Tls> {
    match settings {
        procroute_core_mgr::node::Settings::Trojan { tls, .. } => Some(tls),
        _ => None,
    }
}

fn assert_no_leaks(report: &DiagReport) -> String {
    let json = serde_json::to_string(report).expect("json");
    for leak in LEAKS {
        assert!(
            !json.contains(leak),
            "{leak} leaked into the report: {json}"
        );
    }
    json
}

#[test]
fn report_carries_no_credentials_addresses_or_user_names() {
    let f = fixture("leaks");
    f.populate();
    let log = f.write_log(&format!(
        "2026-10-29T01:02:03Z  INFO procroute_svc: started\n\
         2026-10-29T01:02:04Z  WARN procroute_svc: dial tj.example.com:443 sni={SNI} failed\n\
         2026-10-29T01:02:05Z ERROR procroute_svc: auth failed pw {PASSWORD}\n\
         2026-10-29T01:02:06Z  INFO procroute_svc: fetched {SUB_URL} from sub.example.org\n\
         2026-10-29T01:02:07Z  INFO procroute_svc: peer 203.0.113.7:8443 lan 192.168.1.20\n\
         2026-10-29T01:02:08Z  INFO procroute_svc: image=C:\\Users\\alice\\a.exe token=xyz\n\
         2026-10-29T01:02:09Z  INFO procroute_svc: socks user {SHORT_USERNAME} ok, bobcat kept\n"
    ));
    let report = f.collect(&DiagSources {
        log_file: Some(log),
        kernel_exe: None,
    });
    let json = assert_no_leaks(&report);
    assert!(!json.contains("xyz") && !json.contains(" bob "), "{json}");

    let lines = &report.log.lines;
    assert_eq!(lines.len(), 7);
    assert!(!report.log.truncated);
    assert!(
        lines[1].contains("dial <node>:443 sni=<node> failed"),
        "{}",
        lines[1]
    );
    assert!(lines[2].ends_with("auth failed pw ***"), "{}", lines[2]);
    assert!(lines[3].contains("fetched <subscription> from <subscription>"));
    assert!(
        lines[4].contains("peer <ip>:8443 lan 192.168.1.20"),
        "{}",
        lines[4]
    );
    assert!(lines[5].contains(r"image=C:\Users\<user>\a.exe token=***"));
    assert!(
        lines[6].contains("socks user *** ok, bobcat kept"),
        "{}",
        lines[6]
    );

    let p = &report.profiles[0];
    assert_eq!(
        p.groups[0].matchers[1].value,
        r"C:\Users\<user>\Games\a.exe"
    );
    assert_eq!(p.groups[1].matchers[0].value, r"C:\Users\*\Tools\*.exe");
    assert_eq!(p.dns.remote_server.as_deref(), Some("https://***"));
    assert_eq!(report.session.state, SessionState::Running);
    assert!(report.problems.is_empty(), "{:?}", report.problems);
}

#[test]
fn nodes_are_counted_and_only_referenced_ones_listed() {
    let f = fixture("nodes");
    f.populate();
    let nodes = f.collect(&DiagSources::default()).nodes.expect("nodes");
    assert_eq!(nodes.total, 2);
    assert_eq!(
        nodes.protocols,
        vec![DiagProtocolCount {
            protocol: NodeProtocol::Trojan,
            count: 2
        }]
    );
    assert_eq!(
        nodes.referenced,
        vec![DiagNode {
            id: "n1".into(),
            protocol: NodeProtocol::Trojan,
            server_port: 443,
            credential: CredentialState::Set,
            subscription_id: None,
        }]
    );
    assert_eq!(nodes.missing_outbounds, vec!["gone".to_owned()]);
    assert_eq!(
        nodes.subscriptions,
        vec![DiagSubscription {
            id: "s1".into(),
            node_count: 1,
            updated_at_ms: Some(1),
        }]
    );
}

#[test]
fn environment_names_versions_and_checks_the_kernel() {
    let f = fixture("env");
    let report = f.collect(&DiagSources::default());
    let env = &report.environment;
    assert_eq!(env.service_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(env.protocol_version, IPC_PROTOCOL_VERSION);
    assert!(
        env.os_build
            .as_deref()
            .is_some_and(|b| b.starts_with("10.0."))
    );
    assert_eq!(
        env.kernel_version,
        Some(locked_kernel().expect("lock").version)
    );
    assert_eq!(env.kernel_binary, DiagFileState::Unknown);
    assert!(!report.log.available);

    let fake = f.dir.join("sing-box.exe");
    std::fs::write(&fake, b"not the locked kernel").expect("fake");
    let lock = locked_kernel().expect("lock").sha256;
    assert_eq!(check_file(&fake, &lock), DiagFileState::Mismatch);
    assert_eq!(
        check_file(&f.dir.join("missing.exe"), &lock),
        DiagFileState::Missing
    );
    // `cargo xtask fetch-deps` 拉取的锁定版本（AGENTS 3.3 要求提交前先拉取）
    let locked =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/sing-box/bin/sing-box.exe");
    assert_eq!(
        check_file(&locked, &lock),
        DiagFileState::Verified,
        "run `cargo xtask fetch-deps` first"
    );
}

#[test]
fn unreadable_parts_are_reported_without_failing_the_export() {
    let f = fixture("broken");
    f.profiles.save(&sample("p1", "a")).expect("profile");
    std::fs::write(f.dir.join("nodes.json"), "{ not json").expect("corrupt");
    let report = f.collect(&DiagSources {
        log_file: Some(f.dir.join("no-such.log")),
        kernel_exe: Some(f.dir.join("no-such.exe")),
    });
    assert_eq!(
        report.problems,
        vec!["node_store_unreadable", "log_unreadable"]
    );
    assert!(report.nodes.is_none());
    assert_eq!(report.profiles.len(), 1);
    assert!(report.log.available && report.log.lines.is_empty());
    assert_eq!(report.environment.kernel_binary, DiagFileState::Missing);
}

#[test]
fn only_the_end_of_a_long_log_is_read() {
    let f = fixture("tail");
    let line = format!("{}\n", "x".repeat(99));
    let count = usize::try_from(LOG_TAIL_BYTES / 100).expect("small") * 2;
    let mut text: String = (0..count).map(|i| format!("{i:08} {line}")).collect();
    text.push_str("last line without newline");
    let report = f.collect(&DiagSources {
        log_file: Some(f.write_log(&text)),
        kernel_exe: None,
    });
    let lines = &report.log.lines;
    assert!(report.log.truncated);
    assert_eq!(
        lines.last().map(String::as_str),
        Some("last line without newline")
    );
    // 第一行是完整的一行，不是被截断的半行
    assert_eq!(lines[0].len(), 8 + 1 + 99, "{}", lines[0]);
    let read: usize = lines.iter().map(|l| l.len() + 1).sum();
    assert!(read <= usize::try_from(LOG_TAIL_BYTES).expect("small"));
}

#[test]
fn long_lines_are_clipped_on_char_boundaries() {
    let f = fixture("clip");
    let report = f.collect(&DiagSources {
        log_file: Some(f.write_log(&"长".repeat(MAX_LINE_BYTES))),
        kernel_exe: None,
    });
    let line = &report.log.lines[0];
    assert!(line.len() <= MAX_LINE_BYTES && line.len() > MAX_LINE_BYTES - 3);
    assert!(line.chars().all(|c| c == '长'));
}

#[test]
fn oversized_reports_drop_the_oldest_log_lines() {
    let f = fixture("fit");
    let mut report = f.collect(&DiagSources::default());
    // 反斜杠在 JSON 里转义成两个字节，3000 行 × 约 1 KiB 远超一条消息
    report.log.lines = (0..3000)
        .map(|i| format!("{i:05} {}", "\\".repeat(500)))
        .collect();
    let mut problems = Vec::new();
    fit(&mut report, &mut problems);
    let size = serde_json::to_vec(&report).expect("json").len();
    assert!(size <= REPORT_BUDGET, "{size}");
    assert!(
        size > REPORT_BUDGET / 2,
        "dropped far more than needed: {size}"
    );
    assert!(report.log.truncated);
    assert!(
        report
            .log
            .lines
            .last()
            .is_some_and(|l| l.starts_with("02999"))
    );
    assert!(problems.is_empty());
}

#[test]
fn url_hosts_drop_user_info_path_and_query() {
    assert_eq!(
        url_host("https://u:p@sub.example.org:8443/a?b#c"),
        "sub.example.org:8443"
    );
    assert_eq!(url_host("http://h"), "h");
    assert_eq!(url_host("no-scheme/path"), "no-scheme");
}
