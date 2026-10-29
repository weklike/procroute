// SPDX-License-Identifier: GPL-3.0-or-later
//! 配置生成的单元测试、快照测试，以及（Windows 上）用锁定版本 sing-box 的 `check` 做回归。

use procroute_proto::profile::{
    DnsSettings, FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION, Profile,
    UdpSettings,
};
use serde_json::Value;

use super::*;
use crate::outbound::tests::sample_nodes;

const SNAPSHOT: &str = "snapshots/tun_sample.json";
const PRECISE_SNAPSHOT: &str = "snapshots/precise_sample.json";

fn m(kind: MatchType, value: &str, recursive: bool) -> MatchRule {
    MatchRule {
        kind,
        value: value.into(),
        recursive,
    }
}

fn group(tag: &str, outbound: &str, matchers: Vec<MatchRule>) -> Group {
    Group {
        tag: tag.into(),
        outbound: outbound.into(),
        include_children: true,
        matchers,
    }
}

fn profile(groups: Vec<Group>) -> Profile {
    Profile {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: "p1".into(),
        name: "游戏加速".into(),
        mode: Mode::Tun,
        fail_policy: FailPolicy::Block,
        dns: DnsSettings::default(),
        udp: UdpSettings::default(),
        groups,
        exclude: vec![m(MatchType::Name, "updater.exe", false)],
    }
}

fn nodes() -> Vec<NodeOutbound> {
    sample_nodes()
        .into_iter()
        .map(|(tag, node, credentials)| NodeOutbound {
            tag,
            node,
            credentials,
        })
        .collect()
}

fn runtime() -> Runtime {
    Runtime {
        api_port: 59123,
        api_secret: Secret::new("0123456789abcdefABCDEF0123456789".into()),
        self_exe_paths: vec![
            r"C:\Program Files\ProcRoute\procroute-svc.exe".into(),
            r"C:\Program Files\ProcRoute\procroute-ui.exe".into(),
        ],
    }
}

fn hk_auto() -> GroupOutbound {
    GroupOutbound {
        tag: "hk-auto".into(),
        kind: GroupKind::UrlTest {
            url: "https://probe.example.net/generate_204".into(),
            interval_secs: 300,
        },
        members: vec!["vless-reality".into(), "hy2".into()],
    }
}

fn manual() -> GroupOutbound {
    GroupOutbound {
        tag: "manual".into(),
        kind: GroupKind::Selector {
            default: Some("trojan".into()),
        },
        members: vec!["trojan".into(), "anytls".into()],
    }
}

/// 覆盖全部规则类型、两种节点组和单节点引用的方案。
fn sample_profile() -> Profile {
    profile(vec![
        group(
            "game",
            "hk-auto",
            vec![
                m(MatchType::Dir, r"D:\Games\MyGame", true),
                m(MatchType::Name, "launcher.exe", false),
            ],
        ),
        group(
            "browser",
            "manual",
            vec![
                m(
                    MatchType::Path,
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    false,
                ),
                m(MatchType::Glob, r"D:\Tools\**\*.exe", false),
                m(MatchType::Regex, r"\\steam(webhelper)?\.exe$", false),
            ],
        ),
        group(
            "chat",
            "ss2022",
            vec![m(MatchType::Name, "Telegram.exe", false)],
        ),
    ])
}

fn generate(p: &Profile) -> Result<Value, GenError> {
    let text = generate_tun(p, &nodes(), &[hk_auto(), manual()], &runtime())?;
    Ok(serde_json::from_str(text.expose()).unwrap())
}

fn outbound_tags(v: &Value) -> Vec<&str> {
    v["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["tag"].as_str().unwrap())
        .collect()
}

#[test]
fn matches_snapshot() {
    let text = generate_tun(
        &sample_profile(),
        &nodes(),
        &[hk_auto(), manual()],
        &runtime(),
    )
    .unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(SNAPSHOT);
    let actual = format!("{}\n", text.expose());
    if std::env::var_os("PROCROUTE_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, &actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        actual, expected,
        "生成结果与 {SNAPSHOT} 不一致；确认改动无误后用 PROCROUTE_UPDATE_SNAPSHOTS=1 重新生成"
    );
}

#[test]
fn tun_inbound_respects_hard_constraints() {
    let v = generate(&sample_profile()).unwrap();
    let tun = &v["inbounds"][0];
    assert_eq!(tun["type"], "tun");
    // C-NET-06：system / mixed 栈会留下持久的防火墙规则
    assert_eq!(tun["stack"], "gvisor");
    // C-NET-09：不接管系统 DNS
    assert_eq!(tun["dns_mode"], "disabled");
    assert_eq!(tun["strict_route"], true);
    assert_eq!(
        tun["address"].as_array().unwrap().len(),
        2,
        "IPv4 与 IPv6 都要进 TUN"
    );
    assert_eq!(
        v["inbounds"].as_array().unwrap().len(),
        1,
        "TUN 模式不开任何监听入站"
    );
    // C-NET-08：控制 API 只绑定回环
    assert_eq!(
        v["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:59123"
    );
    assert_eq!(v["route"]["final"], DIRECT_TAG);
    assert_eq!(v["route"]["auto_detect_interface"], true);
}

#[test]
fn only_referenced_outbounds_are_emitted() {
    let v = generate(&sample_profile()).unwrap();
    assert_eq!(
        outbound_tags(&v),
        [
            "direct",
            "hk-auto",
            "manual",
            "vless-reality",
            "hy2",
            "trojan",
            "anytls",
            "ss2022"
        ]
    );
}

#[test]
fn rules_follow_engine_precedence() {
    let v = generate(&sample_profile()).unwrap();
    let rules = v["route"]["rules"].as_array().unwrap();
    let route: Vec<(&str, usize)> = rules
        .iter()
        .map(|r| {
            (
                r["outbound"].as_str().unwrap_or("-"),
                r["process_path_regex"].as_array().map_or(0, Vec::len),
            )
        })
        .collect();
    assert_eq!(
        route,
        [
            ("direct", 0),  // 回环、链路本地等
            ("direct", 2),  // ProcRoute 自身
            ("direct", 1),  // 排除
            ("manual", 1),  // 路径
            ("hk-auto", 1), // 目录
            ("hk-auto", 1), // 名称
            ("ss2022", 1),  // 名称（后一个组）
            ("manual", 2),  // 通配 + 正则
        ]
    );
    assert_eq!(
        rules[0]["ip_cidr"].as_array().unwrap().len(),
        ALWAYS_DIRECT_CIDRS.len()
    );
}

#[test]
fn udp_switches_add_rules_after_exclusions() {
    let mut p = sample_profile();
    p.udp = UdpSettings {
        enabled: false,
        block_quic: true,
    };
    let v = generate(&p).unwrap();
    let rules = v["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[3]["action"], "reject");
    assert_eq!(rules[3]["network"], "udp");
    assert_eq!(rules[3]["port"], 443);
    assert_eq!(rules[4]["network"], "udp");
    assert_eq!(rules[4]["outbound"], DIRECT_TAG);
    // 两条都覆盖全部 6 条进程规则
    assert_eq!(rules[3]["process_path_regex"].as_array().unwrap().len(), 6);
    assert_eq!(rules[4]["process_path_regex"].as_array().unwrap().len(), 6);
}

#[test]
fn credentials_only_appear_inside_the_secret() {
    let text = generate_tun(
        &sample_profile(),
        &nodes(),
        &[hk_auto(), manual()],
        &runtime(),
    )
    .unwrap();
    let dbg = format!("{text:?}");
    assert!(
        !dbg.contains("trojan-password") && !dbg.contains("0123456789abcdefABCDEF"),
        "{dbg}"
    );
    assert!(text.expose().contains("trojan-password"));
}

#[test]
fn rejects_non_tun_or_empty_profiles() {
    let mut p = sample_profile();
    p.mode = Mode::Precise;
    assert_eq!(generate(&p), Err(GenError::UnsupportedMode));
    assert_eq!(generate(&profile(vec![])), Err(GenError::NoGroups));
    let mut p = sample_profile();
    p.groups[0].tag = "Bad Tag".into();
    assert!(matches!(generate(&p), Err(GenError::InvalidProfile(_))));
}

#[test]
fn rejects_dangling_references() {
    let p = profile(vec![group(
        "g",
        "nowhere",
        vec![m(MatchType::Name, "a.exe", false)],
    )]);
    assert_eq!(
        generate(&p),
        Err(GenError::UnknownOutbound {
            group: "g".into(),
            outbound: "nowhere".into()
        })
    );

    let p = profile(vec![group(
        "g",
        "manual",
        vec![m(MatchType::Name, "a.exe", false)],
    )]);
    let bad_member = GroupOutbound {
        members: vec!["trojan".into(), "ghost".into()],
        ..manual()
    };
    assert_eq!(
        generate_tun(&p, &nodes(), &[bad_member], &runtime()).map(|_| ()),
        Err(GenError::UnknownMember {
            group: "manual".into(),
            member: "ghost".into()
        })
    );
    let bad_default = GroupOutbound {
        kind: GroupKind::Selector {
            default: Some("hy2".into()),
        },
        ..manual()
    };
    assert!(matches!(
        generate_tun(&p, &nodes(), &[bad_default], &runtime()),
        Err(GenError::InvalidDefault { .. })
    ));
    let empty = GroupOutbound {
        members: vec![],
        ..manual()
    };
    assert_eq!(
        generate_tun(&p, &nodes(), &[empty], &runtime()).map(|_| ()),
        Err(GenError::EmptyGroup("manual".into()))
    );
}

#[test]
fn rejects_bad_tags_and_url_tests() {
    let p = profile(vec![group(
        "g",
        "hk-auto",
        vec![m(MatchType::Name, "a.exe", false)],
    )]);
    let mut dup = nodes();
    dup[1].tag = "ss".into();
    assert_eq!(
        generate_tun(&p, &dup, &[hk_auto()], &runtime()).map(|_| ()),
        Err(GenError::DuplicateTag("ss".into()))
    );
    let mut reserved = nodes();
    reserved[0].tag = DIRECT_TAG.into();
    assert_eq!(
        generate_tun(&p, &reserved, &[hk_auto()], &runtime()).map(|_| ()),
        Err(GenError::InvalidTag(DIRECT_TAG.into()))
    );
    for (url, interval_secs) in [("ftp://x/", 300), ("https://x/", 10), ("https://a b/", 300)] {
        let g = GroupOutbound {
            kind: GroupKind::UrlTest {
                url: url.into(),
                interval_secs,
            },
            ..hk_auto()
        };
        assert_eq!(
            generate_tun(&p, &nodes(), &[g], &runtime()).map(|_| ()),
            Err(GenError::InvalidUrlTest("hk-auto".into())),
            "{url} {interval_secs}"
        );
    }
}

#[test]
fn rejects_broken_nodes_and_runtime() {
    let p = profile(vec![group(
        "g",
        "trojan",
        vec![m(MatchType::Name, "a.exe", false)],
    )]);
    let mut broken = nodes();
    broken[7].credentials = Credentials::default();
    assert_eq!(
        generate_tun(&p, &broken, &[], &runtime()).map(|_| ()),
        Err(GenError::InvalidNode {
            tag: "trojan".into(),
            source: NodeError::MissingCredential("password")
        })
    );
    // 未被引用的坏节点不影响生成
    let p = profile(vec![group(
        "g",
        "anytls",
        vec![m(MatchType::Name, "a.exe", false)],
    )]);
    assert!(generate_tun(&p, &broken, &[], &runtime()).is_ok());

    for rt in [
        Runtime {
            api_port: 0,
            ..runtime()
        },
        Runtime {
            api_secret: Secret::new("short".into()),
            ..runtime()
        },
        Runtime {
            api_secret: Secret::new("0123456789abcdef0123456789abcde!".into()),
            ..runtime()
        },
    ] {
        assert!(matches!(
            generate_tun(&p, &nodes(), &[], &rt),
            Err(GenError::InvalidEndpoint(_))
        ));
    }
    let no_self = Runtime {
        self_exe_paths: vec![],
        ..runtime()
    };
    assert!(matches!(
        generate_tun(&p, &nodes(), &[], &no_self),
        Err(GenError::InvalidRuntime(_))
    ));
}

#[test]
fn invalid_rules_report_their_location() {
    let p = profile(vec![group(
        "g",
        "trojan",
        vec![
            m(MatchType::Name, "a.exe", false),
            m(MatchType::Glob, "a**b", false),
        ],
    )]);
    assert!(matches!(
        generate(&p),
        Err(GenError::InvalidRule { location, .. }) if location == "groups[0].match[1]"
    ));
}

fn socks() -> SocksInbound {
    SocksInbound {
        port: 59124,
        password: Secret::new("SocksPassword0123456789abcdefXYZ".into()),
    }
}

fn precise_profile() -> Profile {
    Profile {
        mode: Mode::Precise,
        ..sample_profile()
    }
}

fn generate_precise_json(p: &Profile) -> Result<Value, GenError> {
    let text = generate_precise(p, &nodes(), &[hk_auto(), manual()], &runtime(), &socks())?;
    Ok(serde_json::from_str(text.expose()).unwrap())
}

#[test]
fn precise_routes_each_group_by_its_socks_user() {
    let v = generate_precise_json(&precise_profile()).unwrap();
    let inbound = &v["inbounds"][0];
    assert_eq!(
        v["inbounds"].as_array().unwrap().len(),
        1,
        "no TUN in precise mode"
    );
    assert_eq!(inbound["type"], "socks");
    assert_eq!(inbound["tag"], SOCKS_INBOUND_TAG);
    assert_eq!(inbound["listen"], "127.0.0.1", "loopback only (C-NET-08)");
    assert_eq!(inbound["listen_port"], 59124);
    // 用户名是进程组标签，与中继的 SOCKS5 握手一致
    let users: Vec<&str> = inbound["users"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(users, ["game", "browser", "chat"]);
    assert!(
        inbound["users"]
            .as_array()
            .unwrap()
            .iter()
            .all(|u| u["password"] == socks().password.expose().as_str())
    );

    let rules = v["route"]["rules"].as_array().unwrap();
    assert_eq!(
        rules[0],
        serde_json::json!({ "inbound": [SOCKS_INBOUND_TAG], "action": "sniff" })
    );
    for (user, outbound) in [
        ("game", "hk-auto"),
        ("browser", "manual"),
        ("chat", "ss2022"),
    ] {
        assert!(
            rules
                .iter()
                .any(|r| r["auth_user"] == serde_json::json!([user])
                    && r["action"] == "route"
                    && r["outbound"] == outbound),
            "{user} -> {outbound}: {rules:?}"
        );
    }
    // 最后一条：入口上没有匹配进程组的连接一律拒绝，不直连（C-NET-03）
    assert_eq!(
        rules.last().unwrap(),
        &serde_json::json!({ "inbound": [SOCKS_INBOUND_TAG], "action": "reject" })
    );
    assert!(
        rules.iter().all(|r| r.get("process_path_regex").is_none()),
        "process rules are the intercept layer's job in precise mode"
    );
    // 只输出被引用的出站
    let mut tags = outbound_tags(&v);
    tags.sort_unstable();
    let mut expected = vec![
        "direct",
        "hk-auto",
        "vless-reality",
        "hy2",
        "manual",
        "trojan",
        "anytls",
        "ss2022",
    ];
    expected.sort_unstable();
    assert_eq!(tags, expected);
    assert_eq!(
        v["experimental"]["clash_api"]["external_controller"],
        "127.0.0.1:59123"
    );
}

#[test]
fn precise_blocks_quic_on_the_entry_when_asked() {
    let mut p = precise_profile();
    p.udp.block_quic = true;
    let v = generate_precise_json(&p).unwrap();
    let rules = v["route"]["rules"].as_array().unwrap();
    let quic = rules
        .iter()
        .position(|r| r["port"] == 443 && r["network"] == "udp")
        .expect("QUIC rule");
    assert_eq!(rules[quic]["action"], "reject");
    let first_route = rules.iter().position(|r| r["action"] == "route").unwrap();
    assert!(
        quic < first_route,
        "QUIC is rejected before any group routes it"
    );
}

#[test]
fn precise_and_tun_generators_reject_each_others_profiles() {
    assert_eq!(
        generate_precise_json(&sample_profile()).unwrap_err(),
        GenError::UnsupportedMode
    );
    assert_eq!(
        generate(&precise_profile()).unwrap_err(),
        GenError::UnsupportedMode
    );
}

#[test]
fn precise_rejects_weak_socks_endpoints() {
    let p = precise_profile();
    for bad in [
        SocksInbound { port: 0, ..socks() },
        SocksInbound {
            password: Secret::new("short".into()),
            ..socks()
        },
        SocksInbound {
            password: Secret::new("SocksPassword0123456789abcdefXY\"".into()),
            ..socks()
        },
    ] {
        assert_eq!(
            generate_precise(&p, &nodes(), &[hk_auto(), manual()], &runtime(), &bad).unwrap_err(),
            GenError::InvalidEndpoint("SOCKS 入口")
        );
    }
}

#[test]
fn precise_matches_snapshot() {
    let text = generate_precise(
        &precise_profile(),
        &nodes(),
        &[hk_auto(), manual()],
        &runtime(),
        &socks(),
    )
    .unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(PRECISE_SNAPSHOT);
    let actual = format!("{}\n", text.expose());
    if std::env::var_os("PROCROUTE_UPDATE_SNAPSHOTS").is_some() {
        std::fs::write(&path, &actual).unwrap();
    }
    let expected = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        actual == expected,
        "生成结果与 {PRECISE_SNAPSHOT} 不一致；确认改动无误后用 PROCROUTE_UPDATE_SNAPSHOTS=1 重新生成"
    );
}

/// 用锁定版本的 sing-box 执行 `check`（只构造实例、不启动：不建 TUN、不监听端口、不联网）。
#[cfg(windows)]
mod sing_box_check {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use procroute_platform_win::hash;

    use super::*;

    /// `third_party/sing-box/bin/sing-box.exe`，校验与锁文件一致后返回。
    fn locked_sing_box() -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let lock: Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("third_party/sing-box/lock.json")).unwrap(),
        )
        .unwrap();
        let expected = lock["assets"]["windows-x86_64"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "sing-box.exe")
            .and_then(|f| f["sha256"].as_str())
            .unwrap()
            .to_owned();
        let exe = root.join("third_party/sing-box/bin/sing-box.exe");
        let actual = hash::sha256_file(&exe)
            .map(|d| hash::to_hex(&d))
            .unwrap_or_else(|e| {
                panic!("找不到锁定版本的 sing-box（{e}），先运行 `cargo xtask fetch-deps`")
            });
        assert_eq!(
            actual, expected,
            "sing-box.exe 与锁文件不一致，重新运行 `cargo xtask fetch-deps`"
        );
        exe
    }

    fn check(config: &str, name: &str) -> (bool, String) {
        let dir = std::env::temp_dir().join(format!("procroute-core-mgr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join(format!("{name}.json"));
        std::fs::write(&file, config).unwrap();
        let out = Command::new(locked_sing_box())
            .arg("check")
            .arg("-c")
            .arg(&file)
            .output()
            .unwrap();
        std::fs::remove_file(&file).unwrap();
        let log = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.success(), log)
    }

    fn assert_accepted(p: &Profile, groups: &[GroupOutbound], name: &str) {
        let text = generate_tun(p, &nodes(), groups, &runtime()).unwrap();
        let (ok, log) = check(text.expose(), name);
        assert!(ok, "sing-box check 拒绝了生成的配置 {name}：\n{log}");
        // 弃用字段在 check 时只打警告，同样视为回归
        assert!(
            !log.to_ascii_lowercase().contains("deprecated"),
            "{name} 用到了弃用字段：\n{log}"
        );
    }

    #[test]
    fn sample_profile_passes() {
        assert_accepted(&sample_profile(), &[hk_auto(), manual()], "sample");
    }

    #[test]
    fn precise_sample_passes() {
        let mut p = precise_profile();
        p.udp.block_quic = true;
        let text =
            generate_precise(&p, &nodes(), &[hk_auto(), manual()], &runtime(), &socks()).unwrap();
        let (ok, log) = check(text.expose(), "precise");
        assert!(ok, "sing-box check 拒绝了精确模式配置：\n{log}");
        assert!(
            !log.to_ascii_lowercase().contains("deprecated"),
            "精确模式配置用到了弃用字段：\n{log}"
        );
    }

    #[test]
    fn every_protocol_passes() {
        let selector = GroupOutbound {
            tag: "all".into(),
            kind: GroupKind::Selector { default: None },
            members: nodes().into_iter().map(|n| n.tag).collect(),
        };
        let p = profile(vec![group(
            "g",
            "all",
            vec![m(MatchType::Name, "a.exe", false)],
        )]);
        assert_accepted(&p, &[selector], "every-protocol");
    }

    #[test]
    fn udp_switches_and_rule_kinds_pass() {
        let mut p = sample_profile();
        p.udp = UdpSettings {
            enabled: false,
            block_quic: true,
        };
        p.groups.push(group(
            "more",
            "trojan",
            vec![
                m(MatchType::Dir, r"C:\", false),
                m(MatchType::Glob, r"C:\Program Files\{a,b}\[!x]?.exe", false),
                m(MatchType::Path, r"D:\游戏\a+b (x86)\[v1]\app$.exe", false),
            ],
        ));
        assert_accepted(&p, &[hk_auto(), manual()], "udp-and-rules");
    }

    #[test]
    fn check_really_rejects_invalid_configs() {
        // 防止 check 因为环境问题「总是通过」
        let text = generate_tun(
            &sample_profile(),
            &nodes(),
            &[hk_auto(), manual()],
            &runtime(),
        )
        .unwrap();
        let broken = text.expose().replace("\"dns_mode\"", "\"dns_moode\"");
        let (ok, _) = check(&broken, "broken");
        assert!(!ok);
    }
}
