// SPDX-License-Identifier: GPL-3.0-or-later
//! 远程 DNS 的生成（`dns.remote_server`）。

use serde_json::json;

use super::*;

fn with_remote(mut p: Profile, server: &str) -> Profile {
    p.dns.remote_server = Some(server.into());
    p
}

fn precise_json(p: &Profile) -> Value {
    let text = generate_precise(p, &nodes(), &[hk_auto(), manual()], &runtime(), &socks()).unwrap();
    serde_json::from_str(text.expose()).unwrap()
}

fn tun_json(p: &Profile) -> Value {
    generate(p).unwrap()
}

fn servers(v: &Value) -> Vec<Value> {
    v["dns"]["servers"].as_array().unwrap().clone()
}

#[test]
fn tun_hijacks_target_port_53_and_resolves_through_each_group() {
    let v = tun_json(&with_remote(sample_profile(), "tls://198.51.100.53:853"));
    let servers = servers(&v);
    assert_eq!(servers[0], json!({ "type": "local", "tag": LOCAL_DNS_TAG }));
    // 三个进程组引用了三个不同的出站：每个出站一个远程服务器
    let remote: Vec<(&str, &str)> = servers[1..]
        .iter()
        .map(|s| (s["tag"].as_str().unwrap(), s["detour"].as_str().unwrap()))
        .collect();
    assert_eq!(
        remote,
        [
            ("remote-0", "hk-auto"),
            ("remote-1", "manual"),
            ("remote-2", "ss2022")
        ]
    );
    assert_eq!(servers[1]["type"], "tls");
    assert_eq!(servers[1]["server"], "198.51.100.53");
    assert_eq!(servers[1]["server_port"], 853);
    assert!(
        servers[1].get("domain_resolver").is_none(),
        "IP needs no resolver"
    );
    assert_eq!(v["dns"]["final"], LOCAL_DNS_TAG);

    let rules = v["route"]["rules"].as_array().unwrap();
    let hijack = rules
        .iter()
        .position(|r| r["action"] == "hijack-dns")
        .expect("hijack rule");
    assert_eq!(rules[hijack]["port"], 53);
    let exclude = rules
        .iter()
        .position(|r| r["process_path_regex"].to_string().contains("updater"))
        .expect("exclude rule");
    let first_group = rules
        .iter()
        .position(|r| r["outbound"] == "hk-auto")
        .unwrap();
    assert!(exclude < hijack && hijack < first_group, "{rules:#?}");

    let dns_rules = v["dns"]["rules"].as_array().unwrap();
    assert!(
        dns_rules
            .iter()
            .all(|r| r["action"] == "route" && r["process_path_regex"].is_array())
    );
    assert!(dns_rules.iter().any(|r| r["server"] == "remote-2"));
}

#[test]
fn precise_resolves_by_socks_user() {
    let v = precise_json(&with_remote(
        precise_profile(),
        "https://DNS.Example/dns-query",
    ));
    let servers = servers(&v);
    assert_eq!(servers[1]["type"], "https");
    assert_eq!(servers[1]["server"], "dns.example");
    assert_eq!(servers[1]["path"], "/dns-query");
    assert_eq!(
        servers[1]["domain_resolver"], LOCAL_DNS_TAG,
        "the DoH host name is resolved locally first"
    );
    let rules = v["route"]["rules"].as_array().unwrap();
    assert_eq!(rules[0]["action"], "sniff");
    assert_eq!(
        rules[1],
        json!({ "inbound": [SOCKS_INBOUND_TAG], "port": 53, "action": "hijack-dns" })
    );
    let dns_rules = v["dns"]["rules"].as_array().unwrap();
    assert_eq!(
        dns_rules[0],
        json!({ "auth_user": ["game"], "action": "route", "server": "remote-0" })
    );
    assert_eq!(dns_rules.len(), 3);
}

#[test]
fn nothing_changes_without_a_server_or_without_hijacking() {
    let plain = tun_json(&sample_profile());
    assert_eq!(servers(&plain).len(), 1);
    assert!(plain["dns"].get("rules").is_none());
    let mut off = with_remote(sample_profile(), "udp://198.51.100.53");
    off.dns.hijack_port53 = false;
    let v = tun_json(&off);
    assert_eq!(servers(&v).len(), 1);
    assert!(
        !v["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["action"] == "hijack-dns")
    );
}

#[test]
fn groups_sharing_an_outbound_share_a_server() {
    let mut p = with_remote(precise_profile(), "udp://198.51.100.53");
    p.groups[1].outbound = "hk-auto".into();
    let v = precise_json(&p);
    assert_eq!(servers(&v).len(), 3, "local + hk-auto + ss2022");
    let dns_rules = v["dns"]["rules"].as_array().unwrap();
    assert_eq!(dns_rules[0]["server"], dns_rules[1]["server"]);
}

#[cfg(windows)]
#[test]
fn sing_box_accepts_remote_dns_in_both_modes() {
    use super::sing_box_check::check;

    for (name, server) in [
        ("dns-tls-ip", "tls://198.51.100.53:853"),
        ("dns-doh-domain", "https://dns.example/dns-query"),
        ("dns-udp-v6", "udp://[2001:db8::53]"),
    ] {
        let tun = generate_tun(
            &with_remote(sample_profile(), server),
            &nodes(),
            &[hk_auto(), manual()],
            &runtime(),
        )
        .unwrap();
        let (ok, log) = check(tun.expose(), &format!("{name}-tun"));
        assert!(ok, "{name} (TUN) rejected:\n{log}");
        assert!(!log.to_ascii_lowercase().contains("deprecated"), "{log}");

        let precise = generate_precise(
            &with_remote(precise_profile(), server),
            &nodes(),
            &[hk_auto(), manual()],
            &runtime(),
            &socks(),
        )
        .unwrap();
        let (ok, log) = check(precise.expose(), &format!("{name}-precise"));
        assert!(ok, "{name} (precise) rejected:\n{log}");
        assert!(!log.to_ascii_lowercase().contains("deprecated"), "{log}");
    }
}
