// SPDX-License-Identifier: GPL-3.0-or-later
//! 分享链接与订阅解析的测试。链接里的地址、密码都是示例值。

use super::*;
use crate::node::{
    Fingerprint, Hysteria2Obfs, Settings, SsMethod, SsPluginKind, TuicCongestion, TuicUdpRelayMode,
    VlessFlow, VmessSecurity,
};

const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
const PBK: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
/// v2rayN JSON：ws + tls、`?ed=2048`、端口为字符串、UUID 为大写。
const VMESS_WS: &str = "vmess://eyJ2IjogIjIiLCAicHMiOiAi5pel5pysIFZNZXNzIiwgImFkZCI6ICJ2bS5leGFtcGxlLmNvbSIsICJwb3J0IjogIjQ0MyIsICJpZCI6ICJCRjAwMEQyMy0wNzUyLTQwQjQtQUZGRS02OEY3NzA3QTk2NjEiLCAiYWlkIjogIjAiLCAic2N5IjogImF1dG8iLCAibmV0IjogIndzIiwgInR5cGUiOiAibm9uZSIsICJob3N0IjogImNkbi5leGFtcGxlLmNvbSIsICJwYXRoIjogIi9yYXk/ZWQ9MjA0OCIsICJ0bHMiOiAidGxzIiwgInNuaSI6ICIiLCAiYWxwbiI6ICJoMixodHRwLzEuMSIsICJmcCI6ICJjaHJvbWUifQ==";
/// 同上，`aid` 为数字 2。
const VMESS_AID2: &str = "vmess://eyJ2IjogIjIiLCAicHMiOiAi5pel5pysIFZNZXNzIiwgImFkZCI6ICJ2bS5leGFtcGxlLmNvbSIsICJwb3J0IjogIjQ0MyIsICJpZCI6ICJCRjAwMEQyMy0wNzUyLTQwQjQtQUZGRS02OEY3NzA3QTk2NjEiLCAiYWlkIjogMiwgInNjeSI6ICJhdXRvIiwgIm5ldCI6ICJ3cyIsICJ0eXBlIjogIm5vbmUiLCAiaG9zdCI6ICJjZG4uZXhhbXBsZS5jb20iLCAicGF0aCI6ICIvcmF5P2VkPTIwNDgiLCAidGxzIjogInRscyIsICJzbmkiOiAiIiwgImFscG4iOiAiaDIsaHR0cC8xLjEiLCAiZnAiOiAiY2hyb21lIn0=";
/// 同上，`net` 为 kcp。
const VMESS_KCP: &str = "vmess://eyJ2IjogIjIiLCAicHMiOiAi5pel5pysIFZNZXNzIiwgImFkZCI6ICJ2bS5leGFtcGxlLmNvbSIsICJwb3J0IjogIjQ0MyIsICJpZCI6ICJCRjAwMEQyMy0wNzUyLTQwQjQtQUZGRS02OEY3NzA3QTk2NjEiLCAiYWlkIjogIjAiLCAic2N5IjogImF1dG8iLCAibmV0IjogImtjcCIsICJ0eXBlIjogIm5vbmUiLCAiaG9zdCI6ICJjZG4uZXhhbXBsZS5jb20iLCAicGF0aCI6ICIvcmF5P2VkPTIwNDgiLCAidGxzIjogInRscyIsICJzbmkiOiAiIiwgImFscG4iOiAiaDIsaHR0cC8xLjEiLCAiZnAiOiAiY2hyb21lIn0=";
/// grpc、无 TLS、端口为数字 8443、服务名放在 path。
const VMESS_GRPC: &str = "vmess://eyJ2IjogIjIiLCAicHMiOiAi5pel5pysIFZNZXNzIiwgImFkZCI6ICJ2bS5leGFtcGxlLmNvbSIsICJwb3J0IjogODQ0MywgImlkIjogIkJGMDAwRDIzLTA3NTItNDBCNC1BRkZFLTY4Rjc3MDdBOTY2MSIsICJhaWQiOiAiMCIsICJzY3kiOiAiYXV0byIsICJuZXQiOiAiZ3JwYyIsICJ0eXBlIjogIm5vbmUiLCAiaG9zdCI6ICJjZG4uZXhhbXBsZS5jb20iLCAicGF0aCI6ICJteWdycGMiLCAidGxzIjogIiIsICJzbmkiOiAiIiwgImFscG4iOiAiaDIsaHR0cC8xLjEiLCAiZnAiOiAiY2hyb21lIn0=";

fn ok(link: &str) -> ParsedNode {
    parse_link(link).unwrap_or_else(|e| panic!("{link}: {e}"))
}

fn err(link: &str) -> &'static str {
    match parse_link(link) {
        Ok(n) => panic!("{link} should fail, got {n:?}"),
        Err(e) => e.code(),
    }
}

fn password(n: &ParsedNode) -> &str {
    n.credentials.password.as_ref().expect("password").expose()
}

fn uuid(n: &ParsedNode) -> &str {
    n.credentials.uuid.as_ref().expect("uuid").expose()
}

#[test]
fn shadowsocks_sip002_and_legacy() {
    let n = ok("ss://YWVzLTI1Ni1nY206cGFzcy93b3JkKzE@203.0.113.1:8388#HK%2001");
    assert_eq!(n.name, "HK 01");
    assert_eq!(
        (n.node.server.as_str(), n.node.server_port),
        ("203.0.113.1", 8388)
    );
    assert!(matches!(
        n.node.settings,
        Settings::Shadowsocks {
            method: SsMethod::Aes256Gcm,
            plugin: None
        }
    ));
    assert_eq!(password(&n), "pass/word+1");

    // SIP022：2022 加密用百分号编码的明文；带插件、IPv6
    let n = ok(
        "ss://2022-blake3-aes-128-gcm:8JCsPssfgS8tiRwiMlhARg%3D%3D@[2001:db8::1]:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com",
    );
    assert_eq!(n.node.server, "2001:db8::1");
    assert_eq!(n.name, "[2001:db8::1]:8388", "没有备注时用地址");
    assert_eq!(password(&n), "8JCsPssfgS8tiRwiMlhARg==");
    let Settings::Shadowsocks {
        method,
        plugin: Some(p),
    } = &n.node.settings
    else {
        panic!("{:?}", n.node.settings)
    };
    assert_eq!(*method, SsMethod::Blake3Aes128Gcm);
    assert_eq!(p.kind, SsPluginKind::ObfsLocal);
    assert_eq!(p.opts, "obfs=http;obfs-host=cdn.example.com");

    // 旧版整段 Base64，密码里有 `@` 和 `:`
    let n = ok("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwQHNzOncwcmRAMS4yLjMuNDo0NDM=#legacy");
    assert_eq!(
        (n.node.server.as_str(), n.node.server_port),
        ("1.2.3.4", 443)
    );
    assert_eq!(password(&n), "p@ss:w0rd");
}

#[test]
fn shadowsocks_rejections() {
    // rc4-md5:pw
    assert_eq!(err("ss://cmM0LW1kNTpwdw@1.2.3.4:443"), "unsupported_cipher");
    assert_eq!(
        err("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:443/?plugin=kcptun%3Bmode%3Dfast"),
        "unsupported_plugin"
    );
    assert_eq!(err("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4"), "malformed");
    assert_eq!(err("ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:0"), "invalid_port");
    assert_eq!(err("ss://not*base64"), "malformed");
}

#[test]
fn vmess_v2rayn_json() {
    let n = ok(VMESS_WS);
    assert_eq!(n.name, "日本 VMess");
    assert_eq!(uuid(&n), UUID, "UUID 统一为小写");
    let Settings::Vmess {
        security,
        tls: Some(tls),
        transport: Some(t),
    } = &n.node.settings
    else {
        panic!("{:?}", n.node.settings)
    };
    assert_eq!(*security, VmessSecurity::Auto);
    assert_eq!(
        tls.server_name.as_deref(),
        Some("cdn.example.com"),
        "sni 为空时用 host"
    );
    assert_eq!(tls.alpn, ["h2", "http/1.1"]);
    assert_eq!(tls.fingerprint, Some(Fingerprint::Chrome));
    assert_eq!(
        *t,
        crate::node::Transport::Ws {
            path: "/ray".into(),
            host: Some("cdn.example.com".into()),
            max_early_data: Some(2048)
        }
    );

    let n = ok(VMESS_GRPC);
    assert_eq!(n.node.server_port, 8443);
    assert!(matches!(
        &n.node.settings,
        Settings::Vmess { tls: None, transport: Some(crate::node::Transport::Grpc { service_name }), .. }
            if service_name == "mygrpc"
    ));

    assert_eq!(err(VMESS_AID2), "vmess_legacy_alter_id");
    assert_eq!(err(VMESS_KCP), "unsupported_transport");
    assert_eq!(err("vmess://bm90IGpzb24"), "malformed");
}

#[test]
fn vless_reality_and_transports() {
    let n = ok(&format!(
        "vless://{UUID}@vl.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.org&fp=firefox&pbk={PBK}&sid=0123abcd&type=tcp&headerType=none#REALITY"
    ));
    let Settings::Vless {
        flow,
        tls: Some(tls),
        transport,
    } = &n.node.settings
    else {
        panic!("{:?}", n.node.settings)
    };
    assert_eq!(*flow, Some(VlessFlow::XtlsRprxVision));
    assert_eq!(transport, &None);
    assert_eq!(tls.server_name.as_deref(), Some("www.example.org"));
    assert_eq!(tls.fingerprint, Some(Fingerprint::Firefox));
    let reality = tls.reality.as_ref().expect("reality");
    assert_eq!(
        (reality.public_key.as_str(), reality.short_id.as_str()),
        (PBK, "0123abcd")
    );

    let n = ok(&format!(
        "vless://{UUID}@vl.example.com:443?security=tls&type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&sni=cdn.example.com#ws"
    ));
    assert!(matches!(
        &n.node.settings,
        Settings::Vless { transport: Some(crate::node::Transport::Ws { path, max_early_data: Some(2048), .. }), .. }
            if path == "/ws"
    ));
    let n = ok(&format!(
        "vless://{UUID}@vl.example.com:80?type=httpupgrade&path=%2Fup&host=a.example.com"
    ));
    assert!(matches!(
        &n.node.settings,
        Settings::Vless {
            tls: None,
            transport: Some(crate::node::Transport::Httpupgrade { .. }),
            ..
        }
    ));

    assert_eq!(
        err(&format!(
            "vless://{UUID}@h:443?encryption=mlkem768x25519plus.native.0rtt.abc&security=tls"
        )),
        "unsupported_encryption"
    );
    assert_eq!(
        err(&format!("vless://{UUID}@h:443?security=tls&type=xhttp")),
        "unsupported_transport"
    );
    assert_eq!(
        err(&format!("vless://{UUID}@h:443?security=reality&sni=a")),
        "invalid_reality"
    );
    assert_eq!(
        err(&format!("vless://{UUID}@h:443?flow=xtls-rprx-direct")),
        "unsupported_flow"
    );
    assert_eq!(
        err(&format!("vless://{UUID}@h:443?type=tcp&headerType=http")),
        "unsupported_transport"
    );
    assert_eq!(err("vless://not-a-uuid@h:443"), "invalid_uuid");
}

#[test]
fn trojan_defaults_to_tls() {
    let n = ok(
        "trojan://p%40ss@tj.example.com:443?peer=sni.example.com&allowInsecure=1&type=grpc&serviceName=svc#t",
    );
    assert_eq!(password(&n), "p@ss");
    let Settings::Trojan { tls, transport } = &n.node.settings else {
        panic!("{:?}", n.node.settings)
    };
    assert_eq!(tls.server_name.as_deref(), Some("sni.example.com"));
    assert!(tls.insecure);
    assert!(
        matches!(transport, Some(crate::node::Transport::Grpc { service_name }) if service_name == "svc")
    );
    assert_eq!(
        err("trojan://pw@tj.example.com:443?security=none"),
        "unsupported_security"
    );
    assert_eq!(err("trojan://@tj.example.com:443"), "missing_credential");
}

#[test]
fn hysteria2_tuic_anytls() {
    let n = ok(
        "hy2://user:secret@hy.example.com:443,20000-30000/?obfs=salamander&obfs-password=ob&sni=hy.example.com&insecure=1#hy",
    );
    assert_eq!(password(&n), "user:secret");
    assert_eq!(
        n.credentials
            .obfs_password
            .as_ref()
            .map(|s| s.expose().as_str()),
        Some("ob")
    );
    let Settings::Hysteria2 {
        tls,
        server_ports,
        obfs,
    } = &n.node.settings
    else {
        panic!("{:?}", n.node.settings)
    };
    assert_eq!(n.node.server_port, 443);
    assert_eq!(server_ports, &["20000:30000"]);
    assert_eq!(*obfs, Some(Hysteria2Obfs::Salamander));
    assert!(tls.insecure);
    // 没写端口时用 443
    assert_eq!(ok("hysteria2://pw@hy.example.com").node.server_port, 443);
    assert_eq!(
        err("hysteria2://pw@hy.example.com:443?pinSHA256=ab:cd"),
        "unsupported_cert_pin"
    );
    assert_eq!(
        err("hysteria2://pw@hy.example.com:443?obfs=gecko"),
        "unsupported_obfs"
    );
    assert_eq!(
        err("hysteria2://pw@hy.example.com:443?obfs=salamander"),
        "missing_credential"
    );

    let n = ok(&format!(
        "tuic://{UUID}:pw@tu.example.com:443?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=tu.example.com&allow_insecure=0#tu"
    ));
    assert_eq!(uuid(&n), UUID);
    assert_eq!(password(&n), "pw");
    assert!(matches!(
        n.node.settings,
        Settings::Tuic {
            congestion_control: Some(TuicCongestion::Bbr),
            udp_relay_mode: Some(TuicUdpRelayMode::Quic),
            ..
        }
    ));
    assert_eq!(err("tuic://onlyuuid@tu.example.com:443"), "malformed");

    let n = ok("anytls://pw2@at.example.com:443/?sni=at.example.com#at");
    assert_eq!(password(&n), "pw2");
    assert!(
        matches!(&n.node.settings, Settings::Anytls { tls } if tls.server_name.as_deref() == Some("at.example.com"))
    );
}

#[test]
fn socks_and_http() {
    let n = ok("socks5://u%3Ax:p%2525@198.51.100.7:1080#s");
    assert_eq!(
        n.credentials.username.as_ref().map(|s| s.expose().as_str()),
        Some("u:x")
    );
    assert_eq!(password(&n), "p%25", "只解码一次");
    // v2rayN：Base64(user:pass)
    let n = ok("socks://dXNlcjpwJXNz@198.51.100.7:1080");
    assert_eq!(password(&n), "p%ss");
    let n = ok("socks5://198.51.100.7:1080");
    assert!(!n.credentials.is_set());

    let n = ok("https://u:p@px.example.com:443#px");
    assert!(matches!(n.node.settings, Settings::Http { tls: Some(_) }));
    assert_eq!(
        err("https://sub.example.com/api/v1/client/subscribe?token=x"),
        "looks_like_subscription_url"
    );
    assert_eq!(err("http://px.example.com"), "looks_like_subscription_url");
    assert_eq!(err("socks5://u@198.51.100.7:1080"), "malformed");
}

#[test]
fn unknown_and_malformed_links() {
    assert_eq!(err("ssr://abc"), "unsupported_protocol");
    assert_eq!(err("hysteria://h:1"), "unsupported_protocol");
    assert_eq!(err("wireguard://k@h:51820"), "unsupported_protocol");
    assert_eq!(err("just text"), "malformed");
}

#[test]
fn parse_text_reports_line_numbers() {
    let text = format!(
        "\n  trojan://pw1@tj.example.com:443#a  \nssr://x\n\n{VMESS_WS}\nvless://bad@h:443\n"
    );
    let out = parse_text(&text);
    let lines: Vec<u32> = out.nodes.iter().map(|n| n.line).collect();
    assert_eq!(lines, [2, 5]);
    assert_eq!(
        out.issues,
        [
            Issue {
                line: 3,
                code: "unsupported_protocol"
            },
            Issue {
                line: 6,
                code: "invalid_uuid"
            },
        ]
    );
}

#[test]
fn base64_subscriptions() {
    for encoded in [
        // 标准字母表带填充、折行、URL 安全无填充
        "dHJvamFuOi8vcHcxQHRqLmV4YW1wbGUuY29tOjQ0MyNhCmFueXRsczovL3B3MkBhdC5leGFtcGxlLmNvbTo0NDMvP3NuaT1hdC5leGFtcGxlLmNvbSNi",
        "dHJvamFuOi8vcHcxQHRqLmV4YW1wbGUuY29tOjQ0MyNhCmFueXRsczovL3B3\nMkBhdC5leGFtcGxlLmNvbTo0NDMvP3NuaT1hdC5leGFtcGxlLmNvbSNi\n",
    ] {
        let out = parse_text(encoded);
        assert_eq!(out.issues, []);
        let names: Vec<_> = out.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["a", "b"]);
    }
}

#[test]
fn sip008_subscriptions() {
    let out = parse_text(
        r#"{"version":1,"servers":[
            {"id":"1","remarks":"一号","server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-128-gcm"},
            {"server":"5.6.7.8","server_port":"8389","password":"pw","method":"chacha20-ietf-poly1305","plugin":"v2ray-plugin","plugin_opts":"tls;host=a.example.com"},
            {"server":"9.9.9.9","server_port":8388,"password":"pw","method":"rc4-md5"},
            {"server":"9.9.9.9","server_port":70000,"password":"pw","method":"aes-128-gcm"}
        ]}"#,
    );
    assert_eq!(out.nodes.len(), 2);
    assert_eq!(out.nodes[0].name, "一号");
    assert!(matches!(
        &out.nodes[1].node.settings,
        Settings::Shadowsocks { plugin: Some(p), .. } if p.kind == SsPluginKind::V2rayPlugin && p.opts == "tls;host=a.example.com"
    ));
    assert_eq!(
        out.issues,
        [
            Issue {
                line: 3,
                code: "unsupported_cipher"
            },
            Issue {
                line: 4,
                code: "invalid_port"
            }
        ]
    );
    assert_eq!(
        parse_text("{not json").issues,
        [Issue {
            line: 0,
            code: "malformed"
        }]
    );
}

#[test]
fn whole_input_problems() {
    assert_eq!(
        parse_text(" \n ").issues,
        [Issue {
            line: 0,
            code: EMPTY_INPUT
        }]
    );
    assert_eq!(
        parse_text("port: 7890\nproxies:\n  - name: a\n").issues,
        [Issue {
            line: 0,
            code: CLASH_YAML_UNSUPPORTED
        }]
    );
    let huge = "x".repeat(MAX_INPUT_BYTES + 1);
    assert_eq!(
        parse_text(&huge).issues,
        [Issue {
            line: 0,
            code: INPUT_TOO_LARGE
        }]
    );

    let many: String = (0..MAX_NODES + 3)
        .map(|i| format!("trojan://pw@h{i}.example.com:443\n"))
        .collect();
    let out = parse_text(&many);
    assert_eq!(out.nodes.len(), MAX_NODES);
    assert_eq!(
        out.issues,
        [Issue {
            line: MAX_NODES as u32 + 1,
            code: TOO_MANY_NODES
        }]
    );
}

#[test]
fn names_are_sanitized() {
    let long = "名".repeat(MAX_NAME_CHARS + 10);
    let n = ok(&format!("trojan://pw@h.example.com:443#{long}"));
    assert_eq!(n.name.chars().count(), MAX_NAME_CHARS);
    let n = ok("trojan://pw@h.example.com:443#%20a%0Ab%07%20");
    assert_eq!(n.name, "ab");
    let n = ok("trojan://pw@h.example.com:443#%20");
    assert_eq!(n.name, "h.example.com:443");
}

#[test]
fn issues_and_debug_output_never_contain_credentials() {
    let secret = "hunter2-very-secret";
    let links = [
        format!("trojan://{secret}@h.example.com:443?security=none"),
        format!("ss://rc4-md5:{secret}@1.2.3.4:443"),
        format!("vless://{secret}@h:443"),
        format!("hy2://{secret}@h:443?pinSHA256=x"),
    ];
    for link in &links {
        let e = parse_link(link).expect_err("must fail");
        assert!(!e.to_string().contains(secret) && !e.code().contains(secret));
    }
    let n = ok(&format!("trojan://{secret}@h.example.com:443"));
    assert!(!format!("{n:?}").contains(secret));
}

#[test]
fn every_parsed_node_renders() {
    let links = [
        "ss://YWVzLTI1Ni1nY206cGFzcy93b3JkKzE@203.0.113.1:8388#HK",
        VMESS_WS,
        VMESS_GRPC,
        "trojan://pw@tj.example.com:443",
        "hy2://pw@hy.example.com:443,20000-30000/?obfs=salamander&obfs-password=ob",
        "anytls://pw@at.example.com:443",
        "socks5://u:p@198.51.100.7:1080",
    ];
    for link in links {
        let n = ok(link);
        crate::outbound::render("t", &n.node, &n.credentials)
            .unwrap_or_else(|e| panic!("{link}: {e}"));
    }
}
