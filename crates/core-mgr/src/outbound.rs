// SPDX-License-Identifier: GPL-3.0-or-later
//! 把 [`Node`] 渲染成 sing-box 1.14 的出站。
//!
//! 字段名以锁定版本的文档为准（`docs/configuration/outbound/*.md`、`shared/tls.md`、
//! `shared/v2ray-transport.md`）。输出里含凭据明文，只能交给 [`crate::config_gen`] 拼进
//! 整体配置，再以 `Secret` 返回。

use serde_json::{Map, Value, json};

use procroute_platform_win::secret::Secret;

use crate::node::{Credentials, Node, NodeError, Settings, SsPluginKind, Tls, Transport};

/// REALITY 需要 uTLS；分享链接没给指纹时使用的默认值。
const DEFAULT_REALITY_FINGERPRINT: &str = "chrome";

/// 渲染一个节点出站。先做 [`Node::validate`]，凭据缺失或格式不对时不产出任何内容。
pub(crate) fn render(tag: &str, node: &Node, creds: &Credentials) -> Result<Value, NodeError> {
    node.validate(creds)?;
    let mut o = Map::new();
    let kind = match &node.settings {
        Settings::Shadowsocks { method, plugin } => {
            o.insert("method".into(), json!(method.as_str()));
            put_secret(&mut o, "password", &creds.password);
            if let Some(p) = plugin {
                let name = match p.kind {
                    SsPluginKind::ObfsLocal => "obfs-local",
                    SsPluginKind::V2rayPlugin => "v2ray-plugin",
                };
                o.insert("plugin".into(), json!(name));
                o.insert("plugin_opts".into(), json!(p.opts));
            }
            "shadowsocks"
        }
        Settings::Vmess {
            security,
            tls,
            transport,
        } => {
            put_secret(&mut o, "uuid", &creds.uuid);
            o.insert("security".into(), json!(security.as_str()));
            // 只支持 AEAD；alter_id 固定为 0。
            o.insert("alter_id".into(), json!(0));
            put_tls(&mut o, tls.as_ref());
            put_transport(&mut o, transport.as_ref());
            "vmess"
        }
        Settings::Vless {
            flow,
            tls,
            transport,
        } => {
            put_secret(&mut o, "uuid", &creds.uuid);
            if flow.is_some() {
                o.insert("flow".into(), json!("xtls-rprx-vision"));
            }
            put_tls(&mut o, tls.as_ref());
            put_transport(&mut o, transport.as_ref());
            "vless"
        }
        Settings::Trojan { tls, transport } => {
            put_secret(&mut o, "password", &creds.password);
            put_tls(&mut o, Some(tls));
            put_transport(&mut o, transport.as_ref());
            "trojan"
        }
        Settings::Hysteria2 {
            tls,
            server_ports,
            obfs,
        } => {
            put_secret(&mut o, "password", &creds.password);
            if !server_ports.is_empty() {
                o.insert("server_ports".into(), json!(server_ports));
            }
            if obfs.is_some() {
                let password = creds.obfs_password.as_ref().map(|s| s.expose().as_str());
                o.insert(
                    "obfs".into(),
                    json!({ "type": "salamander", "password": password }),
                );
            }
            put_tls(&mut o, Some(tls));
            "hysteria2"
        }
        Settings::Tuic {
            tls,
            congestion_control,
            udp_relay_mode,
        } => {
            put_secret(&mut o, "uuid", &creds.uuid);
            put_secret(&mut o, "password", &creds.password);
            if let Some(cc) = congestion_control {
                o.insert("congestion_control".into(), json!(cc.as_str()));
            }
            if let Some(mode) = udp_relay_mode {
                o.insert("udp_relay_mode".into(), json!(mode.as_str()));
            }
            put_tls(&mut o, Some(tls));
            "tuic"
        }
        Settings::Anytls { tls } => {
            put_secret(&mut o, "password", &creds.password);
            put_tls(&mut o, Some(tls));
            "anytls"
        }
        Settings::Socks => {
            o.insert("version".into(), json!("5"));
            put_secret(&mut o, "username", &creds.username);
            put_secret(&mut o, "password", &creds.password);
            "socks"
        }
        Settings::Http { tls } => {
            put_secret(&mut o, "username", &creds.username);
            put_secret(&mut o, "password", &creds.password);
            put_tls(&mut o, tls.as_ref());
            "http"
        }
    };
    o.insert("type".into(), json!(kind));
    o.insert("tag".into(), json!(tag));
    o.insert("server".into(), json!(node.server));
    o.insert("server_port".into(), json!(node.server_port));
    Ok(Value::Object(o))
}

fn put_secret(o: &mut Map<String, Value>, key: &str, v: &Option<Secret<String>>) {
    if let Some(s) = v {
        o.insert(key.into(), json!(s.expose()));
    }
}

fn put_tls(o: &mut Map<String, Value>, tls: Option<&Tls>) {
    let Some(tls) = tls else { return };
    let mut t = Map::new();
    t.insert("enabled".into(), json!(true));
    if let Some(sni) = &tls.server_name {
        t.insert("server_name".into(), json!(sni));
    }
    if tls.insecure {
        t.insert("insecure".into(), json!(true));
    }
    if !tls.alpn.is_empty() {
        t.insert("alpn".into(), json!(tls.alpn));
    }
    let fingerprint = tls
        .fingerprint
        .map(|f| f.as_str())
        .or_else(|| tls.reality.is_some().then_some(DEFAULT_REALITY_FINGERPRINT));
    if let Some(fp) = fingerprint {
        t.insert("utls".into(), json!({ "enabled": true, "fingerprint": fp }));
    }
    if let Some(r) = &tls.reality {
        t.insert(
            "reality".into(),
            json!({ "enabled": true, "public_key": r.public_key, "short_id": r.short_id }),
        );
    }
    o.insert("tls".into(), Value::Object(t));
}

fn put_transport(o: &mut Map<String, Value>, transport: Option<&Transport>) {
    let Some(transport) = transport else { return };
    let value = match transport {
        Transport::Ws {
            path,
            host,
            max_early_data,
        } => {
            let mut t = Map::new();
            t.insert("type".into(), json!("ws"));
            t.insert("path".into(), json!(path));
            if let Some(h) = host {
                t.insert("headers".into(), json!({ "Host": h }));
            }
            if let Some(n) = max_early_data {
                t.insert("max_early_data".into(), json!(n));
                t.insert(
                    "early_data_header_name".into(),
                    json!("Sec-WebSocket-Protocol"),
                );
            }
            Value::Object(t)
        }
        Transport::Grpc { service_name } => json!({ "type": "grpc", "service_name": service_name }),
        Transport::Http { path, host } => {
            let mut t = Map::new();
            t.insert("type".into(), json!("http"));
            t.insert("path".into(), json!(path));
            if !host.is_empty() {
                t.insert("host".into(), json!(host));
            }
            Value::Object(t)
        }
        Transport::Httpupgrade { path, host } => {
            let mut t = Map::new();
            t.insert("type".into(), json!("httpupgrade"));
            t.insert("path".into(), json!(path));
            if let Some(h) = host {
                t.insert("host".into(), json!(h));
            }
            Value::Object(t)
        }
    };
    o.insert("transport".into(), value);
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::node::*;

    pub(crate) const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
    pub(crate) const REALITY_KEY: &str = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";

    fn s(v: &str) -> Option<Secret<String>> {
        Some(Secret::new(v.to_owned()))
    }

    /// 每种协议、每种传输层各一个节点，供渲染测试与 `sing-box check` 回归共用。
    pub(crate) fn sample_nodes() -> Vec<(String, Node, Credentials)> {
        let tls = |sni: &str| Tls {
            server_name: Some(sni.into()),
            ..Default::default()
        };
        let pw = |p: &str| Credentials {
            password: s(p),
            ..Default::default()
        };
        let id = || Credentials {
            uuid: s(UUID),
            ..Default::default()
        };
        let node = |server: &str, port: u16, settings: Settings| Node {
            server: server.into(),
            server_port: port,
            settings,
        };
        vec![
            (
                "ss".into(),
                node(
                    "203.0.113.1",
                    8388,
                    Settings::Shadowsocks {
                        method: SsMethod::Aes256Gcm,
                        plugin: Some(SsPlugin {
                            kind: SsPluginKind::ObfsLocal,
                            opts: "obfs=http;obfs-host=cdn.example.com".into(),
                        }),
                    },
                ),
                pw("ss-password"),
            ),
            (
                "ss2022".into(),
                node(
                    "2001:db8::1",
                    8388,
                    Settings::Shadowsocks {
                        method: SsMethod::Blake3Aes128Gcm,
                        plugin: None,
                    },
                ),
                pw("8JCsPssfgS8tiRwiMlhARg=="),
            ),
            (
                "vmess-ws".into(),
                node(
                    "vm.example.com",
                    443,
                    Settings::Vmess {
                        security: VmessSecurity::Auto,
                        tls: Some(tls("vm.example.com")),
                        transport: Some(Transport::Ws {
                            path: "/ray".into(),
                            host: Some("vm.example.com".into()),
                            max_early_data: Some(2048),
                        }),
                    },
                ),
                id(),
            ),
            (
                "vless-reality".into(),
                node(
                    "vl.example.com",
                    443,
                    Settings::Vless {
                        flow: Some(VlessFlow::XtlsRprxVision),
                        tls: Some(Tls {
                            server_name: Some("www.example.org".into()),
                            fingerprint: Some(Fingerprint::Firefox),
                            reality: Some(Reality {
                                public_key: REALITY_KEY.into(),
                                short_id: "0123456789abcdef".into(),
                            }),
                            ..Default::default()
                        }),
                        transport: None,
                    },
                ),
                id(),
            ),
            (
                "vless-grpc".into(),
                node(
                    "vl.example.com",
                    443,
                    Settings::Vless {
                        flow: None,
                        tls: Some(tls("vl.example.com")),
                        transport: Some(Transport::Grpc {
                            service_name: "grpc".into(),
                        }),
                    },
                ),
                id(),
            ),
            (
                "vless-h2".into(),
                node(
                    "vl.example.com",
                    443,
                    Settings::Vless {
                        flow: None,
                        tls: Some(tls("vl.example.com")),
                        transport: Some(Transport::Http {
                            path: "/h2".into(),
                            host: vec!["vl.example.com".into()],
                        }),
                    },
                ),
                id(),
            ),
            (
                "vless-httpupgrade".into(),
                node(
                    "vl.example.com",
                    80,
                    Settings::Vless {
                        flow: None,
                        tls: None,
                        transport: Some(Transport::Httpupgrade {
                            path: "/up".into(),
                            host: Some("vl.example.com".into()),
                        }),
                    },
                ),
                id(),
            ),
            (
                "trojan".into(),
                node(
                    "tj.example.com",
                    443,
                    Settings::Trojan {
                        tls: Tls {
                            alpn: vec!["h2".into(), "http/1.1".into()],
                            insecure: true,
                            ..tls("tj.example.com")
                        },
                        transport: None,
                    },
                ),
                pw("trojan-password"),
            ),
            (
                "hy2".into(),
                node(
                    "hy.example.com",
                    443,
                    Settings::Hysteria2 {
                        tls: tls("hy.example.com"),
                        server_ports: vec!["20000:30000".into()],
                        obfs: Some(Hysteria2Obfs::Salamander),
                    },
                ),
                Credentials {
                    password: s("hy2-password"),
                    obfs_password: s("obfs-password"),
                    ..Default::default()
                },
            ),
            (
                "tuic".into(),
                node(
                    "tu.example.com",
                    443,
                    Settings::Tuic {
                        tls: Tls {
                            alpn: vec!["h3".into()],
                            ..tls("tu.example.com")
                        },
                        congestion_control: Some(TuicCongestion::Bbr),
                        udp_relay_mode: Some(TuicUdpRelayMode::Native),
                    },
                ),
                Credentials {
                    uuid: s(UUID),
                    password: s("tuic-password"),
                    ..Default::default()
                },
            ),
            (
                "anytls".into(),
                node(
                    "at.example.com",
                    443,
                    Settings::Anytls {
                        tls: tls("at.example.com"),
                    },
                ),
                pw("anytls-password"),
            ),
            (
                "socks".into(),
                node("198.51.100.7", 1080, Settings::Socks),
                Credentials {
                    username: s("user"),
                    password: s("socks-password"),
                    ..Default::default()
                },
            ),
            (
                "https".into(),
                node(
                    "px.example.com",
                    443,
                    Settings::Http {
                        tls: Some(tls("px.example.com")),
                    },
                ),
                Credentials::default(),
            ),
        ]
    }

    #[test]
    fn renders_shadowsocks_with_plugin() {
        let (tag, node, creds) = &sample_nodes()[0];
        assert_eq!(
            render(tag, node, creds).unwrap(),
            json!({
                "type": "shadowsocks", "tag": "ss", "server": "203.0.113.1", "server_port": 8388,
                "method": "aes-256-gcm", "password": "ss-password",
                "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=cdn.example.com"
            })
        );
    }

    #[test]
    fn renders_vmess_ws_with_early_data() {
        let (tag, node, creds) = &sample_nodes()[2];
        assert_eq!(
            render(tag, node, creds).unwrap(),
            json!({
                "type": "vmess", "tag": "vmess-ws", "server": "vm.example.com", "server_port": 443,
                "uuid": UUID, "security": "auto", "alter_id": 0,
                "tls": { "enabled": true, "server_name": "vm.example.com" },
                "transport": {
                    "type": "ws", "path": "/ray", "headers": { "Host": "vm.example.com" },
                    "max_early_data": 2048, "early_data_header_name": "Sec-WebSocket-Protocol"
                }
            })
        );
    }

    #[test]
    fn reality_always_enables_utls() {
        let (tag, node, creds) = &sample_nodes()[3];
        let v = render(tag, node, creds).unwrap();
        assert_eq!(v["flow"], "xtls-rprx-vision");
        assert_eq!(
            v["tls"]["utls"],
            json!({ "enabled": true, "fingerprint": "firefox" })
        );
        assert_eq!(v["tls"]["reality"]["public_key"], REALITY_KEY);

        // 没给指纹时 REALITY 仍然要 uTLS（sing-box：uTLS is required by reality client）
        let mut node = node.clone();
        if let Settings::Vless { tls: Some(t), .. } = &mut node.settings {
            t.fingerprint = None;
        }
        let v = render(tag, &node, creds).unwrap();
        assert_eq!(v["tls"]["utls"]["fingerprint"], "chrome");
    }

    #[test]
    fn renders_hysteria2_obfs_and_ports() {
        let (tag, node, creds) = &sample_nodes()[8];
        let v = render(tag, node, creds).unwrap();
        assert_eq!(
            v["obfs"],
            json!({ "type": "salamander", "password": "obfs-password" })
        );
        assert_eq!(v["server_ports"], json!(["20000:30000"]));
        assert_eq!(v["password"], "hy2-password");
    }

    #[test]
    fn renders_tuic_and_socks() {
        let nodes = sample_nodes();
        let (tag, node, creds) = &nodes[9];
        let v = render(tag, node, creds).unwrap();
        assert_eq!(v["congestion_control"], "bbr");
        assert_eq!(v["udp_relay_mode"], "native");
        assert_eq!(v["tls"]["alpn"], json!(["h3"]));
        let (tag, node, creds) = &nodes[11];
        let v = render(tag, node, creds).unwrap();
        assert_eq!(v["version"], "5");
        assert_eq!(v["username"], "user");
        // 无认证的 HTTP 代理不输出用户名密码字段
        let (tag, node, creds) = &nodes[12];
        let v = render(tag, node, creds).unwrap();
        assert!(v.get("username").is_none() && v.get("password").is_none());
    }

    #[test]
    fn missing_credentials_produce_no_output() {
        let (tag, node, _) = &sample_nodes()[7];
        assert_eq!(
            render(tag, node, &Credentials::default()),
            Err(NodeError::MissingCredential("password"))
        );
    }
}
