// SPDX-License-Identifier: GPL-3.0-or-later
//! 节点模型的单元测试。

use super::*;

const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";

fn secret(s: &str) -> Option<Secret<String>> {
    Some(Secret::new(s.to_owned()))
}

fn trojan() -> Node {
    Node {
        server: "hk1.example.net".into(),
        server_port: 443,
        settings: Settings::Trojan {
            tls: Tls::default(),
            transport: None,
        },
    }
}

#[test]
fn settings_serialize_without_credentials() {
    let node = Node {
        server: "1.2.3.4".into(),
        server_port: 8388,
        settings: Settings::Shadowsocks {
            method: SsMethod::Blake3Aes128Gcm,
            plugin: None,
        },
    };
    let json = serde_json::to_string(&node).unwrap();
    assert_eq!(
        json,
        r#"{"server":"1.2.3.4","server_port":8388,"settings":{"protocol":"shadowsocks","method":"2022-blake3-aes-128-gcm"}}"#
    );
    let back: Node = serde_json::from_str(&json).unwrap();
    assert_eq!(back, node);
}

#[test]
fn credentials_debug_is_masked() {
    let c = Credentials {
        password: secret("hunter2"),
        uuid: secret(UUID),
        ..Default::default()
    };
    let dbg = format!("{c:?}");
    assert!(!dbg.contains("hunter2") && !dbg.contains(UUID), "{dbg}");
    assert!(c.is_set());
    assert!(!Credentials::default().is_set());
}

#[test]
fn required_credentials_are_enforced() {
    let node = trojan();
    assert_eq!(
        node.validate(&Credentials::default()),
        Err(NodeError::MissingCredential("password"))
    );
    let ok = Credentials {
        password: secret("p"),
        ..Default::default()
    };
    assert_eq!(node.validate(&ok), Ok(()));

    let tuic = Node {
        settings: Settings::Tuic {
            tls: Tls::default(),
            congestion_control: None,
            udp_relay_mode: None,
        },
        ..trojan()
    };
    let only_uuid = Credentials {
        uuid: secret(UUID),
        ..Default::default()
    };
    assert_eq!(
        tuic.validate(&only_uuid),
        Err(NodeError::MissingCredential("password"))
    );
    let bad_uuid = Credentials {
        uuid: secret("not-a-uuid"),
        password: secret("p"),
        ..Default::default()
    };
    assert_eq!(tuic.validate(&bad_uuid), Err(NodeError::InvalidUuid));
}

#[test]
fn socks_auth_must_be_complete() {
    let node = Node {
        settings: Settings::Socks,
        ..trojan()
    };
    assert_eq!(node.validate(&Credentials::default()), Ok(()));
    let half = Credentials {
        username: secret("u"),
        ..Default::default()
    };
    assert_eq!(node.validate(&half), Err(NodeError::IncompleteAuth));
}

#[test]
fn rejects_bad_server_port_and_params() {
    let creds = Credentials {
        password: secret("p"),
        ..Default::default()
    };
    for server in ["", "a b", "a/b", "user@host", "[::1]", &"a".repeat(254)] {
        let node = Node {
            server: server.to_owned(),
            ..trojan()
        };
        assert_eq!(
            node.validate(&creds),
            Err(NodeError::InvalidServer),
            "{server:?}"
        );
    }
    let node = Node {
        server_port: 0,
        ..trojan()
    };
    assert_eq!(node.validate(&creds), Err(NodeError::InvalidPort));
    let node = Node {
        settings: Settings::Trojan {
            tls: Tls {
                server_name: Some("a\nb".into()),
                ..Default::default()
            },
            transport: None,
        },
        ..trojan()
    };
    assert_eq!(node.validate(&creds), Err(NodeError::InvalidParam("sni")));
    let ctl = Credentials {
        password: secret("a\u{0}b"),
        ..Default::default()
    };
    assert_eq!(
        trojan().validate(&ctl),
        Err(NodeError::InvalidCredential("password"))
    );
}

#[test]
fn reality_and_port_ranges_are_checked() {
    let creds = Credentials {
        uuid: secret(UUID),
        ..Default::default()
    };
    let vless = |public_key: &str, short_id: &str| Node {
        settings: Settings::Vless {
            flow: Some(VlessFlow::XtlsRprxVision),
            tls: Some(Tls {
                reality: Some(Reality {
                    public_key: public_key.into(),
                    short_id: short_id.into(),
                }),
                ..Default::default()
            }),
            transport: None,
        },
        ..trojan()
    };
    let key = "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0";
    assert_eq!(vless(key, "0123456789abcdef").validate(&creds), Ok(()));
    assert_eq!(vless(key, "").validate(&creds), Ok(()));
    assert_eq!(
        vless(key, "abc").validate(&creds),
        Err(NodeError::InvalidReality)
    );
    assert_eq!(
        vless("short", "").validate(&creds),
        Err(NodeError::InvalidReality)
    );

    assert!(is_port_range("443"));
    assert!(is_port_range("20000:30000"));
    assert!(!is_port_range("30000:20000"));
    assert!(!is_port_range("0:10"));
    assert!(!is_port_range("a:b"));
}

#[test]
fn names_round_trip() {
    for m in SsMethod::ALL {
        assert_eq!(SsMethod::parse(m.as_str()), Some(m));
        assert_eq!(serde_json::to_value(m).unwrap(), m.as_str());
    }
    assert_eq!(SsMethod::parse("AES-256-GCM"), Some(SsMethod::Aes256Gcm));
    assert_eq!(SsMethod::parse("rc4-md5"), None);
    for f in Fingerprint::ALL {
        assert_eq!(Fingerprint::parse(f.as_str()), Some(f));
        assert_eq!(serde_json::to_value(f).unwrap(), f.as_str());
    }
    for c in [
        TuicCongestion::Cubic,
        TuicCongestion::NewReno,
        TuicCongestion::Bbr,
    ] {
        assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
    }
    for m in [TuicUdpRelayMode::Native, TuicUdpRelayMode::Quic] {
        assert_eq!(serde_json::to_value(m).unwrap(), m.as_str());
    }
    for s in [
        VmessSecurity::Auto,
        VmessSecurity::Aes128Gcm,
        VmessSecurity::Chacha20Poly1305,
        VmessSecurity::None,
        VmessSecurity::Zero,
    ] {
        assert_eq!(serde_json::to_value(s).unwrap(), s.as_str());
    }
}
