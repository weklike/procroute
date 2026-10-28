// SPDX-License-Identifier: GPL-3.0-or-later
//! `hysteria2://` / `hy2://`、`tuic://`、`anytls://`、`socks(5)://`、`http(s)://`。

use procroute_platform_win::secret::Secret;

use super::uri::{Uri, decode, parse_port};
use super::{LinkError, Parsed, alpn, base64};
use crate::node::{
    Credentials, Hysteria2Obfs, Node, Settings, Tls, TuicCongestion, TuicUdpRelayMode,
};

/// Hysteria 2 官方 URI：`hysteria2://auth@host:port[,端口范围]/?obfs=salamander&obfs-password=
/// &sni=&insecure=1#name`。`user:pass` 形式的认证整体作为密码。
pub(super) fn hysteria2(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    // 证书固定比 CA 校验更严格；sing-box 没有等价选项，丢掉它会悄悄降低安全性
    if uri.non_empty("pinSHA256").is_some() {
        return Err(LinkError::UnsupportedCertPin);
    }
    let obfs = match uri.param("obfs").unwrap_or("") {
        "" | "none" => None,
        "salamander" => Some(Hysteria2Obfs::Salamander),
        _ => return Err(LinkError::UnsupportedObfs),
    };
    let (server_port, server_ports) = hysteria2_ports(uri.port.as_deref().unwrap_or("443"))?;
    let auth = decode(uri.userinfo.as_deref().unwrap_or(""))?;
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port,
            settings: Settings::Hysteria2 {
                tls: tls(&uri),
                server_ports,
                obfs,
            },
        },
        credentials: Credentials {
            password: secret(auth),
            obfs_password: obfs
                .and(uri.param("obfs-password").map(str::to_owned))
                .and_then(secret),
            ..Default::default()
        },
    })
}

/// `443`、`443,20000-30000`、`20000-30000`：第一个单独端口（或第一个范围的起点）作为主端口，
/// 范围转成 sing-box 的 `起:止`。
fn hysteria2_ports(spec: &str) -> Result<(u16, Vec<String>), LinkError> {
    let mut main = None;
    let mut ranges = Vec::new();
    for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (parse_port(a)?, parse_port(b)?);
                if a > b {
                    return Err(LinkError::InvalidPort);
                }
                main.get_or_insert(a);
                ranges.push(format!("{a}:{b}"));
            }
            None => {
                let p = parse_port(part)?;
                if main.is_none() {
                    main = Some(p);
                } else {
                    ranges.push(p.to_string());
                }
            }
        }
    }
    Ok((main.ok_or(LinkError::InvalidPort)?, ranges))
}

/// TUIC v5：`tuic://uuid:password@host:port?congestion_control=bbr&udp_relay_mode=native&alpn=h3
/// &sni=&allow_insecure=1#name`。
pub(super) fn tuic(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    let userinfo = uri.userinfo.as_deref().ok_or(LinkError::Malformed)?;
    let (uuid, password) = userinfo.split_once(':').ok_or(LinkError::Malformed)?;
    let congestion_control = match uri.param("congestion_control").unwrap_or("") {
        "" => None,
        "cubic" => Some(TuicCongestion::Cubic),
        "new_reno" | "newreno" => Some(TuicCongestion::NewReno),
        "bbr" => Some(TuicCongestion::Bbr),
        _ => return Err(LinkError::Malformed),
    };
    let udp_relay_mode = match uri.param("udp_relay_mode").unwrap_or("") {
        "" => None,
        "native" => Some(TuicUdpRelayMode::Native),
        "quic" => Some(TuicUdpRelayMode::Quic),
        _ => return Err(LinkError::Malformed),
    };
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Tuic {
                tls: tls(&uri),
                congestion_control,
                udp_relay_mode,
            },
        },
        credentials: Credentials {
            uuid: secret(decode(uuid)?.to_ascii_lowercase()),
            password: secret(decode(password)?),
            ..Default::default()
        },
    })
}

/// `anytls://password@host:port/?sni=&insecure=1#name`。
pub(super) fn anytls(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    let password = decode(uri.userinfo.as_deref().ok_or(LinkError::Malformed)?)?;
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Anytls { tls: tls(&uri) },
        },
        credentials: Credentials {
            password: secret(password),
            ..Default::default()
        },
    })
}

/// `socks5://user:pass@host:port#name`；v2rayN 的 `socks://Base64(user:pass)@host:port#name` 也接受。
pub(super) fn socks(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Socks,
        },
        credentials: user_pass(uri.userinfo.as_deref())?,
    })
}

/// `http(s)://user:pass@host:port#name`。带路径或查询参数的多半是订阅地址，拒绝而不是当成代理。
pub(super) fn http(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    if !(uri.path.is_empty() || uri.path == "/") || !uri.query.is_empty() || uri.port.is_none() {
        return Err(LinkError::LooksLikeSubscriptionUrl);
    }
    let tls = (uri.scheme == "https").then(Tls::default);
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Http { tls },
        },
        credentials: user_pass(uri.userinfo.as_deref())?,
    })
}

/// SNI / insecure / ALPN 这几个通用参数。
fn tls(uri: &Uri) -> Tls {
    Tls {
        server_name: uri
            .non_empty("sni")
            .or_else(|| uri.non_empty("peer"))
            .map(str::to_owned),
        insecure: uri.flag("insecure") || uri.flag("allow_insecure") || uri.flag("allowInsecure"),
        alpn: alpn(uri.param("alpn")),
        fingerprint: None,
        reality: None,
    }
}

/// `user:pass`（百分号编码）或其 Base64。
fn user_pass(userinfo: Option<&str>) -> Result<Credentials, LinkError> {
    let Some(raw) = userinfo.filter(|u| !u.is_empty()) else {
        return Ok(Credentials::default());
    };
    // 先按未编码的 `:` 拆开再分别解码，避免对 `%25` 之类的内容解码两次
    let (user, pass) = match raw.split_once(':') {
        Some((u, p)) => (decode(u)?, decode(p)?),
        None => {
            let plain = base64::decode_text(&decode(raw)?).ok_or(LinkError::Malformed)?;
            let (u, p) = plain.split_once(':').ok_or(LinkError::Malformed)?;
            (u.to_owned(), p.to_owned())
        }
    };
    Ok(Credentials {
        username: secret(user),
        password: secret(pass),
        ..Default::default()
    })
}

fn secret(s: impl Into<String>) -> Option<Secret<String>> {
    let s = s.into();
    (!s.is_empty()).then(|| Secret::new(s))
}
