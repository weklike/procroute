// SPDX-License-Identifier: GPL-3.0-or-later
//! `vless://` 与 `trojan://`：Xray 分享链接标准（XTLS/Xray-core#91）的查询参数。
//!
//! `vless://uuid@host:port?encryption=none&security=tls|reality|none&type=tcp|ws|grpc|h2|httpupgrade
//! &sni=&alpn=&fp=&pbk=&sid=&flow=&path=&host=&serviceName=&headerType=#name`；
//! `trojan://password@host:port?...` 参数相同，另兼容 trojan-gfw 的 `peer`、`allowInsecure`。

use procroute_platform_win::secret::Secret;

use super::uri::{Uri, decode};
use super::{LinkError, Parsed, alpn, fingerprint, transport};
use crate::node::{Credentials, Node, Reality, Settings, Tls, Transport, VlessFlow};

pub(super) fn parse_vless(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    // VLESS 的后量子 `encryption` 是 Xray 2025 年的扩展，sing-box 不支持
    if !matches!(uri.param("encryption").unwrap_or("none"), "" | "none") {
        return Err(LinkError::UnsupportedEncryption);
    }
    let flow = match uri.param("flow").unwrap_or("") {
        "" => None,
        "xtls-rprx-vision" | "xtls-rprx-vision-udp443" => Some(VlessFlow::XtlsRprxVision),
        _ => return Err(LinkError::UnsupportedFlow),
    };
    let tls = security(&uri, false)?;
    let transport = transport_of(&uri)?;
    let uuid = decode(uri.userinfo.as_deref().ok_or(LinkError::Malformed)?)?;
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Vless {
                flow,
                tls,
                transport,
            },
        },
        credentials: Credentials {
            uuid: (!uuid.is_empty()).then(|| Secret::new(uuid.to_ascii_lowercase())),
            ..Default::default()
        },
    })
}

pub(super) fn parse_trojan(link: &str) -> Result<Parsed, LinkError> {
    let uri = Uri::parse(link)?;
    let tls = security(&uri, true)?.ok_or(LinkError::UnsupportedSecurity)?;
    if tls.reality.is_some() {
        // trojan + REALITY 不是通行组合，sing-box 也不建议
        return Err(LinkError::UnsupportedSecurity);
    }
    let transport = transport_of(&uri)?;
    let password = decode(uri.userinfo.as_deref().ok_or(LinkError::Malformed)?)?;
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Trojan { tls, transport },
        },
        credentials: Credentials {
            password: (!password.is_empty()).then(|| Secret::new(password)),
            ..Default::default()
        },
    })
}

/// `security` 参数：`tls` / `reality` / `none`。`default_tls` 为真时缺省按 TLS 处理（trojan）。
fn security(uri: &Uri, default_tls: bool) -> Result<Option<Tls>, LinkError> {
    let security = uri.param("security").unwrap_or("").to_ascii_lowercase();
    let security = match security.as_str() {
        "" if default_tls => "tls",
        "" => "none",
        s => s,
    };
    let server_name = uri
        .non_empty("sni")
        .or_else(|| uri.non_empty("peer"))
        .map(str::to_owned);
    let base = || Tls {
        server_name: server_name.clone(),
        insecure: uri.flag("allowInsecure") || uri.flag("insecure"),
        alpn: alpn(uri.param("alpn")),
        fingerprint: fingerprint(uri.param("fp")),
        reality: None,
    };
    Ok(match security {
        "none" => None,
        "tls" => Some(base()),
        "reality" => {
            let public_key = uri
                .non_empty("pbk")
                .ok_or(LinkError::Invalid(crate::node::NodeError::InvalidReality))?;
            Some(Tls {
                // REALITY 不校验证书，`insecure` 没有意义
                insecure: false,
                alpn: Vec::new(),
                reality: Some(Reality {
                    public_key: public_key.to_owned(),
                    short_id: uri.param("sid").unwrap_or("").to_owned(),
                }),
                ..base()
            })
        }
        _ => return Err(LinkError::UnsupportedSecurity),
    })
}

fn transport_of(uri: &Uri) -> Result<Option<Transport>, LinkError> {
    transport(
        uri.param("type").unwrap_or(""),
        uri.param("headerType").unwrap_or(""),
        uri.param("path").unwrap_or(""),
        uri.param("host").unwrap_or(""),
        uri.param("serviceName").unwrap_or(""),
    )
}
