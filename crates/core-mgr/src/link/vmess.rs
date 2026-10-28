// SPDX-License-Identifier: GPL-3.0-or-later
//! `vmess://Base64(JSON)`：v2rayN 第 2 版约定。
//!
//! 只收 AEAD 认证（`aid` 为 0）：V2Fly 与 Xray 自 2022 年起已强制 AEAD，旧版 MD5 认证的节点
//! 在现行服务端上已无法使用。

use procroute_platform_win::secret::Secret;
use serde_json::Value;

use super::uri::parse_port;
use super::{LinkError, Parsed, alpn, base64, fingerprint, transport};
use crate::node::{Credentials, Node, Settings, Tls, VmessSecurity};

pub(super) fn parse(link: &str) -> Result<Parsed, LinkError> {
    let body = &link["vmess://".len()..];
    // 少数客户端会在 Base64 之后附加 `#备注`
    let encoded = body.split('#').next().unwrap_or(body);
    let json = base64::decode_text(encoded).ok_or(LinkError::Malformed)?;
    let v: Value = serde_json::from_str(&json).map_err(|_| LinkError::Malformed)?;
    if !v.is_object() {
        return Err(LinkError::Malformed);
    }
    let f = |k: &str| field(&v, k);

    let aid = f("aid");
    if !(aid.is_empty() || aid == "0") {
        return Err(LinkError::LegacyVmess);
    }
    let security = match f("scy").to_ascii_lowercase().as_str() {
        "" | "auto" => VmessSecurity::Auto,
        "aes-128-gcm" => VmessSecurity::Aes128Gcm,
        "chacha20-poly1305" => VmessSecurity::Chacha20Poly1305,
        "none" => VmessSecurity::None,
        "zero" => VmessSecurity::Zero,
        _ => return Err(LinkError::UnsupportedCipher),
    };
    let net = f("net");
    let host = f("host");
    let path = f("path");
    // gRPC 的服务名在 v2rayN 里放在 path
    let transport = transport(&net, &f("type"), &path, &host, &path)?;
    let tls = match f("tls").to_ascii_lowercase().as_str() {
        "" | "none" => None,
        "tls" => {
            let sni = f("sni");
            Some(Tls {
                server_name: Some(if sni.is_empty() { host.clone() } else { sni })
                    .filter(|s| !s.is_empty()),
                insecure: matches!(f("allowInsecure").as_str(), "1" | "true")
                    || matches!(f("insecure").as_str(), "1" | "true"),
                alpn: alpn(Some(&f("alpn"))),
                fingerprint: fingerprint(Some(&f("fp"))),
                reality: None,
            })
        }
        _ => return Err(LinkError::UnsupportedSecurity),
    };
    let uuid = f("id");
    Ok(Parsed {
        name: Some(f("ps")),
        node: Node {
            server: f("add"),
            server_port: parse_port(&f("port"))?,
            settings: Settings::Vmess {
                security,
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

/// 字符串或数字字段统一取成去掉首尾空白的字符串；缺失为空串。
fn field(v: &Value, key: &str) -> String {
    match v.get(key) {
        Some(Value::String(s)) => s.trim().to_owned(),
        Some(Value::Number(n)) => n.to_string(),
        Some(Value::Bool(b)) => b.to_string(),
        _ => String::new(),
    }
}
