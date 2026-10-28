// SPDX-License-Identifier: GPL-3.0-or-later
//! `ss://`：SIP002，以及仍然常见的旧版整段 Base64 写法；SIP008 订阅里的单个服务器。
//!
//! - SIP002：`ss://<userinfo>@host:port/?plugin=...#name`，userinfo 为 `Base64URL(method:password)`，
//!   2022 加密按 SIP022 用百分号编码的明文 `method:password`；
//! - 旧版：`ss://Base64(method:password@host:port)#name`。

use procroute_platform_win::secret::Secret;
use serde_json::Value;

use super::uri::{Uri, decode, parse_port};
use super::{LinkError, Parsed, base64};
use crate::node::{Credentials, Node, Settings, SsMethod, SsPlugin, SsPluginKind};

pub(super) fn parse(link: &str) -> Result<Parsed, LinkError> {
    let body = &link["ss://".len()..];
    let before_fragment = body.split('#').next().unwrap_or(body);
    if !before_fragment.contains('@') {
        return legacy(body);
    }
    let uri = Uri::parse(link)?;
    let userinfo = uri.userinfo.as_deref().ok_or(LinkError::Malformed)?;
    let (method, password) = method_password(userinfo)?;
    let plugin = uri.param("plugin").map(plugin).transpose()?.flatten();
    Ok(Parsed {
        name: uri.fragment.clone(),
        node: Node {
            server: uri.host.clone(),
            server_port: uri.single_port()?,
            settings: Settings::Shadowsocks { method, plugin },
        },
        credentials: password,
    })
}

/// 旧版：`#` 之前整段是 Base64。
fn legacy(body: &str) -> Result<Parsed, LinkError> {
    let (encoded, fragment) = match body.split_once('#') {
        Some((e, f)) => (e, Some(decode(f)?)),
        None => (body, None),
    };
    let plain = base64::decode_text(encoded.trim_end_matches('/')).ok_or(LinkError::Malformed)?;
    let rebuilt = Uri::parse(&format!("ss://{plain}"))?;
    let userinfo = rebuilt.userinfo.as_deref().ok_or(LinkError::Malformed)?;
    let (method_s, password) = userinfo.split_once(':').ok_or(LinkError::Malformed)?;
    let method = SsMethod::parse(method_s).ok_or(LinkError::UnsupportedCipher)?;
    Ok(Parsed {
        name: fragment,
        node: Node {
            server: rebuilt.host.clone(),
            server_port: rebuilt.single_port()?,
            settings: Settings::Shadowsocks {
                method,
                plugin: None,
            },
        },
        credentials: password_only(password),
    })
}

/// userinfo：百分号编码的明文 `method:password`，或 `Base64URL(method:password)`。
fn method_password(userinfo: &str) -> Result<(SsMethod, Credentials), LinkError> {
    let plain = decode(userinfo)?;
    let plain = if plain.contains(':') {
        plain
    } else {
        base64::decode_text(&plain).ok_or(LinkError::Malformed)?
    };
    let (method, password) = plain.split_once(':').ok_or(LinkError::Malformed)?;
    let method = SsMethod::parse(method).ok_or(LinkError::UnsupportedCipher)?;
    Ok((method, password_only(password)))
}

/// `plugin` 参数：`名称;选项`。空值表示没有插件。
fn plugin(value: &str) -> Result<Option<SsPlugin>, LinkError> {
    let (name, opts) = value.split_once(';').unwrap_or((value, ""));
    let kind = match name.trim() {
        "" => return Ok(None),
        "obfs-local" | "simple-obfs" => SsPluginKind::ObfsLocal,
        "v2ray-plugin" => SsPluginKind::V2rayPlugin,
        _ => return Err(LinkError::UnsupportedPlugin),
    };
    Ok(Some(SsPlugin {
        kind,
        opts: opts.to_owned(),
    }))
}

fn password_only(password: &str) -> Credentials {
    Credentials {
        password: (!password.is_empty()).then(|| Secret::new(password.to_owned())),
        ..Default::default()
    }
}

/// SIP008 订阅中的一个服务器。
pub(super) fn from_sip008(v: &Value) -> Result<Parsed, LinkError> {
    let s = |k: &str| v.get(k).and_then(Value::as_str);
    let port = match v.get("server_port") {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or(LinkError::InvalidPort)?,
        Some(Value::String(p)) => parse_port(p)?,
        _ => return Err(LinkError::InvalidPort),
    };
    let method = SsMethod::parse(s("method").ok_or(LinkError::Malformed)?)
        .ok_or(LinkError::UnsupportedCipher)?;
    let plugin = match s("plugin").filter(|p| !p.is_empty()) {
        Some(name) => plugin(&format!("{name};{}", s("plugin_opts").unwrap_or("")))?,
        None => None,
    };
    Ok(Parsed {
        name: s("remarks").map(str::to_owned),
        node: Node {
            server: s("server").ok_or(LinkError::Malformed)?.to_owned(),
            server_port: port,
            settings: Settings::Shadowsocks { method, plugin },
        },
        credentials: password_only(s("password").unwrap_or("")),
    })
}
