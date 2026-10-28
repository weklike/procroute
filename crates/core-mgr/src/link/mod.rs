// SPDX-License-Identifier: GPL-3.0-or-later
//! 分享链接与订阅内容的解析（`node.import`）。
//!
//! 支持范围：近五年（2021 年起）主流客户端通用的格式，且锁定的 sing-box 1.14.4 能承载：
//!
//! | 格式 | 约定 | 说明 |
//! | --- | --- | --- |
//! | `ss://` | SIP002（含旧版整段 Base64） | AEAD 与 2022 加密；插件只收 `obfs-local` / `v2ray-plugin` |
//! | `vmess://` | v2rayN 第 2 版 JSON | 只收 AEAD（`aid` 为 0）；传输层 tcp / ws / grpc / h2 / httpupgrade |
//! | `vless://` | Xray 分享链接标准 | TLS / REALITY / 无加密；流控只收 `xtls-rprx-vision` |
//! | `trojan://` | trojan-gfw + Xray 扩展参数 | 必须 TLS |
//! | `hysteria2://`、`hy2://` | Hysteria 2 官方 URI | salamander 混淆、端口跳跃；不支持证书固定 `pinSHA256` |
//! | `tuic://` | TUIC v5 | |
//! | `anytls://` | sing-box / mihomo 约定 | |
//! | `socks://`、`socks5://`、`http://`、`https://` | 常规代理 URL | |
//!
//! 订阅内容：一行一个链接的纯文本、整体 Base64（v2rayN 约定，标准或 URL 安全字母表）、SIP008 JSON。
//! Clash / mihomo 的 YAML 需要 YAML 解析库，暂不支持，会明确报告。
//!
//! 不收录：SSR、Hysteria 1、Shadowsocks 流加密、VMess 旧版 MD5 认证、xhttp / kcp / quic 传输、
//! WireGuard、NaiveProxy、ShadowTLS 等（已被弃用，或锁定的 sing-box 不支持 / 需要额外组件）。
//!
//! 安全：输入不超过 10 MB、节点不超过 5000 个（C-SEC-07）；只解析，不执行任何内容；
//! 失败原因只给固定的原因代码，不回显链接内容（C-SEC-04）。

mod base64;
mod others;
mod ss;
mod uri;
mod vmess;
mod xray;

use serde_json::Value;
use thiserror::Error;

use crate::node::{Credentials, Fingerprint, Node, NodeError, Transport};

/// 一次导入的输入上限（C-SEC-07）。
pub const MAX_INPUT_BYTES: usize = 10 * 1024 * 1024;
/// 一次导入的节点上限（C-SEC-07）。
pub const MAX_NODES: usize = 5000;
/// 节点名的长度上限（字符）。
pub const MAX_NAME_CHARS: usize = 64;

/// 解析出的一个节点。
#[derive(Debug, Clone)]
pub struct ParsedNode {
    /// 输入中的行号（从 1 开始；SIP008 为服务器序号）。单独解析一条链接时为 0。
    pub line: u32,
    pub name: String,
    pub node: Node,
    pub credentials: Credentials,
}

/// 被跳过的一行。`line` 从 1 开始；0 表示针对整段输入。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Issue {
    pub line: u32,
    pub code: &'static str,
}

#[derive(Debug, Clone, Default)]
pub struct ParseOutcome {
    pub nodes: Vec<ParsedNode>,
    pub issues: Vec<Issue>,
}

/// 单条链接无法导入的原因。只有固定代码，不携带输入内容。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LinkError {
    #[error("malformed")]
    Malformed,
    #[error("unsupported_protocol")]
    UnsupportedProtocol,
    #[error("invalid_port")]
    InvalidPort,
    #[error("unsupported_cipher")]
    UnsupportedCipher,
    #[error("unsupported_plugin")]
    UnsupportedPlugin,
    #[error("vmess_legacy_alter_id")]
    LegacyVmess,
    #[error("unsupported_transport")]
    UnsupportedTransport,
    #[error("unsupported_security")]
    UnsupportedSecurity,
    #[error("unsupported_flow")]
    UnsupportedFlow,
    #[error("unsupported_encryption")]
    UnsupportedEncryption,
    #[error("unsupported_obfs")]
    UnsupportedObfs,
    #[error("unsupported_cert_pin")]
    UnsupportedCertPin,
    #[error("looks_like_subscription_url")]
    LooksLikeSubscriptionUrl,
    #[error("{}", node_error_code(.0))]
    Invalid(NodeError),
}

impl LinkError {
    /// 稳定的原因代码，界面据此翻译。
    pub fn code(&self) -> &'static str {
        match self {
            LinkError::Malformed => "malformed",
            LinkError::UnsupportedProtocol => "unsupported_protocol",
            LinkError::InvalidPort => "invalid_port",
            LinkError::UnsupportedCipher => "unsupported_cipher",
            LinkError::UnsupportedPlugin => "unsupported_plugin",
            LinkError::LegacyVmess => "vmess_legacy_alter_id",
            LinkError::UnsupportedTransport => "unsupported_transport",
            LinkError::UnsupportedSecurity => "unsupported_security",
            LinkError::UnsupportedFlow => "unsupported_flow",
            LinkError::UnsupportedEncryption => "unsupported_encryption",
            LinkError::UnsupportedObfs => "unsupported_obfs",
            LinkError::UnsupportedCertPin => "unsupported_cert_pin",
            LinkError::LooksLikeSubscriptionUrl => "looks_like_subscription_url",
            LinkError::Invalid(e) => node_error_code(e),
        }
    }
}

impl From<NodeError> for LinkError {
    fn from(e: NodeError) -> Self {
        LinkError::Invalid(e)
    }
}

fn node_error_code(e: &NodeError) -> &'static str {
    match e {
        NodeError::InvalidServer => "invalid_server",
        NodeError::InvalidPort => "invalid_port",
        NodeError::InvalidParam(_) => "invalid_parameter",
        NodeError::MissingCredential(_) => "missing_credential",
        NodeError::InvalidCredential(_) => "invalid_credential",
        NodeError::InvalidUuid => "invalid_uuid",
        NodeError::InvalidReality => "invalid_reality",
        NodeError::InvalidPortRange => "invalid_port_range",
        NodeError::IncompleteAuth => "incomplete_auth",
    }
}

/// 整段输入的问题代码。
pub const INPUT_TOO_LARGE: &str = "input_too_large";
pub const TOO_MANY_NODES: &str = "too_many_nodes";
pub const CLASH_YAML_UNSUPPORTED: &str = "clash_yaml_unsupported";
pub const EMPTY_INPUT: &str = "empty_input";

/// 解析一段文本：多行分享链接、整体 Base64 的订阅内容，或 SIP008 JSON。
pub fn parse_text(text: &str) -> ParseOutcome {
    let mut out = ParseOutcome::default();
    if text.len() > MAX_INPUT_BYTES {
        out.issues.push(Issue {
            line: 0,
            code: INPUT_TOO_LARGE,
        });
        return out;
    }
    let text = text.trim_start_matches('\u{feff}');
    let trimmed = text.trim();
    if trimmed.is_empty() {
        out.issues.push(Issue {
            line: 0,
            code: EMPTY_INPUT,
        });
        return out;
    }
    if trimmed.starts_with('{') {
        return sip008(trimmed);
    }
    if trimmed.lines().any(|l| l.trim_end() == "proxies:") {
        out.issues.push(Issue {
            line: 0,
            code: CLASH_YAML_UNSUPPORTED,
        });
        return out;
    }
    // 整体 Base64：没有 `://`，解码后才是链接列表
    let decoded = (!trimmed.contains("://"))
        .then(|| base64::decode_text(trimmed))
        .flatten()
        .filter(|d| d.contains("://"));
    let body = decoded.as_deref().unwrap_or(text);
    for (i, line) in body.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let line_no = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if out.nodes.len() >= MAX_NODES {
            out.issues.push(Issue {
                line: line_no,
                code: TOO_MANY_NODES,
            });
            break;
        }
        match parse_link(line) {
            Ok(n) => out.nodes.push(ParsedNode { line: line_no, ..n }),
            Err(e) => out.issues.push(Issue {
                line: line_no,
                code: e.code(),
            }),
        }
    }
    out
}

/// 解析单条分享链接。
pub fn parse_link(link: &str) -> Result<ParsedNode, LinkError> {
    let scheme = link
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or(LinkError::Malformed)?;
    let parsed = match scheme.as_str() {
        "ss" => ss::parse(link)?,
        "vmess" => vmess::parse(link)?,
        "vless" => xray::parse_vless(link)?,
        "trojan" => xray::parse_trojan(link)?,
        "hysteria2" | "hy2" => others::hysteria2(link)?,
        "tuic" => others::tuic(link)?,
        "anytls" => others::anytls(link)?,
        "socks" | "socks5" => others::socks(link)?,
        "http" | "https" => others::http(link)?,
        _ => return Err(LinkError::UnsupportedProtocol),
    };
    parsed.node.validate(&parsed.credentials)?;
    Ok(ParsedNode {
        line: 0,
        name: node_name(parsed.name.as_deref(), &parsed.node),
        node: parsed.node,
        credentials: parsed.credentials,
    })
}

/// 各协议解析器的中间结果。
pub(crate) struct Parsed {
    pub name: Option<String>,
    pub node: Node,
    pub credentials: Credentials,
}

/// 去掉控制字符、截断到上限；为空时用 `服务器:端口`。
fn node_name(raw: Option<&str>, node: &Node) -> String {
    let cleaned: String = raw
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .collect();
    let cleaned: String = cleaned.trim().chars().take(MAX_NAME_CHARS).collect();
    if !cleaned.is_empty() {
        return cleaned;
    }
    if node.server.contains(':') {
        format!("[{}]:{}", node.server, node.server_port)
    } else {
        format!("{}:{}", node.server, node.server_port)
    }
}

/// SIP008：`{"version":1,"servers":[{"server","server_port","method","password",...}]}`。
fn sip008(text: &str) -> ParseOutcome {
    let mut out = ParseOutcome::default();
    let servers = serde_json::from_str::<Value>(text)
        .ok()
        .and_then(|v| v.get("servers").and_then(Value::as_array).cloned());
    let Some(servers) = servers else {
        out.issues.push(Issue {
            line: 0,
            code: LinkError::Malformed.code(),
        });
        return out;
    };
    for (i, s) in servers.iter().enumerate() {
        let line = u32::try_from(i + 1).unwrap_or(u32::MAX);
        if out.nodes.len() >= MAX_NODES {
            out.issues.push(Issue {
                line,
                code: TOO_MANY_NODES,
            });
            break;
        }
        match ss::from_sip008(s).and_then(|p| {
            p.node.validate(&p.credentials)?;
            Ok(ParsedNode {
                line,
                name: node_name(p.name.as_deref(), &p.node),
                node: p.node,
                credentials: p.credentials,
            })
        }) {
            Ok(n) => out.nodes.push(n),
            Err(e) => out.issues.push(Issue {
                line,
                code: e.code(),
            }),
        }
    }
    out
}

/// 由 `net` / `type` 等参数构造传输层；tcp 无伪装时为 `None`。
pub(crate) fn transport(
    net: &str,
    header_type: &str,
    path: &str,
    host: &str,
    service_name: &str,
) -> Result<Option<Transport>, LinkError> {
    let host = (!host.is_empty()).then(|| host.to_owned());
    Ok(match net.to_ascii_lowercase().as_str() {
        "" | "tcp" | "raw" => match header_type.to_ascii_lowercase().as_str() {
            "" | "none" => None,
            // V2Ray 的 TCP HTTP 伪装 sing-box 不支持
            _ => return Err(LinkError::UnsupportedTransport),
        },
        "ws" | "websocket" => {
            let (path, max_early_data) = ws_early_data(path);
            Some(Transport::Ws {
                path,
                host,
                max_early_data,
            })
        }
        "grpc" | "gun" => Some(Transport::Grpc {
            service_name: service_name.to_owned(),
        }),
        "h2" | "http" => Some(Transport::Http {
            path: path.to_owned(),
            host: host
                .map(|h| {
                    h.split(',')
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
        }),
        "httpupgrade" => Some(Transport::Httpupgrade {
            path: path.to_owned(),
            host,
        }),
        _ => return Err(LinkError::UnsupportedTransport),
    })
}

/// Xray 风格的 WebSocket 0-RTT：路径里的 `?ed=2048`。
fn ws_early_data(path: &str) -> (String, Option<u32>) {
    if let Some((base, query)) = path.split_once('?') {
        for kv in query.split('&') {
            if let Some(n) = kv.strip_prefix("ed=").and_then(|v| v.parse::<u32>().ok()) {
                return (base.to_owned(), Some(n));
            }
        }
    }
    (path.to_owned(), None)
}

/// 逗号分隔的 ALPN 列表。
pub(crate) fn alpn(s: Option<&str>) -> Vec<String> {
    s.map(|s| {
        s.split(',')
            .map(|a| a.trim().to_owned())
            .filter(|a| !a.is_empty())
            .collect()
    })
    .unwrap_or_default()
}

/// uTLS 指纹；不认识的取值（多是已移除的旧指纹）忽略。
pub(crate) fn fingerprint(s: Option<&str>) -> Option<Fingerprint> {
    s.and_then(Fingerprint::parse)
}

#[cfg(test)]
mod tests;
