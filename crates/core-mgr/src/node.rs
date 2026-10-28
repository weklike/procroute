// SPDX-License-Identifier: GPL-3.0-or-later
//! 节点模型。
//!
//! 一个节点拆成两部分：
//!
//! - [`Node`]：服务器地址与协议参数，不含任何凭据，可以序列化落盘、记日志；
//! - [`Credentials`]：密码、UUID 等，只以 [`Secret`] 持有，不实现序列化。落盘由服务显式取出后
//!   交给 DPAPI（C-SEC-04）。
//!
//! 支持范围以锁定版本的 sing-box（1.14.4，见 `third_party/sing-box/`）为准，只收录近五年仍是主流、
//! 且该版本支持的协议与参数：Shadowsocks 只收 AEAD 与 2022 加密，VMess 只收 AEAD（alterId 为 0），
//! 传输层只收 sing-box 支持的 WebSocket、gRPC、HTTP/2、HTTPUpgrade。

use procroute_platform_win::secret::Secret;
use procroute_proto::node::NodeProtocol;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// 服务器地址的长度上限（DNS 名称上限）。
pub const MAX_SERVER_LEN: usize = 253;
/// 其他文本参数（SNI、路径、服务名等）的长度上限。
pub const MAX_PARAM_LEN: usize = 1024;

/// 一个代理节点（不含凭据）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// 域名或 IP 字面量（IPv6 不带方括号）。
    pub server: String,
    pub server_port: u16,
    pub settings: Settings,
}

/// 各协议的参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case", deny_unknown_fields)]
pub enum Settings {
    Shadowsocks {
        method: SsMethod,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        plugin: Option<SsPlugin>,
    },
    Vmess {
        #[serde(default)]
        security: VmessSecurity,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls: Option<Tls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<Transport>,
    },
    Vless {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        flow: Option<VlessFlow>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls: Option<Tls>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<Transport>,
    },
    Trojan {
        tls: Tls,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport: Option<Transport>,
    },
    Hysteria2 {
        tls: Tls,
        /// 端口跳跃范围，sing-box 格式 `起:止`。
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        server_ports: Vec<String>,
        /// 混淆；密码在 [`Credentials::obfs_password`]。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<Hysteria2Obfs>,
    },
    Tuic {
        tls: Tls,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        congestion_control: Option<TuicCongestion>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        udp_relay_mode: Option<TuicUdpRelayMode>,
    },
    Anytls {
        tls: Tls,
    },
    Socks,
    Http {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tls: Option<Tls>,
    },
}

/// Shadowsocks 加密方式：AEAD 与 2022。流加密已被各实现弃用，不收录。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SsMethod {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "aes-192-gcm")]
    Aes192Gcm,
    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,
    #[serde(rename = "xchacha20-ietf-poly1305")]
    Xchacha20IetfPoly1305,
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305,
}

impl SsMethod {
    pub const ALL: [SsMethod; 8] = [
        SsMethod::Aes128Gcm,
        SsMethod::Aes192Gcm,
        SsMethod::Aes256Gcm,
        SsMethod::Chacha20IetfPoly1305,
        SsMethod::Xchacha20IetfPoly1305,
        SsMethod::Blake3Aes128Gcm,
        SsMethod::Blake3Aes256Gcm,
        SsMethod::Blake3Chacha20Poly1305,
    ];

    /// sing-box 与分享链接里使用的名字。
    pub fn as_str(self) -> &'static str {
        match self {
            SsMethod::Aes128Gcm => "aes-128-gcm",
            SsMethod::Aes192Gcm => "aes-192-gcm",
            SsMethod::Aes256Gcm => "aes-256-gcm",
            SsMethod::Chacha20IetfPoly1305 => "chacha20-ietf-poly1305",
            SsMethod::Xchacha20IetfPoly1305 => "xchacha20-ietf-poly1305",
            SsMethod::Blake3Aes128Gcm => "2022-blake3-aes-128-gcm",
            SsMethod::Blake3Aes256Gcm => "2022-blake3-aes-256-gcm",
            SsMethod::Blake3Chacha20Poly1305 => "2022-blake3-chacha20-poly1305",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase();
        Self::ALL.into_iter().find(|m| m.as_str() == s)
    }
}

/// SIP003 插件。sing-box 内置实现只有这两种。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsPlugin {
    pub kind: SsPluginKind,
    /// 原样传给插件的选项，例如 `obfs=http;obfs-host=example.com`。
    #[serde(default)]
    pub opts: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SsPluginKind {
    /// `obfs-local`（simple-obfs）。
    ObfsLocal,
    V2rayPlugin,
}

/// VMess 的加密方式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum VmessSecurity {
    #[default]
    Auto,
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,
    #[serde(rename = "chacha20-poly1305")]
    Chacha20Poly1305,
    None,
    Zero,
}

impl VmessSecurity {
    pub fn as_str(self) -> &'static str {
        match self {
            VmessSecurity::Auto => "auto",
            VmessSecurity::Aes128Gcm => "aes-128-gcm",
            VmessSecurity::Chacha20Poly1305 => "chacha20-poly1305",
            VmessSecurity::None => "none",
            VmessSecurity::Zero => "zero",
        }
    }
}

/// VLESS 的流控。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VlessFlow {
    #[serde(rename = "xtls-rprx-vision")]
    XtlsRprxVision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hysteria2Obfs {
    Salamander,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicCongestion {
    Cubic,
    NewReno,
    Bbr,
}

impl TuicCongestion {
    pub fn as_str(self) -> &'static str {
        match self {
            TuicCongestion::Cubic => "cubic",
            TuicCongestion::NewReno => "new_reno",
            TuicCongestion::Bbr => "bbr",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TuicUdpRelayMode {
    Native,
    Quic,
}

impl TuicUdpRelayMode {
    pub fn as_str(self) -> &'static str {
        match self {
            TuicUdpRelayMode::Native => "native",
            TuicUdpRelayMode::Quic => "quic",
        }
    }
}

/// 客户端 TLS 参数。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// 不校验证书。只能由分享链接或用户显式指定。
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub alpn: Vec<String>,
    /// uTLS 指纹。REALITY 必须启用 uTLS，未指定时用 `chrome`。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Fingerprint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<Reality>,
}

/// REALITY 的公钥与短 ID 都是公开参数，不是凭据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reality {
    pub public_key: String,
    #[serde(default)]
    pub short_id: String,
}

/// sing-box 1.14 的 uTLS 指纹取值。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fingerprint {
    Chrome,
    Firefox,
    Edge,
    Safari,
    #[serde(rename = "360")]
    Qihoo360,
    Qq,
    Ios,
    Android,
    Random,
    Randomized,
}

impl Fingerprint {
    pub const ALL: [Fingerprint; 10] = [
        Fingerprint::Chrome,
        Fingerprint::Firefox,
        Fingerprint::Edge,
        Fingerprint::Safari,
        Fingerprint::Qihoo360,
        Fingerprint::Qq,
        Fingerprint::Ios,
        Fingerprint::Android,
        Fingerprint::Random,
        Fingerprint::Randomized,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Fingerprint::Chrome => "chrome",
            Fingerprint::Firefox => "firefox",
            Fingerprint::Edge => "edge",
            Fingerprint::Safari => "safari",
            Fingerprint::Qihoo360 => "360",
            Fingerprint::Qq => "qq",
            Fingerprint::Ios => "ios",
            Fingerprint::Android => "android",
            Fingerprint::Random => "random",
            Fingerprint::Randomized => "randomized",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let s = s.to_ascii_lowercase();
        Self::ALL.into_iter().find(|f| f.as_str() == s)
    }
}

/// V2Ray 传输层。只收 sing-box 支持的几种。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Transport {
    Ws {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
        /// Xray 风格的 0-RTT（路径里的 `?ed=2048`），走 `Sec-WebSocket-Protocol` 头。
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_early_data: Option<u32>,
    },
    Grpc {
        #[serde(default)]
        service_name: String,
    },
    /// HTTP/2（启用 TLS 时）或明文 HTTP/1.1。
    Http {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        host: Vec<String>,
    },
    Httpupgrade {
        #[serde(default)]
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        host: Option<String>,
    },
}

/// 节点凭据。只在内存中以 [`Secret`] 持有；`Debug` 输出全部是掩码。
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub username: Option<Secret<String>>,
    pub password: Option<Secret<String>>,
    pub uuid: Option<Secret<String>>,
    /// Hysteria2 salamander 混淆密码。
    pub obfs_password: Option<Secret<String>>,
}

impl Credentials {
    /// 是否设置了任一凭据（给 UI 的 `credential: set / not_set`）。
    pub fn is_set(&self) -> bool {
        self.username.is_some()
            || self.password.is_some()
            || self.uuid.is_some()
            || self.obfs_password.is_some()
    }
}

/// 节点参数不合法。原因里不包含凭据。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NodeError {
    #[error("服务器地址为空或含非法字符")]
    InvalidServer,
    #[error("端口不能为 0")]
    InvalidPort,
    #[error("参数 {0} 过长或含控制字符")]
    InvalidParam(&'static str),
    #[error("缺少凭据：{0}")]
    MissingCredential(&'static str),
    #[error("凭据 {0} 含控制字符或过长")]
    InvalidCredential(&'static str),
    #[error("VMess/VLESS 的 UUID 格式不正确")]
    InvalidUuid,
    #[error("REALITY 公钥或短 ID 格式不正确")]
    InvalidReality,
    #[error("Hysteria2 端口范围格式不正确")]
    InvalidPortRange,
    #[error("用户名与密码必须同时设置")]
    IncompleteAuth,
}

impl Node {
    /// 对应 IPC 里的协议枚举。
    pub fn protocol(&self) -> NodeProtocol {
        match self.settings {
            Settings::Shadowsocks { .. } => NodeProtocol::Shadowsocks,
            Settings::Vmess { .. } => NodeProtocol::Vmess,
            Settings::Vless { .. } => NodeProtocol::Vless,
            Settings::Trojan { .. } => NodeProtocol::Trojan,
            Settings::Hysteria2 { .. } => NodeProtocol::Hysteria2,
            Settings::Tuic { .. } => NodeProtocol::Tuic,
            Settings::Anytls { .. } => NodeProtocol::Anytls,
            Settings::Socks => NodeProtocol::Socks,
            Settings::Http { .. } => NodeProtocol::Http,
        }
    }

    /// 校验参数与凭据是否齐全、格式是否正确。生成配置前必须调用。
    pub fn validate(&self, creds: &Credentials) -> Result<(), NodeError> {
        if !is_valid_server(&self.server) {
            return Err(NodeError::InvalidServer);
        }
        if self.server_port == 0 {
            return Err(NodeError::InvalidPort);
        }
        for (name, value) in self.params() {
            if value.chars().count() > MAX_PARAM_LEN || value.chars().any(char::is_control) {
                return Err(NodeError::InvalidParam(name));
            }
        }
        for (name, value) in [
            ("username", &creds.username),
            ("password", &creds.password),
            ("uuid", &creds.uuid),
            ("obfs_password", &creds.obfs_password),
        ] {
            if let Some(v) = value {
                let v = v.expose();
                if v.is_empty()
                    || v.chars().count() > MAX_PARAM_LEN
                    || v.chars().any(char::is_control)
                {
                    return Err(NodeError::InvalidCredential(name));
                }
            }
        }
        match &self.settings {
            Settings::Shadowsocks { .. } | Settings::Trojan { .. } | Settings::Anytls { .. } => {
                require(&creds.password, "password")?;
            }
            Settings::Vmess { .. } | Settings::Vless { .. } => {
                let uuid = require(&creds.uuid, "uuid")?;
                if !is_uuid(uuid) {
                    return Err(NodeError::InvalidUuid);
                }
            }
            Settings::Hysteria2 {
                server_ports, obfs, ..
            } => {
                require(&creds.password, "password")?;
                if obfs.is_some() {
                    require(&creds.obfs_password, "obfs_password")?;
                }
                if !server_ports.iter().all(|r| is_port_range(r)) {
                    return Err(NodeError::InvalidPortRange);
                }
            }
            Settings::Tuic { .. } => {
                let uuid = require(&creds.uuid, "uuid")?;
                if !is_uuid(uuid) {
                    return Err(NodeError::InvalidUuid);
                }
                require(&creds.password, "password")?;
            }
            Settings::Socks | Settings::Http { .. } => {
                if creds.username.is_some() != creds.password.is_some() {
                    return Err(NodeError::IncompleteAuth);
                }
            }
        }
        if let Some(reality) = self.tls().and_then(|t| t.reality.as_ref())
            && !is_valid_reality(reality)
        {
            return Err(NodeError::InvalidReality);
        }
        Ok(())
    }

    /// 节点的 TLS 参数（如果有）。
    pub fn tls(&self) -> Option<&Tls> {
        match &self.settings {
            Settings::Vmess { tls, .. } | Settings::Vless { tls, .. } | Settings::Http { tls } => {
                tls.as_ref()
            }
            Settings::Trojan { tls, .. }
            | Settings::Hysteria2 { tls, .. }
            | Settings::Tuic { tls, .. }
            | Settings::Anytls { tls } => Some(tls),
            Settings::Shadowsocks { .. } | Settings::Socks => None,
        }
    }

    fn transport(&self) -> Option<&Transport> {
        match &self.settings {
            Settings::Vmess { transport, .. }
            | Settings::Vless { transport, .. }
            | Settings::Trojan { transport, .. } => transport.as_ref(),
            _ => None,
        }
    }

    /// 需要做长度与控制字符检查的文本参数。
    fn params(&self) -> Vec<(&'static str, &str)> {
        let mut out = Vec::new();
        if let Some(tls) = self.tls() {
            if let Some(sni) = &tls.server_name {
                out.push(("sni", sni.as_str()));
            }
            out.extend(tls.alpn.iter().map(|a| ("alpn", a.as_str())));
        }
        if let Settings::Shadowsocks {
            plugin: Some(plugin),
            ..
        } = &self.settings
        {
            out.push(("plugin_opts", plugin.opts.as_str()));
        }
        match self.transport() {
            Some(Transport::Ws { path, host, .. } | Transport::Httpupgrade { path, host }) => {
                out.push(("path", path.as_str()));
                if let Some(h) = host {
                    out.push(("host", h.as_str()));
                }
            }
            Some(Transport::Http { path, host }) => {
                out.push(("path", path.as_str()));
                out.extend(host.iter().map(|h| ("host", h.as_str())));
            }
            Some(Transport::Grpc { service_name }) => {
                out.push(("service_name", service_name.as_str()))
            }
            None => {}
        }
        out
    }
}

fn require<'a>(v: &'a Option<Secret<String>>, name: &'static str) -> Result<&'a str, NodeError> {
    v.as_ref()
        .map(|s| s.expose().as_str())
        .ok_or(NodeError::MissingCredential(name))
}

/// 域名或 IP 字面量：非空、不超长、不含空白 / 控制字符 / URL 分隔符。
pub fn is_valid_server(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_SERVER_LEN
        && !s
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "/\\@?#[]".contains(c))
}

/// 标准 8-4-4-4-12 形式的 UUID。
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// `起:止` 形式的端口范围，或单个端口。
fn is_port_range(s: &str) -> bool {
    let port = |p: &str| p.parse::<u16>().is_ok_and(|n| n != 0);
    match s.split_once(':') {
        Some((a, b)) => port(a) && port(b) && a.parse::<u16>().ok() <= b.parse::<u16>().ok(),
        None => port(s),
    }
}

/// REALITY 公钥是 32 字节 X25519 公钥的 base64url（无填充，43 个字符）；短 ID 是 0~16 位十六进制。
fn is_valid_reality(r: &Reality) -> bool {
    r.public_key.len() == 43
        && r.public_key
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        && r.short_id.len() <= 16
        && r.short_id.len().is_multiple_of(2)
        && r.short_id.bytes().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests;
