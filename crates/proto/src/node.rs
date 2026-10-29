// SPDX-License-Identifier: GPL-3.0-or-later
//! 节点、出站与订阅。
//!
//! 凭据（密码、UUID、私钥、预共享密钥、订阅令牌）永远不出现在任何返回给 UI 的类型里
//! （C-SEC-04、C-UI-03）：返回值只告诉界面「凭据已设置 / 未设置」。UI 只能写入新值。

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// 节点协议。实际支持范围以锁定版本的 sing-box 为准。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum NodeProtocol {
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    Hysteria2,
    Tuic,
    Anytls,
    Socks,
    Http,
}

/// 凭据是否已设置。不携带凭据本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    Set,
    NotSet,
}

/// 返回给 UI 的节点信息。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub protocol: NodeProtocol,
    /// `host:port`。服务器地址不是凭据，但诊断包导出时会脱敏。
    pub server: String,
    pub subscription_id: Option<String>,
    pub credential: CredentialState,
}

/// 出站的种类。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum OutboundKind {
    /// 单个节点。
    Single,
    /// 按延迟自动选择。
    UrlTest,
    /// 手动选择。
    Selector,
}

/// 方案里的进程组按 `tag` 引用出站。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct OutboundInfo {
    pub tag: String,
    pub kind: OutboundKind,
    /// 成员节点 id。
    pub members: Vec<String>,
    /// 当前实际使用的成员节点 id（自动选择或手动选择时）。
    pub current: Option<String>,
}

/// 订阅。完整订阅地址常含令牌，视同凭据，只返回 `scheme://host` 用于展示。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct SubscriptionInfo {
    pub id: String,
    pub name: String,
    pub url_display: String,
    pub node_count: u32,
    pub updated_at_ms: Option<u64>,
}

/// `node.list` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct NodeListResult {
    pub nodes: Vec<NodeInfo>,
    pub outbounds: Vec<OutboundInfo>,
    pub subscriptions: Vec<SubscriptionInfo>,
}

/// `node.import` 的参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NodeImportParams {
    /// 一行一个分享链接；也接受整体 Base64 的订阅内容与 SIP008 JSON。
    /// 支持的格式见 `procroute-core-mgr::link`。
    ShareLinks { text: String },
    /// 新增订阅；服务负责拉取（C-SEC-07 限制大小与节点数）。
    Subscription { name: String, url: String },
}

/// 导入时被跳过的一行及原因。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ImportIssue {
    /// 输入中的行号，从 1 开始；0 表示针对整段输入（例如 `clash_yaml_unsupported`）。
    pub line: u32,
    /// 稳定的原因代码（`snake_case`，例如 `unsupported_protocol`、`duplicate`），界面据此翻译。
    /// 只取固定代码，不回显输入内容与凭据（C-SEC-04）。
    pub reason: String,
}

/// `node.import` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct NodeImportResult {
    pub added: u32,
    pub skipped: u32,
    pub issues: Vec<ImportIssue>,
}

/// `node.test` 的参数；`ids` 为空表示测全部节点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct NodeTestParams {
    pub ids: Vec<String>,
    /// 测速地址（`https://`），经每个节点访问它并计时。必须由用户配置，软件不内置任何地址
    /// （C-SEC-08、C-SEC-09）；缺省或不是 `https://` 时服务拒绝测速。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub url: Option<String>,
}

/// 单个节点的测速结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct LatencyResult {
    pub id: String,
    /// 超时或失败时为空。
    pub latency_ms: Option<u32>,
    pub timed_out: bool,
}

/// `node.test` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct NodeTestResult {
    pub results: Vec<LatencyResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_info_has_no_credential_payload() {
        let n = NodeInfo {
            id: "n1".into(),
            name: "香港 01".into(),
            protocol: NodeProtocol::Anytls,
            server: "hk1.example.net:443".into(),
            subscription_id: None,
            credential: CredentialState::Set,
        };
        let v: serde_json::Value = serde_json::to_value(&n).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        for forbidden in ["password", "uuid", "private_key", "psk", "secret", "token"] {
            assert!(
                !keys.contains(&forbidden),
                "{forbidden} must never be sent to the UI"
            );
        }
        assert_eq!(v["credential"], "set");
    }

    #[test]
    fn import_params_are_tagged() {
        let p: NodeImportParams =
            serde_json::from_str(r#"{"kind":"share_links","text":"anytls://x"}"#).unwrap();
        assert!(matches!(p, NodeImportParams::ShareLinks { .. }));
        let s: NodeImportParams = serde_json::from_str(
            r#"{"kind":"subscription","name":"我的订阅","url":"https://example.com/s"}"#,
        )
        .unwrap();
        assert!(matches!(s, NodeImportParams::Subscription { .. }));
    }

    #[test]
    fn latency_result_round_trips() {
        let r = LatencyResult {
            id: "n1".into(),
            latency_ms: None,
            timed_out: true,
        };
        let back: LatencyResult =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(r, back);
    }
}
