// SPDX-License-Identifier: GPL-3.0-or-later
//! 诊断包（T-112）：`diag.export` 的返回值。
//!
//! 服务生成，桌面外壳原样存成文件，供用户自己查看或附在问题报告里。生成时已脱敏（C-SEC-04）：
//! 不含凭据、订阅地址、节点名称与节点地址（只留端口）；日志里的节点地址、凭据样式的字段、
//! 公网 IP 与用户目录名替换为占位符。

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::node::{CredentialState, NodeProtocol};
use crate::profile::Profile;
use crate::session::SessionStatus;

/// `diag.export` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagReport {
    /// 生成时间，Unix 毫秒。
    pub generated_at_ms: u64,
    pub environment: DiagEnvironment,
    pub session: SessionStatus,
    /// 全部方案。规则里的用户目录名与远程 DNS 服务器地址已脱敏。
    pub profiles: Vec<Profile>,
    /// 节点概况；`nodes.json` 读不出时为空，原因见 `problems`。
    pub nodes: Option<DiagNodes>,
    pub log: DiagLog,
    /// 收集过程中遇到的问题，稳定的 `snake_case` 代码（例如 `node_store_unreadable`）。
    /// 某一部分失败不影响其余部分的导出。
    pub problems: Vec<String>,
}

/// 运行环境与组件版本。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagEnvironment {
    pub service_version: String,
    pub protocol_version: u32,
    /// 例如 `10.0.26100.2314`。
    pub os_build: Option<String>,
    /// 例如 `24H2`。
    pub os_display_version: Option<String>,
    /// 内存完整性（HVCI）的配置开关，影响拦截驱动能否加载；从未配置时为空。
    pub memory_integrity: Option<bool>,
    /// 锁定的 sing-box 版本。
    pub kernel_version: Option<String>,
    /// 安装目录里的 sing-box 与版本锁的比对结果。
    pub kernel_binary: DiagFileState,
}

/// 第三方二进制与版本锁的比对结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum DiagFileState {
    /// 存在且 SHA-256 与锁文件一致。
    Verified,
    Missing,
    /// 存在但哈希不一致：服务会拒绝启动它（C-SEC-06）。
    Mismatch,
    Unreadable,
    /// 没有检查（例如控制台模式下不知道安装目录）。
    Unknown,
}

/// 节点概况，不含名称、地址与凭据。节点可能有上千个，只列出方案用到的，其余只计数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagNodes {
    pub total: u32,
    /// 各协议的节点数，从多到少。
    pub protocols: Vec<DiagProtocolCount>,
    /// 方案里的进程组引用到的节点。
    pub referenced: Vec<DiagNode>,
    /// 方案引用了、但不存在的出站标签（会话因此无法启动）。
    pub missing_outbounds: Vec<String>,
    pub subscriptions: Vec<DiagSubscription>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagProtocolCount {
    pub protocol: NodeProtocol,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagNode {
    pub id: String,
    pub protocol: NodeProtocol,
    /// 服务器端口；地址本身不导出。
    pub server_port: u16,
    pub credential: CredentialState,
    pub subscription_id: Option<String>,
}

/// 订阅概况，不含名称与地址（地址常含令牌）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagSubscription {
    pub id: String,
    pub node_count: u32,
    pub updated_at_ms: Option<u64>,
}

/// 服务日志的末尾部分。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct DiagLog {
    /// 是否有日志文件。控制台模式下日志写到终端，没有文件。
    pub available: bool,
    /// 只取了文件末尾的一部分。
    pub truncated: bool,
    /// 脱敏后的日志行，从旧到新。
    pub lines: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_states_are_snake_case() {
        assert_eq!(
            serde_json::to_string(&DiagFileState::Mismatch).unwrap(),
            r#""mismatch""#
        );
    }

    #[test]
    fn nodes_carry_no_name_address_or_credential() {
        let n = DiagNode {
            id: "n1".into(),
            protocol: NodeProtocol::Trojan,
            server_port: 443,
            credential: CredentialState::Set,
            subscription_id: None,
        };
        let v = serde_json::to_value(&n).unwrap();
        let keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        for forbidden in ["name", "server", "password", "uuid", "url"] {
            assert!(
                !keys.contains(&forbidden),
                "{forbidden} must not be exported"
            );
        }
        let s = serde_json::to_value(DiagSubscription {
            id: "s1".into(),
            node_count: 3,
            updated_at_ms: None,
        })
        .unwrap();
        assert!(s.get("url").is_none() && s.get("name").is_none());
    }
}
