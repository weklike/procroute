// SPDX-License-Identifier: GPL-3.0-or-later
//! 方案（Profile）：哪些进程、走哪个出站、出错时怎么办。
//!
//! 这里定义线上传输与落盘共用的数据结构；校验与 schema 迁移在 `procroute-config`。

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// 当前方案的 schema 版本。结构变更必须加一并提供迁移（C-ARCH-06）。
///
/// - 2：`dns.remote_server`（用户配置的远程 DNS 服务器）。
pub const PROFILE_SCHEMA_VERSION: u32 = 2;

/// 工作模式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// 精确进程模式：只改道目标进程的数据包，不改系统路由。
    #[default]
    Precise,
    /// TUN 分流模式：由内核的 TUN 入站和进程规则完成。
    Tun,
}

/// 内核或中继不可用时，目标进程流量的处理方式。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum FailPolicy {
    /// 默认值（C-NET-03）：新连接直接失败，绝不回落直连。
    #[default]
    Block,
    /// 用户显式选择后才允许：临时直连。
    Allow,
}

/// DNS 处理策略。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum DnsStrategy {
    /// 默认：劫持目标进程直发的 53 端口查询，并对改道连接做域名嗅探。
    #[default]
    Sniff,
    /// 接管系统 DNS。影响全局，默认关闭，开启前需用户确认（C-NET-09）。
    SystemTakeover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct DnsSettings {
    #[serde(default)]
    pub strategy: DnsStrategy,
    /// 劫持目标进程自己发往 53 端口的查询。
    #[serde(default = "default_true")]
    pub hijack_port53: bool,
    /// 远程 DNS 服务器（v2 起）：被劫持的查询经该进程组的出站交给它解析，绕开本地被污染的结果。
    /// 形如 `udp://`、`tcp://`、`tls://`、`https://` 地址，例如 `tls://198.51.100.53` 或
    /// `https://dns.example/dns-query`。由用户配置，软件不内置任何服务器（C-SEC-09）；为空时不劫持。
    #[serde(default)]
    pub remote_server: Option<String>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            strategy: DnsStrategy::default(),
            hijack_port53: true,
            remote_server: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct UdpSettings {
    /// 是否代理目标进程的 UDP 流量。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 阻断目标进程的 UDP 443，让应用回落到 TCP。
    #[serde(default)]
    pub block_quic: bool,
}

impl Default for UdpSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            block_quic: false,
        }
    }
}

/// 匹配项类型。求值顺序见 `procroute-rules`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    /// 进程名，例如 `launcher.exe`（不区分大小写）。
    Name,
    /// 可执行文件完整路径。
    Path,
    /// 目录；`recursive` 为真时包含子目录。
    Dir,
    /// 通配符，作用于完整路径，例如 `D:\Games\*\bin\*.exe`。
    Glob,
    /// 正则表达式，作用于完整路径。
    Regex,
}

/// 一条进程匹配规则。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct MatchRule {
    #[serde(rename = "type")]
    pub kind: MatchType,
    pub value: String,
    /// 只对 `dir` 有意义：是否包含子目录。
    #[serde(default)]
    pub recursive: bool,
}

/// 进程组：同一组的进程走同一个出站。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// 组标签，同一方案内唯一；也用作本地 SOCKS 用户名以选择出站。
    pub tag: String,
    /// 出站或出站组的标签，对应 sing-box 的出站。
    pub outbound: String,
    /// 是否把本组进程派生的子进程纳入本组（F7）。
    #[serde(default = "default_true")]
    pub include_children: bool,
    #[serde(rename = "match")]
    pub matchers: Vec<MatchRule>,
}

/// 方案。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub fail_policy: FailPolicy,
    #[serde(default)]
    pub dns: DnsSettings,
    #[serde(default)]
    pub udp: UdpSettings,
    #[serde(default)]
    pub groups: Vec<Group>,
    /// 排除规则，优先级最高，命中即直连。
    #[serde(default)]
    pub exclude: Vec<MatchRule>,
}

/// 方案列表里的一项。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProfileSummary {
    pub id: String,
    pub name: String,
    pub mode: Mode,
    pub group_count: u32,
    /// 是否为当前会话正在使用的方案。
    pub active: bool,
}

/// `profile.list` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProfileListResult {
    pub profiles: Vec<ProfileSummary>,
}

/// `profile.get` / `profile.delete` 的参数。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ProfileIdParams {
    pub id: String,
}

/// `profile.save` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct ProfileSaveResult {
    pub id: String,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "schema_version": 1,
      "id": "01JBX7Q3K2M8T5W9Y4C6N0R1PZ",
      "name": "游戏加速",
      "mode": "precise",
      "fail_policy": "block",
      "dns": { "strategy": "sniff", "hijack_port53": true },
      "udp": { "enabled": true, "block_quic": false },
      "groups": [
        {
          "tag": "game",
          "outbound": "hk-auto",
          "include_children": true,
          "match": [
            { "type": "dir", "value": "D:\\Games\\MyGame", "recursive": true },
            { "type": "name", "value": "launcher.exe" }
          ]
        }
      ],
      "exclude": [ { "type": "name", "value": "updater.exe" } ]
    }"#;

    #[test]
    fn design_doc_example_round_trips() {
        let p: Profile = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(p.groups[0].matchers[0].kind, MatchType::Dir);
        assert!(p.groups[0].matchers[0].recursive);
        assert!(!p.groups[0].matchers[1].recursive);
        let back: Profile = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn fail_policy_defaults_to_block() {
        // C-NET-03：缺省必须是 block
        let p: Profile =
            serde_json::from_str(r#"{"schema_version":1,"id":"a","name":"n"}"#).unwrap();
        assert_eq!(p.fail_policy, FailPolicy::Block);
        assert_eq!(p.dns.strategy, DnsStrategy::Sniff);
        assert!(p.dns.hijack_port53);
        assert!(p.udp.enabled);
        assert!(!p.udp.block_quic);
        assert_eq!(p.mode, Mode::Precise);
    }

    #[test]
    fn system_dns_takeover_is_never_the_default() {
        // C-NET-09
        assert_eq!(DnsStrategy::default(), DnsStrategy::Sniff);
    }

    #[test]
    fn include_children_defaults_to_true() {
        let g: Group = serde_json::from_str(r#"{"tag":"t","outbound":"o","match":[]}"#).unwrap();
        assert!(g.include_children);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let bad = r#"{"schema_version":1,"id":"a","name":"n","surprise":1}"#;
        assert!(serde_json::from_str::<Profile>(bad).is_err());
    }
}
