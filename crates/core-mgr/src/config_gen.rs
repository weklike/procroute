// SPDX-License-Identifier: GPL-3.0-or-later
//! 由方案生成 sing-box 1.14 配置：TUN 模式（T-055）与精确进程模式（T-095）。
//!
//! 生成结果每次启动重建，经标准输入交给 sing-box，禁止手改（C-ARCH-05）；其中含节点凭据明文，因此以
//! [`Secret`] 返回。字段以锁定版本（1.14.4）为准，与旧版本配置的差异见 `third_party/sing-box/`。
//!
//! 精确进程模式下 sing-box 只有一个绑定回环的 SOCKS5 入口（C-NET-08），由本地中继把目标进程的连接
//! 转进来：用户名是进程组标签，`auth_user` 规则把它路由到该组的出站；入口上没有匹配到任何进程组的
//! 连接一律拒绝，绝不直连（C-NET-03）。入口上的连接都做协议嗅探，连接面板因此能显示域名。
//! 1.14 已删除「用嗅探出的域名覆盖目标地址」（`sniff_override_destination`，规则动作里没有替代），
//! 设计文档 6.3 的「让远端重新解析」需要另找做法（T-092，见 TASKS.md）。
//!
//! TUN 入站的几处取值有硬约束背景：
//!
//! - `stack` 固定为 `gvisor`：`system` / `mixed` 栈在 Windows 上会为 sing-box 添加一条持久的
//!   Windows 防火墙入站规则且从不删除（sing-tun `stack_system_windows.go`），违反 C-NET-06；
//! - `dns_mode` 显式设为 `disabled`：1.14 起开启 `auto_route` 时默认 `hijack`，会给 TUN 网卡设置 DNS
//!   并用 WFP 阻断所有发往 53 端口的流量，等同系统 DNS 接管，必须默认关闭（C-NET-09，T-092 再按方案开启）；
//! - `strict_route` 开启并同时配置 IPv4 与 IPv6 地址：两个地址族的默认路由都进 TUN，目标进程的 IPv6
//!   流量不会绕过 TUN 直连；Windows 上这只会附加随 sing-box 进程一起消失的动态 WFP 过滤器。
//!
//! 进程规则按 `procroute-rules` 的优先级展开成有序的路由规则（排除 > 路径 > 目录 > 名称 > 通配 / 正则，
//! 同级按进程组顺序），保证 TUN 模式与精确模式对同一进程的判定一致。TUN 模式下 sing-box 只能按发起连接
//! 的进程判定，`include_children` 不生效。
//!
//! 已知风险：sing-box 退出后 TUN 与路由随之撤销，目标进程会回落直连。fail-closed（C-NET-03）
//! 由守护进程（T-056）负责，这里无法单独保证。

use std::collections::{HashMap, HashSet};

use procroute_platform_win::secret::Secret;
use procroute_proto::profile::{MatchType, Mode, Profile};
use procroute_rules::matcher::RuleError;
use serde_json::{Value, json};
use thiserror::Error;

use crate::node::{Credentials, Node, NodeError};
use crate::{outbound, process_regex};

/// 直连出站的标签（保留）。
pub const DIRECT_TAG: &str = "direct";
/// TUN 入站的标签。
pub const TUN_INBOUND_TAG: &str = "tun-in";
/// 精确进程模式的 SOCKS5 入站标签。
pub const SOCKS_INBOUND_TAG: &str = "socks-in";
/// 解析节点域名用的 DNS 服务器标签。
pub const LOCAL_DNS_TAG: &str = "local";
/// TUN 网卡名。
pub const TUN_INTERFACE_NAME: &str = "ProcRoute";
/// TUN 网卡地址：基准测试保留段 198.18.0.0/15 与 ULA，避开常见的 Docker / WSL 网段。
pub const TUN_ADDRESSES: [&str; 2] = ["198.18.0.1/30", "fdfe:dcba:9876::1/126"];
/// 永久直连的目标：回环、链路本地、组播与广播（C-NET-05）。
pub const ALWAYS_DIRECT_CIDRS: [&str; 7] = [
    "127.0.0.0/8",
    "::1/128",
    "169.254.0.0/16",
    "fe80::/10",
    "224.0.0.0/4",
    "ff00::/8",
    "255.255.255.255/32",
];
/// 控制 API 密钥的最短长度（C-NET-08：每次启动随机生成）。
pub const MIN_API_SECRET_LEN: usize = 32;
/// 自动选择组的最短测速间隔。
pub const MIN_URLTEST_INTERVAL_SECS: u32 = 60;

/// `procroute-rules` 的优先级，从高到低。
const TIERS: [&[MatchType]; 4] = [
    &[MatchType::Path],
    &[MatchType::Dir],
    &[MatchType::Name],
    &[MatchType::Glob, MatchType::Regex],
];

/// 一个节点出站。
#[derive(Debug, Clone)]
pub struct NodeOutbound {
    pub tag: String,
    pub node: Node,
    pub credentials: Credentials,
}

/// 节点组的选择方式。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupKind {
    /// 手动选择；`default` 为空时用第一个成员。
    Selector { default: Option<String> },
    /// 按延迟自动选择。测速会定时访问 `url`，所以地址必须由用户配置（C-SEC-08、C-SEC-09）。
    UrlTest { url: String, interval_secs: u32 },
}

/// 一个节点组出站；成员是节点出站的标签。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupOutbound {
    pub tag: String,
    pub kind: GroupKind,
    pub members: Vec<String>,
}

/// 精确进程模式的本地 SOCKS5 入口：只绑定 127.0.0.1，端口与密码每次启动随机生成（C-NET-08）。
/// 所有进程组共用这个密码，用户名是进程组标签。
#[derive(Debug, Clone)]
pub struct SocksInbound {
    pub port: u16,
    pub password: Secret<String>,
}

/// 每次启动随机生成的运行参数。
#[derive(Debug, Clone)]
pub struct Runtime {
    /// 控制 API（Clash API）端口，只绑定 127.0.0.1（C-NET-08）。
    pub api_port: u16,
    pub api_secret: Secret<String>,
    /// ProcRoute 自身的可执行文件（服务、界面），永久直连（C-NET-05）。
    pub self_exe_paths: Vec<String>,
}

/// 生成失败。错误信息只含标签与规则位置，不含凭据。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GenError {
    #[error("方案未通过校验（{0} 处问题）")]
    InvalidProfile(usize),
    #[error("方案的工作模式与要生成的配置不一致")]
    UnsupportedMode,
    #[error("方案没有任何进程组")]
    NoGroups,
    #[error("{location}：{source}")]
    InvalidRule {
        location: String,
        #[source]
        source: RuleError,
    },
    #[error("进程组 {group} 引用了不存在的出站 {outbound}")]
    UnknownOutbound { group: String, outbound: String },
    #[error("出站标签 {0} 重复")]
    DuplicateTag(String),
    #[error("出站标签 {0} 为保留标签或格式不正确")]
    InvalidTag(String),
    #[error("节点组 {0} 没有成员")]
    EmptyGroup(String),
    #[error("节点组 {group} 的成员 {member} 不是节点出站")]
    UnknownMember { group: String, member: String },
    #[error("节点组 {group} 的默认成员 {member} 不在成员列表中")]
    InvalidDefault { group: String, member: String },
    #[error("自动选择组 {0} 的测速地址必须是 http(s) 地址，间隔不少于 60 秒")]
    InvalidUrlTest(String),
    #[error("节点 {tag}：{source}")]
    InvalidNode {
        tag: String,
        #[source]
        source: NodeError,
    },
    #[error("运行参数无效：{0}")]
    InvalidRuntime(&'static str),
    #[error("{0}的端口为 0，或密钥过短、含非字母数字字符")]
    InvalidEndpoint(&'static str),
}

/// 生成 TUN 模式的 sing-box 配置。只输出方案实际引用到的出站。
pub fn generate_tun(
    profile: &Profile,
    nodes: &[NodeOutbound],
    groups: &[GroupOutbound],
    runtime: &Runtime,
) -> Result<Secret<String>, GenError> {
    procroute_config::validate::validate(profile)
        .map_err(|issues| GenError::InvalidProfile(issues.len()))?;
    if profile.mode != Mode::Tun {
        return Err(GenError::UnsupportedMode);
    }
    if profile.groups.is_empty() {
        return Err(GenError::NoGroups);
    }
    check_runtime(runtime)?;
    let outbounds = outbounds(profile, nodes, groups)?;
    let rules = route_rules(profile, runtime)?;

    let config = json!({
        "log": log_options(),
        "dns": local_dns(),
        "inbounds": [ {
            "type": "tun",
            "tag": TUN_INBOUND_TAG,
            "interface_name": TUN_INTERFACE_NAME,
            "address": TUN_ADDRESSES,
            "auto_route": true,
            "strict_route": true,
            "stack": "gvisor",
            "dns_mode": "disabled",
        } ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": DIRECT_TAG,
            // 出站连接绑定物理网卡，避免 sing-box 自己的流量再进 TUN 形成回环（C-NET-05）
            "auto_detect_interface": true,
            "default_domain_resolver": LOCAL_DNS_TAG,
        },
        "experimental": clash_api(runtime),
    });
    Ok(Secret::new(format!("{config:#}")))
}

/// 生成精确进程模式的 sing-box 配置：一个回环 SOCKS5 入口，按用户名（进程组标签）分流到各组出站。
/// 只输出方案实际引用到的出站。
pub fn generate_precise(
    profile: &Profile,
    nodes: &[NodeOutbound],
    groups: &[GroupOutbound],
    runtime: &Runtime,
    socks: &SocksInbound,
) -> Result<Secret<String>, GenError> {
    procroute_config::validate::validate(profile)
        .map_err(|issues| GenError::InvalidProfile(issues.len()))?;
    if profile.mode != Mode::Precise {
        return Err(GenError::UnsupportedMode);
    }
    if profile.groups.is_empty() {
        return Err(GenError::NoGroups);
    }
    check_runtime(runtime)?;
    check_secret(socks.port, socks.password.expose(), "SOCKS 入口")?;
    let outbounds = outbounds(profile, nodes, groups)?;
    let users: Vec<Value> = profile
        .groups
        .iter()
        .map(|g| json!({ "username": g.tag, "password": socks.password.expose() }))
        .collect();

    let mut rules = vec![json!({ "inbound": [SOCKS_INBOUND_TAG], "action": "sniff" })];
    if profile.udp.block_quic {
        // 拦截层（T-093）已经丢弃目标进程的 UDP 443，这里再兜一层
        rules.push(json!({
            "inbound": [SOCKS_INBOUND_TAG], "network": "udp", "port": 443, "action": "reject",
        }));
    }
    rules.extend(
        profile
            .groups
            .iter()
            .map(|g| json!({ "auth_user": [g.tag], "action": "route", "outbound": g.outbound })),
    );
    // 入口上的连接走到这里说明没有对应的进程组：拒绝，不直连（C-NET-03）
    rules.push(json!({ "inbound": [SOCKS_INBOUND_TAG], "action": "reject" }));

    let config = json!({
        "log": log_options(),
        "dns": local_dns(),
        "inbounds": [ {
            "type": "socks",
            "tag": SOCKS_INBOUND_TAG,
            "listen": "127.0.0.1",
            "listen_port": socks.port,
            "users": users,
        } ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            // 只有不经入口的流量会走到 final；精确模式下没有这种流量
            "final": DIRECT_TAG,
            "auto_detect_interface": true,
            "default_domain_resolver": LOCAL_DNS_TAG,
        },
        "experimental": clash_api(runtime),
    });
    Ok(Secret::new(format!("{config:#}")))
}

fn log_options() -> Value {
    json!({ "level": "warn", "timestamp": true })
}

fn local_dns() -> Value {
    json!({
        "servers": [ { "type": "local", "tag": LOCAL_DNS_TAG } ],
        "final": LOCAL_DNS_TAG,
    })
}

fn clash_api(runtime: &Runtime) -> Value {
    json!({
        "clash_api": {
            "external_controller": format!("127.0.0.1:{}", runtime.api_port),
            "secret": runtime.api_secret.expose(),
            // 控制 API 只给服务用；不放行任何网页来源
            "access_control_allow_origin": ["http://127.0.0.1"],
        },
    })
}

fn check_runtime(rt: &Runtime) -> Result<(), GenError> {
    check_secret(rt.api_port, rt.api_secret.expose(), "控制 API")?;
    if rt.self_exe_paths.is_empty() {
        return Err(GenError::InvalidRuntime(
            "缺少 ProcRoute 自身的可执行文件路径",
        ));
    }
    Ok(())
}

/// 回环入口的端口与密钥：端口非 0，密钥足够长且只含字母数字（C-NET-08）。
fn check_secret(port: u16, secret: &str, what: &'static str) -> Result<(), GenError> {
    if port == 0 {
        return Err(GenError::InvalidEndpoint(what));
    }
    if secret.len() < MIN_API_SECRET_LEN || !secret.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(GenError::InvalidEndpoint(what));
    }
    Ok(())
}

/// 按引用关系收集出站：直连 + 方案引用到的节点组与节点。
fn outbounds(
    profile: &Profile,
    nodes: &[NodeOutbound],
    groups: &[GroupOutbound],
) -> Result<Vec<Value>, GenError> {
    let mut seen = HashSet::new();
    for tag in nodes
        .iter()
        .map(|n| &n.tag)
        .chain(groups.iter().map(|g| &g.tag))
    {
        if tag == DIRECT_TAG
            || tag.is_empty()
            || tag.len() > 64
            || tag.chars().any(char::is_control)
        {
            return Err(GenError::InvalidTag(tag.clone()));
        }
        if !seen.insert(tag.as_str()) {
            return Err(GenError::DuplicateTag(tag.clone()));
        }
    }
    let node_by_tag: HashMap<&str, &NodeOutbound> =
        nodes.iter().map(|n| (n.tag.as_str(), n)).collect();
    let group_by_tag: HashMap<&str, &GroupOutbound> =
        groups.iter().map(|g| (g.tag.as_str(), g)).collect();

    let mut out = vec![json!({ "type": "direct", "tag": DIRECT_TAG })];
    let mut emitted_groups = HashSet::new();
    let mut wanted_nodes: Vec<&str> = Vec::new();
    for pg in &profile.groups {
        let tag = pg.outbound.as_str();
        if node_by_tag.contains_key(tag) {
            wanted_nodes.push(tag);
        } else if let Some(g) = group_by_tag.get(tag) {
            if emitted_groups.insert(tag) {
                out.push(group(g, &node_by_tag)?);
                wanted_nodes.extend(g.members.iter().map(String::as_str));
            }
        } else {
            return Err(GenError::UnknownOutbound {
                group: pg.tag.clone(),
                outbound: pg.outbound.clone(),
            });
        }
    }
    let mut emitted_nodes = HashSet::new();
    for tag in wanted_nodes {
        if emitted_nodes.insert(tag)
            && let Some(n) = node_by_tag.get(tag)
        {
            let value = outbound::render(&n.tag, &n.node, &n.credentials).map_err(|source| {
                GenError::InvalidNode {
                    tag: n.tag.clone(),
                    source,
                }
            })?;
            out.push(value);
        }
    }
    Ok(out)
}

fn group(g: &GroupOutbound, nodes: &HashMap<&str, &NodeOutbound>) -> Result<Value, GenError> {
    if g.members.is_empty() {
        return Err(GenError::EmptyGroup(g.tag.clone()));
    }
    if let Some(m) = g.members.iter().find(|m| !nodes.contains_key(m.as_str())) {
        return Err(GenError::UnknownMember {
            group: g.tag.clone(),
            member: m.clone(),
        });
    }
    Ok(match &g.kind {
        GroupKind::Selector { default } => {
            let default = match default {
                Some(d) if g.members.contains(d) => d.clone(),
                Some(d) => {
                    return Err(GenError::InvalidDefault {
                        group: g.tag.clone(),
                        member: d.clone(),
                    });
                }
                None => g.members[0].clone(),
            };
            json!({ "type": "selector", "tag": g.tag, "outbounds": g.members, "default": default })
        }
        GroupKind::UrlTest { url, interval_secs } => {
            let valid_url = (url.starts_with("http://") || url.starts_with("https://"))
                && url.len() <= 2048
                && !url.chars().any(|c| c.is_whitespace() || c.is_control());
            if !valid_url || *interval_secs < MIN_URLTEST_INTERVAL_SECS {
                return Err(GenError::InvalidUrlTest(g.tag.clone()));
            }
            json!({
                "type": "urltest",
                "tag": g.tag,
                "outbounds": g.members,
                "url": url,
                "interval": format!("{interval_secs}s"),
            })
        }
    })
}

/// 路由规则，顺序即优先级：永久直连 → 自身进程 → 排除 → QUIC 阻断 → UDP 不代理 → 各进程组。
fn route_rules(profile: &Profile, runtime: &Runtime) -> Result<Vec<Value>, GenError> {
    let mut rules =
        vec![json!({ "ip_cidr": ALWAYS_DIRECT_CIDRS, "action": "route", "outbound": DIRECT_TAG })];

    let self_regexes = runtime
        .self_exe_paths
        .iter()
        .map(|p| {
            let rule = procroute_proto::profile::MatchRule {
                kind: MatchType::Path,
                value: p.clone(),
                recursive: false,
            };
            process_regex::translate(&rule)
                .map_err(|_| GenError::InvalidRuntime("ProcRoute 自身路径无效"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    rules.push(direct(&self_regexes));

    let exclude = profile
        .exclude
        .iter()
        .enumerate()
        .map(|(i, r)| translate(r, || format!("exclude[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    if !exclude.is_empty() {
        rules.push(direct(&exclude));
    }

    // 每个进程组按优先级分层的正则
    let mut tiers: Vec<Vec<Vec<String>>> =
        vec![vec![Vec::new(); profile.groups.len()]; TIERS.len()];
    for (gi, g) in profile.groups.iter().enumerate() {
        for (ri, r) in g.matchers.iter().enumerate() {
            let re = translate(r, || format!("groups[{gi}].match[{ri}]"))?;
            if let Some(t) = TIERS.iter().position(|kinds| kinds.contains(&r.kind)) {
                tiers[t][gi].push(re);
            }
        }
    }
    let all_targets: Vec<String> = tiers.iter().flatten().flatten().cloned().collect();
    if !all_targets.is_empty() {
        if profile.udp.block_quic {
            rules.push(json!({
                "process_path_regex": all_targets, "network": "udp", "port": 443, "action": "reject",
            }));
        }
        if !profile.udp.enabled {
            rules.push(json!({
                "process_path_regex": all_targets, "network": "udp", "action": "route", "outbound": DIRECT_TAG,
            }));
        }
    }
    for tier in &tiers {
        for (gi, regexes) in tier.iter().enumerate() {
            if !regexes.is_empty() {
                rules.push(json!({
                    "process_path_regex": regexes,
                    "action": "route",
                    "outbound": profile.groups[gi].outbound,
                }));
            }
        }
    }
    Ok(rules)
}

fn translate(
    rule: &procroute_proto::profile::MatchRule,
    location: impl FnOnce() -> String,
) -> Result<String, GenError> {
    process_regex::translate(rule).map_err(|source| GenError::InvalidRule {
        location: location(),
        source,
    })
}

fn direct(regexes: &[String]) -> Value {
    json!({ "process_path_regex": regexes, "action": "route", "outbound": DIRECT_TAG })
}

#[cfg(test)]
mod tests;
