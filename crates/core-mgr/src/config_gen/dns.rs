// SPDX-License-Identifier: GPL-3.0-or-later
//! 远程 DNS（`dns.remote_server`，T-092）：目标进程自己发往 53 端口的查询被劫持到内核，按进程组经该组的
//! 出站交给用户配置的服务器解析，绕开本地被污染的结果。
//!
//! 每个被进程组引用的出站对应一个服务器（标签 `remote-<n>`，`detour` 为该出站）；服务器地址是域名时先用
//! 本地 DNS 解析它。未配置服务器或关闭了 `hijack_port53` 时不生成任何东西，查询照旧。
//! 服务器地址只来自用户配置，这里不提供任何默认值（C-SEC-09）。

use std::collections::HashMap;

use procroute_config::dns::{RemoteDns as Server, parse_remote};
use procroute_proto::profile::Profile;
use serde_json::{Value, json};

use super::{GenError, LOCAL_DNS_TAG};

/// 本次配置要用到的远程服务器。
pub(super) struct RemoteDns {
    servers: Vec<Value>,
    by_outbound: HashMap<String, String>,
}

impl RemoteDns {
    /// 经 `outbound` 出站发出的那个远程服务器的标签。
    pub(super) fn server_for(&self, outbound: &str) -> &str {
        self.by_outbound
            .get(outbound)
            .map_or(LOCAL_DNS_TAG, String::as_str)
    }
}

/// 方案要求远程 DNS 时返回服务器列表。方案已经过校验，地址格式不会出错。
pub(super) fn plan(profile: &Profile) -> Result<Option<RemoteDns>, GenError> {
    let Some(raw) = profile.dns.remote_server.as_deref() else {
        return Ok(None);
    };
    if !profile.dns.hijack_port53 {
        return Ok(None);
    }
    let parsed = parse_remote(raw).map_err(|_| GenError::InvalidProfile(1))?;
    let mut servers = Vec::new();
    let mut by_outbound = HashMap::new();
    for g in &profile.groups {
        if by_outbound.contains_key(&g.outbound) {
            continue;
        }
        let tag = format!("remote-{}", servers.len());
        servers.push(server(&parsed, &tag, &g.outbound));
        by_outbound.insert(g.outbound.clone(), tag);
    }
    Ok(Some(RemoteDns {
        servers,
        by_outbound,
    }))
}

fn server(s: &Server, tag: &str, detour: &str) -> Value {
    let mut v = json!({
        "type": s.transport.sing_box_type(),
        "tag": tag,
        "server": s.host,
        "detour": detour,
    });
    if let Some(port) = s.port {
        v["server_port"] = json!(port);
    }
    if let Some(path) = &s.path {
        v["path"] = json!(path);
    }
    if s.host_is_domain {
        v["domain_resolver"] = json!(LOCAL_DNS_TAG);
    }
    v
}

/// `dns` 段：本地服务器（解析节点域名、未劫持的查询）加上远程服务器与按进程组的规则。
pub(super) fn section(remote: Option<&RemoteDns>, rules: Vec<Value>) -> Value {
    let mut servers = vec![json!({ "type": "local", "tag": LOCAL_DNS_TAG })];
    if let Some(r) = remote {
        servers.extend(r.servers.iter().cloned());
    }
    let mut v = json!({ "servers": servers, "final": LOCAL_DNS_TAG });
    if !rules.is_empty() {
        v["rules"] = Value::Array(rules);
    }
    v
}
