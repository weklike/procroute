// SPDX-License-Identifier: GPL-3.0-or-later
//! `node.*`：导入分享链接与订阅、列出节点。订阅的拉取与刷新见 [`super::subscription`]，
//! 测速见 [`super::latency`]。
//!
//! 解析在 `procroute-core-mgr::link`，支持范围以锁定的 sing-box 为准；这里负责去重、分配 id、
//! 落盘（凭据经 DPAPI 加密，C-SEC-04）以及把节点映射成 IPC 类型。返回值与错误里不含凭据。

use std::time::{SystemTime, UNIX_EPOCH};

use procroute_core_mgr::link::{self, Issue, MAX_NODES, ParsedNode, TOO_MANY_NODES};
use procroute_core_mgr::node::{Credentials, Node};
use procroute_platform_win::secret::Secret;
use procroute_proto::Empty;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::node::{
    CredentialState, ImportIssue, NodeImportParams, NodeImportResult, NodeInfo, NodeListResult,
    OutboundInfo, OutboundKind,
};
use serde_json::Value;

use super::{Services, blocking, subscription, to_json};
use crate::ipc_server::parse_params;
use crate::node_store::{NodeStoreError, StoredNode};

/// 与已有节点参数、凭据完全相同时跳过。
pub(super) const DUPLICATE: &str = "duplicate";

pub(super) async fn import(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let text = match parse_params::<NodeImportParams>(params)? {
        NodeImportParams::ShareLinks { text } => text,
        NodeImportParams::Subscription { name, url } => {
            return subscription::import(svc, name, url).await;
        }
    };
    let store = svc.nodes.clone();
    let result = blocking(move || {
        let parsed = link::parse_text(&text);
        store
            .update(|nodes| merge(nodes, parsed.nodes, parsed.issues))
            .map_err(storage_error)
    })
    .await?;
    tracing::info!(
        added = result.added,
        skipped = result.skipped,
        "share links imported"
    );
    to_json(result)
}

pub(super) async fn list(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    let store = svc.nodes.clone();
    let data = blocking(move || store.load_all().map_err(storage_error)).await?;
    let subscriptions = subscription::infos(&data);
    let nodes = data.nodes;
    // 每个节点都是一个单节点出站，标签即节点 id；节点组的增删改随后续任务接入
    let outbounds = nodes
        .iter()
        .map(|n| OutboundInfo {
            tag: n.id.clone(),
            kind: OutboundKind::Single,
            members: vec![n.id.clone()],
            current: Some(n.id.clone()),
        })
        .collect();
    let nodes = nodes.into_iter().map(info).collect();
    to_json(NodeListResult {
        nodes,
        outbounds,
        subscriptions,
    })
}

/// 把解析结果并入已有节点：跳过重复项，遵守节点总数上限（C-SEC-07）。
fn merge(
    existing: &mut Vec<StoredNode>,
    parsed: Vec<ParsedNode>,
    mut issues: Vec<Issue>,
) -> NodeImportResult {
    let mut added = 0u32;
    // 达到总数上限后剩下的节点：只在第一个上报问题，其余计入跳过数
    let mut overflow = 0u32;
    let stamp = u128::from(now_ms());
    for (i, p) in parsed.into_iter().enumerate() {
        if overflow > 0 {
            overflow += 1;
            continue;
        }
        if existing
            .iter()
            .any(|e| same_node(e, &p.node, &p.credentials))
        {
            issues.push(Issue {
                line: p.line,
                code: DUPLICATE,
            });
            continue;
        }
        if existing.len() >= MAX_NODES {
            issues.push(Issue {
                line: p.line,
                code: TOO_MANY_NODES,
            });
            overflow = 1;
            continue;
        }
        existing.push(StoredNode {
            id: unique_id(|id| existing.iter().any(|e| e.id == id), stamp, i),
            name: p.name,
            subscription_id: None,
            node: p.node,
            credentials: p.credentials,
        });
        added += 1;
    }
    issues.sort_by_key(|i| i.line);
    let skipped = u32::try_from(issues.iter().filter(|i| i.line > 0).count())
        .unwrap_or(u32::MAX)
        .saturating_add(overflow.saturating_sub(1));
    NodeImportResult {
        added,
        skipped,
        issues: issues
            .into_iter()
            .map(|i| ImportIssue {
                line: i.line,
                reason: i.code.to_owned(),
            })
            .collect(),
    }
}

/// `n<毫秒时间戳的十六进制>-<序号>`；`taken` 判断 id 是否已被占用，冲突时顺延序号。
pub(super) fn unique_id(taken: impl Fn(&str) -> bool, stamp: u128, index: usize) -> String {
    let mut seq = index;
    loop {
        let id = format!("n{stamp:x}-{seq}");
        if !taken(&id) {
            return id;
        }
        seq += 1;
    }
}

/// 当前 Unix 毫秒时间。
pub(super) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// 参数与凭据都相同的才算同一个节点。
pub(super) fn same_node(stored: &StoredNode, node: &Node, credentials: &Credentials) -> bool {
    stored.node == *node && same_credentials(&stored.credentials, credentials)
}

fn same_credentials(a: &Credentials, b: &Credentials) -> bool {
    let eq = |x: &Option<Secret<String>>, y: &Option<Secret<String>>| {
        x.as_ref().map(Secret::expose) == y.as_ref().map(Secret::expose)
    };
    eq(&a.username, &b.username)
        && eq(&a.password, &b.password)
        && eq(&a.uuid, &b.uuid)
        && eq(&a.obfs_password, &b.obfs_password)
}

fn info(n: StoredNode) -> NodeInfo {
    let server = if n.node.server.contains(':') {
        format!("[{}]:{}", n.node.server, n.node.server_port)
    } else {
        format!("{}:{}", n.node.server, n.node.server_port)
    };
    NodeInfo {
        protocol: n.node.protocol(),
        credential: if n.credentials.is_set() {
            CredentialState::Set
        } else {
            CredentialState::NotSet
        },
        id: n.id,
        name: n.name,
        server,
        subscription_id: n.subscription_id,
    }
}

pub(super) fn storage_error(e: NodeStoreError) -> IpcError {
    tracing::error!(error = %e, "node storage failure");
    IpcError::new(ErrorCode::Internal, "node storage failure")
}
