// SPDX-License-Identifier: GPL-3.0-or-later
//! `node.import` 的订阅部分：拉取（WinHTTP）、解析、与已有订阅节点合并；以及 `node.list` 里的订阅列表。
//!
//! - 拉取只由用户操作触发（C-SEC-08），大小上限 10 MB、节点总数上限 5000（C-SEC-07）；
//! - 完整地址可能含访问令牌：加密落盘，日志、错误与返回值里只出现 `scheme://host`（C-SEC-04）；
//! - 再次导入同一地址即刷新：内容没变的节点保留原 id（方案按 id 引用出站），消失的节点删除，
//!   新节点追加。

use procroute_core_mgr::link::{
    self, Issue, MAX_INPUT_BYTES, MAX_NODES, ParseOutcome, TOO_MANY_NODES,
};
use procroute_platform_win::http::{self, GetOptions, HttpError};
use procroute_platform_win::secret::Secret;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::node::{ImportIssue, NodeImportResult, SubscriptionInfo};
use serde_json::Value;
use std::time::Duration;

use super::node::{DUPLICATE, now_ms, same_node, storage_error, unique_id};
use super::{Services, blocking, to_json};
use crate::node_store::{NodeData, StoredNode, StoredSubscription};

/// 订阅名的最大字符数。
const MAX_NAME_CHARS: usize = 64;
/// 订阅地址的最大长度。
const MAX_URL_LEN: usize = 2048;
/// 拉取订阅时每个阶段的超时。
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) async fn import(svc: &Services, name: String, url: String) -> Result<Value, IpcError> {
    let name = check_name(&name)?;
    let url = check_url(url)?;
    let shown = url_display(url.expose());
    let fetch_url = url.clone();
    let body = blocking(move || fetch(&fetch_url)).await?;
    let store = svc.nodes.clone();
    let result = blocking(move || {
        let parsed = link::parse_text(&String::from_utf8_lossy(&body));
        store
            .update_all(|data| merge(data, name, url, parsed, now_ms()))
            .map_err(storage_error)
    })
    .await?;
    tracing::info!(
        subscription = %shown,
        added = result.added,
        skipped = result.skipped,
        "subscription imported"
    );
    to_json(result)
}

/// `node.list` 里的订阅列表。
pub(super) fn infos(data: &NodeData) -> Vec<SubscriptionInfo> {
    data.subscriptions
        .iter()
        .map(|s| SubscriptionInfo {
            id: s.id.clone(),
            name: s.name.clone(),
            url_display: url_display(s.url.expose()),
            node_count: u32::try_from(
                data.nodes
                    .iter()
                    .filter(|n| n.subscription_id.as_deref() == Some(s.id.as_str()))
                    .count(),
            )
            .unwrap_or(u32::MAX),
            updated_at_ms: s.updated_at_ms,
        })
        .collect()
}

/// `scheme://host[:port]`：去掉用户信息、路径、查询串与片段，令牌通常就在这些地方。
pub(super) fn url_display(url: &str) -> String {
    let (scheme, rest) = url.split_once("://").unwrap_or(("", url));
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    format!("{scheme}://{host}")
}

fn invalid(message: &str) -> IpcError {
    IpcError::new(ErrorCode::IpcInvalidParams, message)
}

fn check_name(name: &str) -> Result<String, IpcError> {
    let name = name.trim();
    if name.is_empty()
        || name.chars().count() > MAX_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(invalid(
            "subscription name is empty, too long or has control characters",
        ));
    }
    Ok(name.to_owned())
}

fn check_url(url: String) -> Result<Secret<String>, IpcError> {
    let scheme_ok = url.starts_with("https://") || url.starts_with("http://");
    let clean = !url.chars().any(|c| c.is_whitespace() || c.is_control());
    let has_host = url_display(&url).len() > "https://".len();
    if !scheme_ok || !clean || url.len() > MAX_URL_LEN || !has_host {
        return Err(invalid(
            "subscription URL must be an http(s) URL of at most 2048 characters",
        ));
    }
    Ok(Secret::new(url))
}

fn import_failed(message: String) -> IpcError {
    IpcError::new(ErrorCode::NodeImportFailed, message)
}

/// 下载订阅内容。错误信息里没有地址。
fn fetch(url: &Secret<String>) -> Result<Vec<u8>, IpcError> {
    let opts = GetOptions {
        timeout: FETCH_TIMEOUT,
        max_body: MAX_INPUT_BYTES,
        user_agent: format!("ProcRoute/{}", env!("CARGO_PKG_VERSION")),
    };
    match http::get(url.expose(), &opts) {
        Ok(r) if (200..300).contains(&r.status) => Ok(r.body),
        Ok(r) => Err(import_failed(format!(
            "the subscription server answered HTTP {}",
            r.status
        ))),
        Err(HttpError::TooLarge(n)) => {
            Err(import_failed(format!("the subscription exceeds {n} bytes")))
        }
        Err(e) => Err(import_failed(format!(
            "cannot download the subscription: {e}"
        ))),
    }
}

/// 把一次拉取的结果并入存储。同一地址的订阅视为刷新。
fn merge(
    data: &mut NodeData,
    name: String,
    url: Secret<String>,
    parsed: ParseOutcome,
    now: u64,
) -> NodeImportResult {
    let sub_id = upsert_subscription(&mut data.subscriptions, name, url, now);
    let (mut old, others): (Vec<StoredNode>, Vec<StoredNode>) = std::mem::take(&mut data.nodes)
        .into_iter()
        .partition(|n| n.subscription_id.as_deref() == Some(sub_id.as_str()));
    let mut issues = parsed.issues;
    let mut kept: Vec<StoredNode> = Vec::new();
    let mut added = 0u32;
    let mut overflow = 0u32;
    for (i, p) in parsed.nodes.into_iter().enumerate() {
        if overflow > 0 {
            overflow += 1;
            continue;
        }
        if kept.iter().any(|k| same_node(k, &p.node, &p.credentials)) {
            issues.push(Issue {
                line: p.line,
                code: DUPLICATE,
            });
            continue;
        }
        if let Some(pos) = old
            .iter()
            .position(|o| same_node(o, &p.node, &p.credentials))
        {
            let mut node = old.swap_remove(pos);
            node.name = p.name;
            kept.push(node);
            continue;
        }
        if others.len() + kept.len() >= MAX_NODES {
            issues.push(Issue {
                line: p.line,
                code: TOO_MANY_NODES,
            });
            overflow = 1;
            continue;
        }
        let id = unique_id(
            |id| {
                others
                    .iter()
                    .chain(kept.iter())
                    .chain(old.iter())
                    .any(|n| n.id == id)
            },
            u128::from(now),
            i,
        );
        kept.push(StoredNode {
            id,
            name: p.name,
            subscription_id: Some(sub_id.clone()),
            node: p.node,
            credentials: p.credentials,
        });
        added += 1;
    }
    data.nodes = others;
    data.nodes.extend(kept);
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

/// 按地址找到已有订阅并更新名称与时间，没有就新建；返回订阅 id。
fn upsert_subscription(
    subs: &mut Vec<StoredSubscription>,
    name: String,
    url: Secret<String>,
    now: u64,
) -> String {
    if let Some(s) = subs.iter_mut().find(|s| s.url.expose() == url.expose()) {
        s.name = name;
        s.updated_at_ms = Some(now);
        return s.id.clone();
    }
    let mut seq = 0;
    let id = loop {
        let id = format!("s{now:x}-{seq}");
        if !subs.iter().any(|s| s.id == id) {
            break id;
        }
        seq += 1;
    };
    subs.push(StoredSubscription {
        id: id.clone(),
        name,
        url,
        updated_at_ms: Some(now),
    });
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_keeps_only_scheme_and_host() {
        assert_eq!(
            url_display("https://sub.example.com/api/v1?token=hunter2#x"),
            "https://sub.example.com"
        );
        assert_eq!(
            url_display("http://user:pw@sub.example.com:8443/s"),
            "http://sub.example.com:8443"
        );
        assert_eq!(
            url_display("https://sub.example.com"),
            "https://sub.example.com"
        );
    }

    #[test]
    fn names_and_urls_are_checked() {
        assert_eq!(check_name("  我的订阅 ").expect("ok"), "我的订阅");
        assert!(check_name("   ").is_err());
        assert!(check_name(&"长".repeat(MAX_NAME_CHARS + 1)).is_err());
        assert!(check_name("a\u{7}b").is_err());
        assert!(check_url("https://sub.example.com/s?t=1".into()).is_ok());
        for bad in [
            "ftp://sub.example.com/s",
            "https://",
            "https://sub.example.com/a b",
            "sub.example.com/s",
        ] {
            assert!(check_url(bad.into()).is_err(), "{bad}");
        }
        assert!(check_url(format!("https://a.example/{}", "x".repeat(MAX_URL_LEN))).is_err());
    }
}
