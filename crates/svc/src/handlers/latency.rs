// SPDX-License-Identifier: GPL-3.0-or-later
//! `node.test`：节点测速。
//!
//! 每次调用临时启动一个只有出站、**没有任何入站**的 sing-box（`config_gen::generate_probe`：不建 TUN、
//! 不监听代理端口），经它的控制 API 让每个节点访问测速地址并计时，测完即停。与会话的内核互不影响，
//! 会话运行与否都能测。
//!
//! - 测速地址必须由用户给出，软件不内置任何地址（C-SEC-08、C-SEC-09）；缺省或无效时返回 `ipc.invalid_params`；
//! - 一次最多 [`MAX_NODES_PER_CALL`] 个节点，最多 [`PARALLEL`] 个同时测，单个节点 [`PROBE_TIMEOUT`]：
//!   一次调用在界面的调用超时之内结束，节点多时由界面分批调用；
//! - 结果与日志里没有地址、凭据（C-SEC-04）。

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use procroute_core_mgr::clash_api::{Delay, fetch_delay};
use procroute_core_mgr::config_gen::{NodeOutbound, Runtime, generate_probe};
use procroute_core_mgr::runtime::{free_loopback_port, random_api_secret};
use procroute_platform_win::secret::Secret;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::node::{LatencyResult, NodeTestParams, NodeTestResult};
use serde_json::Value;

use super::subscription::url_display;
use super::{Services, blocking, node, to_json};
use crate::ipc_server::parse_params;
use crate::node_store::StoredNode;

/// 一次调用最多测的节点数。
pub const MAX_NODES_PER_CALL: usize = 64;
/// 同时测的节点数。
const PARALLEL: usize = 16;
/// 单个节点的测速超时。
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// 测速地址的最大长度。
const MAX_URL_LEN: usize = 2048;

pub(super) async fn test(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let NodeTestParams { ids, url } = parse_params(params)?;
    let url = check_url(url)?;
    let store = svc.nodes.clone();
    let stored = blocking(move || store.load().map_err(node::storage_error)).await?;
    let selected = select(stored, &ids)?;
    if selected.is_empty() {
        return to_json(NodeTestResult {
            results: Vec::new(),
        });
    }

    let api_port = free_loopback_port()
        .map_err(|e| IpcError::new(ErrorCode::Internal, format!("no free loopback port: {e}")))?;
    let api_secret =
        random_api_secret().map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))?;
    let runtime = Runtime {
        api_port,
        api_secret: api_secret.clone(),
        self_exe_paths: svc.self_exe_paths.clone(),
    };
    let ids: Vec<String> = selected.iter().map(|n| n.id.clone()).collect();
    let outbounds: Vec<NodeOutbound> = selected
        .into_iter()
        .map(|n| NodeOutbound {
            tag: n.id,
            node: n.node,
            credentials: n.credentials,
        })
        .collect();
    let config = generate_probe(&outbounds, &runtime).map_err(|e| {
        tracing::error!(error = %e, "cannot generate the probe config");
        IpcError::new(ErrorCode::Internal, e.to_string())
    })?;

    let api = SocketAddr::from((Ipv4Addr::LOCALHOST, api_port));
    let launcher = svc.launcher.clone();
    let launched = tokio::task::spawn_blocking(move || {
        let kernel = launcher.launch(config, api, Box::new(|_| {}))?;
        let results = measure(api, &api_secret, &ids, &url);
        kernel.stop();
        Ok(results)
    })
    .await
    .map_err(|e| IpcError::new(ErrorCode::Internal, format!("worker failed: {e}")))?;
    let results = launched.map_err(|e: procroute_core_mgr::supervisor::LaunchError| {
        tracing::warn!(error = %e, "probe kernel failed to start");
        IpcError::new(
            ErrorCode::KernelUnavailable,
            format!("sing-box failed to start: {e}"),
        )
    })?;
    let ok = results.iter().filter(|r| r.latency_ms.is_some()).count();
    tracing::info!(nodes = results.len(), ok, "latency test finished");
    to_json(NodeTestResult { results })
}

/// 测速地址：`https://` 开头（原因见 `clash_api::fetch_delay`）、有主机名、不含空白与控制字符、
/// 不超过 2048 字节。
fn check_url(url: Option<String>) -> Result<String, IpcError> {
    let Some(url) = url else {
        return Err(IpcError::new(
            ErrorCode::IpcInvalidParams,
            "set a latency test URL first",
        ));
    };
    let scheme_ok = url.starts_with("https://");
    let clean = !url.chars().any(|c| c.is_whitespace() || c.is_control());
    let has_host = url_display(&url).len() > "https://".len();
    if !scheme_ok || !clean || url.len() > MAX_URL_LEN || !has_host {
        return Err(IpcError::new(
            ErrorCode::IpcInvalidParams,
            "latency test URL must be an https:// URL of at most 2048 characters",
        ));
    }
    Ok(url)
}

/// 按 `ids` 的顺序挑出节点；`ids` 为空表示全部。重复的 id 只测一次。
fn select(stored: Vec<StoredNode>, ids: &[String]) -> Result<Vec<StoredNode>, IpcError> {
    let selected: Vec<StoredNode> = if ids.is_empty() {
        stored
    } else {
        let mut picked: Vec<StoredNode> = Vec::with_capacity(ids.len());
        let mut pool = stored;
        for id in ids {
            if picked.iter().any(|n| &n.id == id) {
                continue;
            }
            let Some(pos) = pool.iter().position(|n| &n.id == id) else {
                return Err(IpcError::new(ErrorCode::NodeNotFound, "node not found"));
            };
            picked.push(pool.swap_remove(pos));
        }
        picked
    };
    if selected.len() > MAX_NODES_PER_CALL {
        return Err(IpcError::new(
            ErrorCode::IpcInvalidParams,
            format!("at most {MAX_NODES_PER_CALL} nodes per call"),
        ));
    }
    Ok(selected)
}

/// 最多 [`PARALLEL`] 个线程同时测，结果按 `ids` 的顺序返回。
fn measure(
    api: SocketAddr,
    secret: &Secret<String>,
    ids: &[String],
    url: &str,
) -> Vec<LatencyResult> {
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<LatencyResult>>> = ids.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..PARALLEL.min(ids.len()) {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(id) = ids.get(i) else { break };
                    let result = probe(api, secret, id, url);
                    if let Some(slot) = slots.get(i)
                        && let Ok(mut slot) = slot.lock()
                    {
                        *slot = Some(result);
                    }
                }
            });
        }
    });
    ids.iter()
        .zip(slots)
        .map(|(id, slot)| {
            slot.into_inner()
                .ok()
                .flatten()
                .unwrap_or_else(|| failed(id))
        })
        .collect()
}

fn probe(api: SocketAddr, secret: &Secret<String>, id: &str, url: &str) -> LatencyResult {
    match fetch_delay(api, secret, id, url, PROBE_TIMEOUT) {
        Ok(Delay::Ms(ms)) => LatencyResult {
            id: id.to_owned(),
            latency_ms: Some(ms),
            timed_out: false,
        },
        Ok(Delay::TimedOut) => LatencyResult {
            id: id.to_owned(),
            latency_ms: None,
            timed_out: true,
        },
        Ok(Delay::Failed) => failed(id),
        Err(e) => {
            tracing::debug!(node = id, error = %e, "latency request failed");
            failed(id)
        }
    }
}

fn failed(id: &str) -> LatencyResult {
    LatencyResult {
        id: id.to_owned(),
        latency_ms: None,
        timed_out: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_urls_are_checked() {
        assert_eq!(
            check_url(None).unwrap_err().code,
            ErrorCode::IpcInvalidParams
        );
        for bad in [
            "ftp://x.example/",
            "http://x.example/generate_204",
            "HTTPS://x.example/generate_204",
            "https://",
            "https://x.example/a b",
            "https://x.example/\n",
            "x.example/generate_204",
        ] {
            assert_eq!(
                check_url(Some(bad.into())).unwrap_err().code,
                ErrorCode::IpcInvalidParams,
                "{bad}"
            );
        }
        let long = format!("https://x.example/{}", "a".repeat(MAX_URL_LEN));
        assert!(check_url(Some(long)).is_err());
        assert_eq!(
            check_url(Some("https://127.0.0.1:8080/204".into())).unwrap(),
            "https://127.0.0.1:8080/204"
        );
    }
}
