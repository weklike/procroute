// SPDX-License-Identifier: GPL-3.0-or-later
//! 诊断包（T-112）：收集环境、会话、方案、节点概况与服务日志的末尾，脱敏后交给 `diag.export`。
//!
//! - 不导出凭据、订阅地址、节点名称与节点地址（C-SEC-04）；方案规则里的用户目录名、远程 DNS
//!   服务器地址脱敏；日志按 [`redact`] 的规则逐行处理，节点地址、凭据、订阅地址先登记进去；
//! - 任何一部分收集失败只记进 `problems`，不影响其余部分：存储损坏时恰恰最需要诊断包；
//! - 整份报告必须放得进一条 IPC 消息（C-SEC-03），超出时从最旧的日志行开始丢。
//!
//! 这里全是阻塞 IO，异步代码必须经 `spawn_blocking` 调用（C-CODE-05）。

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use procroute_core_mgr::kernel_lock::locked_kernel;
use procroute_platform_win::hash::{sha256_file, to_hex};
use procroute_platform_win::os;
use procroute_proto::IPC_PROTOCOL_VERSION;
use procroute_proto::diag::{
    DiagEnvironment, DiagFileState, DiagLog, DiagNode, DiagNodes, DiagProtocolCount, DiagReport,
    DiagSubscription,
};
use procroute_proto::node::CredentialState;
use procroute_proto::profile::{MatchRule, Profile};
use procroute_proto::rpc::MAX_MESSAGE_BYTES;
use procroute_proto::session::SessionStatus;

use crate::node_store::{NodeData, NodeStore};
use crate::store::ProfileStore;

mod redact;

use redact::{MASK, Redactor, scrub_user_dirs};

/// 只读日志文件末尾这么多字节。
const LOG_TAIL_BYTES: u64 = 512 * 1024;
/// 单行日志的长度上限（字节），超出截断。
const MAX_LINE_BYTES: usize = 4096;
/// 报告序列化后的上限：给 JSON-RPC 信封留出余量。
const REPORT_BUDGET: usize = MAX_MESSAGE_BYTES - 64 * 1024;

const NODE: &str = "<node>";
const SUBSCRIPTION: &str = "<subscription>";

/// 诊断包要读的文件。控制台模式下没有日志文件；测试里两者都可以没有。
#[derive(Debug, Clone, Default)]
pub struct DiagSources {
    /// 服务日志（`<配置根>\logs\svc.log`）。
    pub log_file: Option<PathBuf>,
    /// 安装目录里的 `sing-box.exe`，与版本锁比对。
    pub kernel_exe: Option<PathBuf>,
}

/// 生成脱敏后的诊断报告。
pub fn collect(
    profiles: &ProfileStore,
    nodes: &NodeStore,
    sources: &DiagSources,
    session: SessionStatus,
    now_ms: u64,
) -> DiagReport {
    let mut problems = Vec::new();
    let node_data = nodes
        .load_all()
        .inspect_err(|e| tracing::warn!(error = %e, "diagnostics: cannot read nodes"))
        .ok();
    if node_data.is_none() {
        problems.push("node_store_unreadable");
    }
    let profiles = profiles.list().unwrap_or_else(|e| {
        tracing::warn!(error = %e, "diagnostics: cannot list profiles");
        problems.push("profile_store_unreadable");
        Vec::new()
    });
    let redactor = node_data.as_ref().map(redactor_for).unwrap_or_default();
    let mut report = DiagReport {
        generated_at_ms: now_ms,
        environment: environment(sources.kernel_exe.as_deref(), &mut problems),
        session,
        nodes: node_data.as_ref().map(|d| node_summary(d, &profiles)),
        profiles: profiles.into_iter().map(sanitize_profile).collect(),
        log: read_log(sources.log_file.as_deref(), &redactor, &mut problems),
        problems: Vec::new(),
    };
    fit(&mut report, &mut problems);
    report.problems = problems.into_iter().map(str::to_owned).collect();
    report
}

/// 把节点地址、TLS 服务器名、凭据与订阅地址登记为要替换的文本。
fn redactor_for(data: &NodeData) -> Redactor {
    let mut r = Redactor::default();
    for n in &data.nodes {
        r.add(&n.node.server, NODE);
        if let Some(sni) = n.node.tls().and_then(|t| t.server_name.as_deref()) {
            r.add(sni, NODE);
        }
        let c = &n.credentials;
        for secret in [&c.username, &c.password, &c.uuid, &c.obfs_password]
            .into_iter()
            .flatten()
        {
            r.add(secret.expose(), MASK);
        }
    }
    for s in &data.subscriptions {
        let url = s.url.expose();
        r.add(url, SUBSCRIPTION);
        r.add(url_host(url), SUBSCRIPTION);
    }
    r
}

/// 地址里的主机部分（含端口）：去掉协议、用户信息、路径、查询串与片段。
fn url_host(url: &str) -> &str {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    authority.rsplit_once('@').map_or(authority, |(_, h)| h)
}

fn environment(kernel_exe: Option<&Path>, problems: &mut Vec<&'static str>) -> DiagEnvironment {
    let version = os::windows_version();
    if version.is_none() {
        problems.push("os_version_unreadable");
    }
    let lock = locked_kernel().ok();
    if lock.is_none() {
        problems.push("kernel_lock_invalid");
    }
    let kernel_binary = match (kernel_exe, &lock) {
        (Some(path), Some(lock)) => check_file(path, &lock.sha256),
        _ => DiagFileState::Unknown,
    };
    let (os_build, os_display_version) =
        version.map_or((None, None), |v| (Some(v.build), v.display_version));
    DiagEnvironment {
        service_version: env!("CARGO_PKG_VERSION").to_owned(),
        protocol_version: IPC_PROTOCOL_VERSION,
        os_build,
        os_display_version,
        memory_integrity: os::memory_integrity_enabled(),
        kernel_version: lock.map(|l| l.version),
        kernel_binary,
    }
}

/// 文件与锁文件里的 SHA-256（小写十六进制）比对。
fn check_file(path: &Path, sha256: &str) -> DiagFileState {
    match path.try_exists() {
        Ok(false) => return DiagFileState::Missing,
        Err(_) => return DiagFileState::Unreadable,
        Ok(true) => {}
    }
    match sha256_file(path) {
        Ok(digest) if to_hex(&digest) == sha256 => DiagFileState::Verified,
        Ok(_) => DiagFileState::Mismatch,
        Err(_) => DiagFileState::Unreadable,
    }
}

/// 节点计数与方案用到的节点。每个节点都是一个单节点出站、标签即节点 id（见 `handlers::node`），
/// 节点组接入后这里要按组展开成员。
fn node_summary(data: &NodeData, profiles: &[Profile]) -> DiagNodes {
    let mut protocols: Vec<DiagProtocolCount> = Vec::new();
    for n in &data.nodes {
        let protocol = n.node.protocol();
        match protocols.iter_mut().find(|c| c.protocol == protocol) {
            Some(c) => c.count += 1,
            None => protocols.push(DiagProtocolCount { protocol, count: 1 }),
        }
    }
    protocols.sort_by_key(|c| std::cmp::Reverse(c.count));

    let mut tags: Vec<&str> = profiles
        .iter()
        .flat_map(|p| &p.groups)
        .map(|g| g.outbound.as_str())
        .collect();
    tags.sort_unstable();
    tags.dedup();
    let referenced = data
        .nodes
        .iter()
        .filter(|n| tags.binary_search(&n.id.as_str()).is_ok())
        .map(|n| DiagNode {
            id: n.id.clone(),
            protocol: n.node.protocol(),
            server_port: n.node.server_port,
            credential: if n.credentials.is_set() {
                CredentialState::Set
            } else {
                CredentialState::NotSet
            },
            subscription_id: n.subscription_id.clone(),
        })
        .collect();
    let missing_outbounds = tags
        .into_iter()
        .filter(|t| !data.nodes.iter().any(|n| n.id == *t))
        .map(str::to_owned)
        .collect();
    let subscriptions = data
        .subscriptions
        .iter()
        .map(|s| DiagSubscription {
            id: s.id.clone(),
            node_count: count_u32(
                data.nodes
                    .iter()
                    .filter(|n| n.subscription_id.as_deref() == Some(s.id.as_str())),
            ),
            updated_at_ms: s.updated_at_ms,
        })
        .collect();
    DiagNodes {
        total: count_u32(data.nodes.iter()),
        protocols,
        referenced,
        missing_outbounds,
        subscriptions,
    }
}

fn count_u32<T>(items: impl Iterator<Item = T>) -> u32 {
    u32::try_from(items.count()).unwrap_or(u32::MAX)
}

/// 规则里的用户目录名换成占位符；远程 DNS 服务器只留协议（地址里可能有私人解析服务的账号）。
fn sanitize_profile(mut p: Profile) -> Profile {
    let scrub = |rules: &mut Vec<MatchRule>| {
        for r in rules {
            r.value = scrub_user_dirs(&r.value);
        }
    };
    for g in &mut p.groups {
        scrub(&mut g.matchers);
    }
    scrub(&mut p.exclude);
    if let Some(server) = &mut p.dns.remote_server {
        *server = match server.split_once("://") {
            Some((scheme, _)) => format!("{scheme}://{MASK}"),
            None => MASK.to_owned(),
        };
    }
    p
}

fn read_log(path: Option<&Path>, redactor: &Redactor, problems: &mut Vec<&'static str>) -> DiagLog {
    let Some(path) = path else {
        return DiagLog {
            available: false,
            truncated: false,
            lines: Vec::new(),
        };
    };
    match tail(path, LOG_TAIL_BYTES) {
        Ok((text, truncated)) => DiagLog {
            available: true,
            truncated,
            lines: text
                .lines()
                .map(|l| redactor.redact(clip(l, MAX_LINE_BYTES)))
                .collect(),
        },
        Err(e) => {
            tracing::warn!(error = %e, "diagnostics: cannot read the service log");
            problems.push("log_unreadable");
            DiagLog {
                available: true,
                truncated: false,
                lines: Vec::new(),
            }
        }
    }
}

/// 文件末尾至多 `max` 字节；没从开头读时丢掉第一行（多半不完整）。
fn tail(path: &Path, max: u64) -> io::Result<(String, bool)> {
    let mut file = File::open(path)?;
    let start = file.metadata()?.len().saturating_sub(max);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let text = if start > 0 {
        text.split_once('\n').map_or("", |(_, rest)| rest)
    } else {
        &text
    };
    Ok((text.to_owned(), start > 0))
}

/// 截到 `max` 字节以内的字符边界。
fn clip(line: &str, max: usize) -> &str {
    if line.len() <= max {
        return line;
    }
    let end = (0..=max)
        .rev()
        .find(|&i| line.is_char_boundary(i))
        .unwrap_or(0);
    &line[..end]
}

/// 报告超出一条消息的预算时，从最旧的日志行开始丢；日志丢完仍超出（方案极多）时去掉方案。
fn fit(report: &mut DiagReport, problems: &mut Vec<&'static str>) {
    let size = |r: &DiagReport| serde_json::to_vec(r).map_or(usize::MAX, |v| v.len());
    while size(report) > REPORT_BUDGET && !report.log.lines.is_empty() {
        let drop = (report.log.lines.len() / 8).max(1);
        report.log.lines.drain(..drop);
        report.log.truncated = true;
    }
    if size(report) > REPORT_BUDGET {
        report.profiles.clear();
        problems.push("profiles_omitted_for_size");
    }
}

#[cfg(test)]
mod tests;
