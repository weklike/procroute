// SPDX-License-Identifier: GPL-3.0-or-later
//! 流与进程身份。

use std::net::SocketAddr;

use procroute_proto::event::Network;

/// 进程身份：PID + 创建时间（C-DRV-04）。只用 PID 会在 PID 复用时误判。
///
/// `created_at` 的单位由进程追踪器决定（Windows 上是 FILETIME），只要求单调可比。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: u32,
    pub created_at: u64,
}

/// 一条流的五元组（从应用视角：本地端 → 远端）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub network: Network,
    pub local: SocketAddr,
    pub remote: SocketAddr,
}

/// 后端看到的一条新流，交给 [`crate::decide`] 判定。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewFlow {
    pub key: FlowKey,
    /// 归属的进程。首包暂存与端口反查（C-NET-04）之后仍无法归属时为 `None`。
    pub process: Option<ProcessKey>,
}

/// 后端发给上层的流事件。不含任何负载内容，只有元数据（C-NET-02）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEvent {
    /// 流被改道到本地中继。`group` 是方案里进程组的下标。
    Redirected {
        key: FlowKey,
        process: ProcessKey,
        group: u16,
    },
    /// 流按 fail_policy 被阻断（TCP 回 RST、UDP 丢弃）。
    Blocked {
        key: FlowKey,
        process: Option<ProcessKey>,
    },
    /// 改道过的流结束，NAT 表项可以回收。
    Closed { key: FlowKey },
}
