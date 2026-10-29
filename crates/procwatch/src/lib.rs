// SPDX-License-Identifier: GPL-3.0-or-later
//! 进程追踪（T-079，设计文档 6.4）。
//!
//! - [`tree`]：进程树与目标集合。进程身份是「PID + 创建时间」（C-DRV-04），子进程按
//!   `procroute_rules::inherit` 继承父进程的组。纯逻辑，跨平台；
//! - `snapshot`（仅 Windows）：Toolhelp 快照，附创建时间与完整路径；
//! - `watcher`（仅 Windows）：ETW 实时进程事件驱动进程树，启动时与之后定期用快照补登、校正；
//!   ETW 不可用（没有管理员权限、会话被外部停掉）时退回定时快照。
//!
//! 目标集合的变化以 [`Change`] 交给调用方；本 crate 不依赖拦截层，由 `svc` 接到需要的地方
//! （C-ARCH-02）。
#![forbid(unsafe_code)]

#[cfg(windows)]
pub mod snapshot;
pub mod tree;
#[cfg(windows)]
pub mod watcher;

pub use tree::{Change, ProcessInfo, ProcessKey, ProcessTree};
