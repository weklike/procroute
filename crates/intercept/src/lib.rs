// SPDX-License-Identifier: GPL-3.0-or-later
//! 拦截层：认出目标进程的流，并决定改道、放行还是阻断。
//!
//! 所有后端都通过 [`Interceptor`] 接入（C-DRV-06），判定顺序统一由 [`decide`] 给出，
//! 这样假后端上的测试与真实后端的行为一致。真正的代理工作不在这里：改道后的流
//! 交给本地中继，中继与本 crate 只通过 svc 组装的 trait 与消息交互（C-ARCH-02）。
//!
//! 目前只有跨平台部分与假后端；WinDivert 后端在 `divert/`（T-071 起，仅 Windows）。
//! `unsafe` 只允许出现在 `*::ffi` 子模块（C-CODE-01）。

pub mod backend;
pub mod exclude;
pub mod flow;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

pub use backend::{
    BypassReason, Counters, FlowPolicy, InterceptError, InterceptSettings, InterceptStats,
    Interceptor, StartContext, Verdict, decide, emit, unprocessable,
};
pub use exclude::ExclusionSet;
pub use flow::{FlowEvent, FlowKey, NewFlow, ProcessKey};
