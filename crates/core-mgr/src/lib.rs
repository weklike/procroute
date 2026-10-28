// SPDX-License-Identifier: GPL-3.0-or-later
//! sing-box 内核管理。
//!
//! sing-box 只以独立子进程方式接入（C-ARCH-03），版本锁定在 `third_party/sing-box/lock.json`。
//! 本 crate 负责：
//!
//! - [`node`]：节点模型，参数与凭据分开持有（C-SEC-04）；
//! - [`link`]：分享链接与订阅内容解析（`node.import`），支持范围见模块文档；
//! - [`config_gen`]：由方案、节点与运行参数生成 sing-box 配置（T-055，TUN 模式）；
//! - [`kernel_lock`]：编译进来的版本锁，启动前据此校验 `sing-box.exe`（C-SEC-06）；
//! - [`runtime`]：每次启动随机生成的控制 API 端口与密钥（C-NET-08）；
//! - [`restart`] 与 `supervisor`：子进程守护与重启预算（T-056，C-PERF-05；守护只在 Windows 上）；
//! - 控制 API 客户端（测速、连接列表，待实现）。
//!
//! 与 `procwatch`、`intercept`、`relay` 之间没有直接依赖（C-ARCH-02），由 `svc` 组装。
#![forbid(unsafe_code)]

pub mod config_gen;
pub mod kernel_lock;
pub mod link;
pub mod node;
mod outbound;
mod process_regex;
pub mod restart;
pub mod runtime;
#[cfg(windows)]
pub mod supervisor;
