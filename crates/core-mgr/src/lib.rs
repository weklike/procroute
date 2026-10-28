// SPDX-License-Identifier: GPL-3.0-or-later
//! sing-box 内核管理。
//!
//! sing-box 只以独立子进程方式接入（C-ARCH-03），版本锁定在 `third_party/sing-box/lock.json`。
//! 本 crate 负责：
//!
//! - [`node`]：节点模型，参数与凭据分开持有（C-SEC-04）；
//! - [`config_gen`]：由方案、节点与运行参数生成 sing-box 配置（T-055，TUN 模式）；
//! - 子进程守护与控制 API 客户端（T-056，待实现）。
//!
//! 与 `procwatch`、`intercept`、`relay` 之间没有直接依赖（C-ARCH-02），由 `svc` 组装。
#![forbid(unsafe_code)]

pub mod config_gen;
pub mod node;
mod outbound;
mod process_regex;
