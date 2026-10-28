// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows 平台封装（T-050）。
//!
//! 本 crate 是除 `intercept::*::ffi` 之外唯一允许出现 `unsafe` 的地方（C-CODE-01），
//! 每处 `unsafe` 块上方必须有 `// SAFETY:` 注释。目前还没有任何 `unsafe`，所以仍沿用
//! workspace 的 `unsafe_code = "forbid"`；第一个需要它的模块落地时，改为本 crate 自己的
//! `[lints]` 配置并在该模块上局部放开。
//!
//! 模块划分：
//!
//! - `secret`：凭据包装，跨平台（T-051）；
//! - `path`：NT 设备路径转 DOS 路径、8.3 短名展开（T-052，仅 Windows）；
//! - `dpapi`：机器范围 DPAPI 加解密（T-053，仅 Windows）；
//! - `acl`：控制管道的安全描述符（T-054，仅 Windows）；
//! - `service`：Windows 服务控制（仅 Windows）。

#[cfg(windows)]
pub mod acl;
#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod path;
#[cfg(windows)]
pub mod service;
