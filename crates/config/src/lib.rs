// SPDX-License-Identifier: GPL-3.0-or-later
//! 方案（Profile）的校验与 schema 迁移。
//!
//! 数据结构本身定义在 `procroute-proto`（见 docs/adr/0001），这里重新导出，
//! 让服务端只需要依赖本 crate 就能拿到「解析 → 迁移 → 校验」的完整流程。
//! 本 crate 不依赖平台 crate，也不做文件或网络 IO（C-ARCH-02）；读写文件由服务负责。
#![forbid(unsafe_code)]

pub mod dns;
pub mod migrate;
pub mod model;
pub mod validate;
