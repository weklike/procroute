// SPDX-License-Identifier: GPL-3.0-or-later
//! 进程匹配引擎。
//!
//! 只有纯函数：不读文件、不访问网络、不调用平台 API（C-ARCH-02）。
//! NT 设备路径转 DOS 路径、8.3 短名展开等需要系统调用的步骤由 `platform-win`
//! 在调用前完成，这里只做与平台无关的规范化。
#![forbid(unsafe_code)]

pub mod engine;
pub mod matcher;
pub mod path;
