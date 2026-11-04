// SPDX-License-Identifier: GPL-3.0-or-later
//! 端到端测试的公共部分：泄漏检测器（[`leak_detector`]）与测试框架（`harness`，仅 Windows）。
//!
//! 用例在 `tests/` 下，只在 `--features vm-tests` 时编译，必须在虚拟机里以管理员身份运行（C-TEST-04）：
//! `cargo xtask sandbox-test --only leak_e2e`。
#![forbid(unsafe_code)]

#[cfg(windows)]
pub mod harness;
pub mod leak_detector;
