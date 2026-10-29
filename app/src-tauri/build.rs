// SPDX-License-Identifier: GPL-3.0-or-later
//! 只在 Windows 目标上生成 Tauri 上下文（其他平台只编译一个提示后退出的 main）。
//!
//! 应用自己的命令登记在 app manifest 里：每个命令都必须在 `capabilities/` 中显式授权，
//! 而不是默认对所有窗口开放（C-SEC-10）。

/// 前端可以调用的全部应用命令。新增命令时同时在 `capabilities/main.json` 里授权。
const COMMANDS: &[&str] = &["ipc_call", "tray_update", "autostart_get", "autostart_set"];

fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    if let Err(e) = tauri_build::try_build(attributes) {
        // 构建脚本只能以失败退出的方式报告错误
        eprintln!("tauri-build failed: {e:#}");
        std::process::exit(1);
    }
}
