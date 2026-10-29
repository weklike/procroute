// SPDX-License-Identifier: GPL-3.0-or-later
//! `procroute-ui`：ProcRoute 的 Windows 客户端外壳（Tauri 2）。
//!
//! 普通用户权限运行，不持有凭据、不碰驱动与配置目录（C-ARCH-01）；只依赖 `procroute-proto`
//! （C-ARCH-02），所有服务端操作都经控制管道交给 `procroute-svc`。界面本身在 `app/src/`。
//!
//! - [`ipc`]：控制管道客户端（握手、请求配对、通知转发、断线重连与订阅重放）；
//! - [`shell`]：Tauri 命令、主窗口、托盘与开机自启。
#![forbid(unsafe_code)]
// 发布构建不弹控制台窗口
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

#[cfg(windows)]
mod ipc;
#[cfg(windows)]
mod shell;

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("procroute-ui only runs on Windows");
    std::process::ExitCode::FAILURE
}

#[cfg(windows)]
fn main() {
    shell::run();
}
