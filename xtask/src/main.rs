// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask <命令>`：仓库内的自动化任务。
//!
//! 新增子命令时同步更新 AGENTS.md 第 3.2 节的命令表。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[cfg(windows)]
mod bundle;
mod fetch_deps;
mod gen_types;
#[cfg(windows)]
mod sandbox;
#[cfg(windows)]
mod sandbox_dev;
#[cfg(windows)]
mod sandbox_install;
#[cfg(windows)]
mod sandbox_test;

const HELP: &str = "\
用法：cargo xtask <命令>

命令：
  help                显示本帮助
  gen-types [--check] 从 crates/proto 生成 app/src/api/generated.ts；
                      --check 只检查是否过期（CI 用）
  fetch-deps          按 third_party/*/lock.json 拉取并校验第三方二进制（Windows）
  sandbox-test [--only <测试名>]... [--keep-open] [--timeout-mins <分钟>]
                      在 Windows Sandbox 中运行只允许在虚拟机里运行的测试
                      （驱动、WFP、管理员权限，C-TEST-04）
  bundle              打包 Windows 安装器：本机自签名证书签名服务、界面与安装器，
                      输出到 target/bundle（Windows）
  sandbox-install [--keep-open] [--timeout-mins <分钟>]
                      在 Windows Sandbox 中验证安装器：安装、服务与界面、卸载后无残留
  sandbox-dev [--timeout-mins <分钟>]
                      在 Windows Sandbox 中以控制台模式运行真实的服务与界面，
                      供手动联调（沙盒保持打开，关窗口即结束）

尚未实现（见 TASKS.md）：
  dev          在装有工具链的测试虚拟机中以控制台模式运行服务和 tauri dev
  e2e          在 Hyper-V 虚拟机中运行端到端测试
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |f: &str| args.iter().skip(1).any(|a| a == f);
    let result = match args.first().map(String::as_str) {
        None | Some("help" | "-h" | "--help") => {
            print!("{HELP}");
            Ok(())
        }
        Some("gen-types") => gen_types::run(flag("--check")),
        Some("fetch-deps") => fetch_deps::run(),
        #[cfg(windows)]
        Some("sandbox-test") => sandbox_test::run(&args[1..]),
        #[cfg(not(windows))]
        Some("sandbox-test") => Err(anyhow::anyhow!(
            "sandbox-test 需要 Windows（Windows Sandbox）"
        )),
        #[cfg(windows)]
        Some("sandbox-dev") => sandbox_dev::run(&args[1..]),
        #[cfg(windows)]
        Some("bundle") => bundle::run(&args[1..]),
        #[cfg(windows)]
        Some("sandbox-install") => sandbox_install::run(&args[1..]),
        #[cfg(not(windows))]
        Some("sandbox-install") => Err(anyhow::anyhow!(
            "sandbox-install 需要 Windows（Windows Sandbox）"
        )),
        #[cfg(not(windows))]
        Some("bundle") => Err(anyhow::anyhow!("bundle 需要 Windows")),
        #[cfg(not(windows))]
        Some("sandbox-dev") => Err(anyhow::anyhow!(
            "sandbox-dev 需要 Windows（Windows Sandbox）"
        )),
        Some(other) => {
            eprintln!("未知命令：{other}\n");
            eprint!("{HELP}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("错误：{e:#}");
            ExitCode::FAILURE
        }
    }
}

/// 仓库根目录（xtask 的上一级）。
pub(crate) fn workspace_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.parent().unwrap_or(manifest).to_path_buf()
}
