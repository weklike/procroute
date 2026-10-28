// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask <命令>`：仓库内的自动化任务。
//!
//! 新增子命令时同步更新 AGENTS.md 第 3.2 节的命令表。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

mod gen_types;

const HELP: &str = "\
用法：cargo xtask <命令>

命令：
  help                显示本帮助
  gen-types [--check] 从 crates/proto 生成 app/src/api/generated.ts；
                      --check 只检查是否过期（CI 用）

尚未实现（见 TASKS.md）：
  fetch-deps   拉取并校验第三方二进制
  dev          在测试虚拟机中以控制台模式运行服务和界面
  bundle       打包安装包
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
