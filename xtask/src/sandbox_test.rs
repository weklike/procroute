// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask sandbox-test [--only <测试名>]... [--keep-open] [--timeout-mins <分钟>]`
//!
//! 在 Windows Sandbox 里运行只允许在虚拟机中运行的测试（C-TEST-04：加载驱动、改动网络行为、
//! 需要管理员权限的测试）。开发机上不会加载驱动，也不会留下 WFP 过滤器或服务。
//!
//! 流程：
//!
//! 1. 在开发机上用静态 CRT 编译各测试程序（只编译、不运行，见 [`crate::sandbox`]）；
//! 2. 把测试程序、锁定版本的 WinDivert 文件、`manifest.json` 与 `xtask/sandbox/run.ps1` 放进
//!    `target/sandbox/in`，以只读方式映射进沙盒；`target/sandbox/out` 可写，用来取回结果；
//! 3. 生成 `.wsb` 并启动沙盒，登录命令运行 `run.ps1`：复制到沙盒本地磁盘后逐个运行测试，
//!    写出 `summary.json` 与各测试的输出，然后关机；
//! 4. 开发机等待 `done` 标记，汇总结果；任一测试失败、或沙盒里不是管理员时返回失败。
//!
//! 只在 Windows 上编译（`main.rs` 里按平台分派）。

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::sandbox::{self, WsbOptions};

/// 一个只能在虚拟机里运行的集成测试。
struct Suite {
    package: &'static str,
    features: &'static str,
    /// `tests/<名字>.rs`
    test: &'static str,
    /// 端到端测试：要服务的「安装目录」和回显目标进程（见 [`stage_e2e`]）。
    e2e: bool,
}

const E2E_PACKAGE: &str = "procroute-e2e";
/// 回显目标进程：测试包里的 bin，放在测试程序旁边。
const ECHO_TARGET: &str = "echo_target";
const SVC_PACKAGE: &str = "procroute-svc";
/// 开发构建的服务跳过控制管道客户端的签名校验（C-SEC-02 只允许调试构建这样做）。
const SVC_FEATURES: &str = "insecure-skip-client-auth";

const SUITES: [Suite; 8] = [
    Suite {
        package: "procroute-platform-win",
        features: "vm-tests",
        test: "wfp_vm",
        e2e: false,
    },
    Suite {
        package: "procroute-platform-win",
        features: "admin-tests",
        test: "etw_admin",
        e2e: false,
    },
    Suite {
        package: "procroute-procwatch",
        features: "admin-tests",
        test: "watcher_admin",
        e2e: false,
    },
    Suite {
        package: "procroute-intercept",
        features: "vm-tests",
        test: "divert_vm",
        e2e: false,
    },
    Suite {
        package: "procroute-intercept",
        features: "vm-tests",
        test: "redirect_vm",
        e2e: false,
    },
    Suite {
        package: "procroute-intercept",
        features: "vm-tests",
        test: "precise_vm",
        e2e: false,
    },
    Suite {
        package: E2E_PACKAGE,
        features: "vm-tests",
        test: "precise_e2e",
        e2e: true,
    },
    Suite {
        package: E2E_PACKAGE,
        features: "vm-tests",
        test: "leak_e2e",
        e2e: true,
    },
];

const RUN_PS1: &str = include_str!("../sandbox/run.ps1");
const WINDIVERT_FILES: [&str; 2] = ["WinDivert.dll", "WinDivert64.sys"];
const KERNEL_FILE_NAME: &str = "sing-box.exe";

struct Options {
    only: Vec<String>,
    keep_open: bool,
    timeout: Duration,
}

pub fn run(args: &[String]) -> Result<()> {
    let opts = parse_args(args)?;
    let suites: Vec<&Suite> = SUITES
        .iter()
        .filter(|s| opts.only.is_empty() || opts.only.iter().any(|o| o == s.test))
        .collect();
    if suites.is_empty() {
        let names: Vec<&str> = SUITES.iter().map(|s| s.test).collect();
        bail!("--only 没有匹配任何测试；可选：{}", names.join("、"));
    }
    run_suites(&crate::workspace_root(), &suites, &opts)
}

fn parse_args(args: &[String]) -> Result<Options> {
    let mut opts = Options {
        only: Vec::new(),
        keep_open: false,
        timeout: Duration::from_secs(20 * 60),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--only" => match it.next() {
                Some(name) => opts.only.push(name.clone()),
                None => bail!("--only 需要一个测试名"),
            },
            "--keep-open" => opts.keep_open = true,
            "--timeout-mins" => {
                let mins: u64 = match it.next().map(|v| v.parse()) {
                    Some(Ok(m)) if m > 0 => m,
                    _ => bail!("--timeout-mins 需要一个正整数"),
                };
                opts.timeout = Duration::from_secs(mins * 60);
            }
            other => bail!("sandbox-test 不认识参数 {other}"),
        }
    }
    Ok(opts)
}

#[derive(Debug, Deserialize)]
struct Summary {
    admin: bool,
    #[serde(default)]
    results: Vec<TestResult>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TestResult {
    name: String,
    exit_code: Option<i64>,
    seconds: f64,
}

fn run_suites(root: &Path, suites: &[&Suite], opts: &Options) -> Result<()> {
    sandbox::ensure_idle()?;
    let base = root.join("target").join("sandbox");
    let input = base.join("in");
    let output = base.join("out");
    sandbox::recreate(&input)?;
    sandbox::recreate(&output)?;

    let mut manifest = Vec::new();
    for s in suites {
        println!(
            "编译 {} 的 {}（--features {}）",
            s.package, s.test, s.features
        );
        let json = sandbox::cargo_json(
            root,
            &base.join("build"),
            &[
                "test",
                "--no-run",
                "-p",
                s.package,
                "--features",
                s.features,
                "--test",
                s.test,
            ],
            s.test,
        )?;
        let exe = sandbox::artifact_executable(&json, "test", s.test)
            .with_context(|| format!("cargo 没有报告 {} 的可执行文件", s.test))?;
        let file = format!("{}.exe", s.test);
        fs::copy(&exe, input.join(&file)).with_context(|| format!("复制 {}", exe.display()))?;
        if s.e2e {
            stage_e2e(root, &base.join("build"), &input, &json)?;
        }
        manifest.push(serde_json::json!({ "name": s.test, "file": file, "args": [] }));
    }
    stage_windivert(root, &input.join("windivert"))?;
    fs::write(
        input.join("manifest.json"),
        serde_json::to_string_pretty(&serde_json::json!({ "tests": manifest }))?,
    )?;
    fs::write(input.join("run.ps1"), RUN_PS1)?;
    if opts.keep_open {
        fs::write(input.join("keep-open"), "")?;
    }
    let config = sandbox::wsb_config(
        &input,
        &output,
        &WsbOptions {
            script: "run.ps1",
            clipboard: false,
            extra_read_only: None,
        },
    );
    sandbox::launch(&base.join("procroute-tests.wsb"), &config)?;
    println!(
        "等待沙盒里的测试结束（最长 {} 分钟）……",
        opts.timeout.as_secs() / 60
    );
    sandbox::wait_for(&output.join("done"), opts.timeout)?;
    report(&output)
}

/// 端到端测试要的文件。`test_json` 是编译测试程序时 cargo 的输出。
///
/// - 回显目标进程放在测试程序旁边（`harness::echo_target_exe`）；
/// - 安装目录 `install`（经 `PROCROUTE_INSTALL_DIR` 告诉测试）：服务程序、锁定版本的 sing-box 与 WinDivert 放在
///   一起，和正式安装一样。服务在另一个包里，cargo 不会为这里的测试编译它，要单独编译。
fn stage_e2e(root: &Path, target_dir: &Path, input: &Path, test_json: &str) -> Result<()> {
    let echo = sandbox::artifact_executable(test_json, "bin", ECHO_TARGET)
        .with_context(|| format!("cargo 没有报告 {ECHO_TARGET} 的可执行文件"))?;
    fs::copy(&echo, input.join(format!("{ECHO_TARGET}.exe")))
        .with_context(|| format!("复制 {}", echo.display()))?;

    let dest = input.join("install");
    stage_windivert(root, &dest)?;
    let svc = sandbox::cargo_build(
        root,
        target_dir,
        &[
            "build",
            "-p",
            SVC_PACKAGE,
            "--features",
            SVC_FEATURES,
            "--bin",
            SVC_PACKAGE,
        ],
        "bin",
        SVC_PACKAGE,
    )?;
    fs::copy(&svc, dest.join(format!("{SVC_PACKAGE}.exe")))
        .with_context(|| format!("复制 {}", svc.display()))?;
    let kernel = root.join("third_party/sing-box/bin").join(KERNEL_FILE_NAME);
    fs::copy(&kernel, dest.join(KERNEL_FILE_NAME)).with_context(|| {
        format!(
            "复制 {}（先运行 `cargo xtask fetch-deps`）",
            kernel.display()
        )
    })?;
    Ok(())
}

fn stage_windivert(root: &Path, dest: &Path) -> Result<()> {
    let src = root.join("third_party/windivert/bin");
    fs::create_dir_all(dest)?;
    for name in WINDIVERT_FILES {
        fs::copy(src.join(name), dest.join(name))
            .with_context(|| format!("复制 {name}（先运行 `cargo xtask fetch-deps`）"))?;
    }
    Ok(())
}

fn report(output: &Path) -> Result<()> {
    let path = output.join("summary.json");
    let summary: Summary = serde_json::from_str(&sandbox::read_text(&path)?)
        .with_context(|| format!("解析 {}", path.display()))?;
    let mut failed = Vec::new();
    for r in &summary.results {
        let ok = r.exit_code == Some(0);
        println!(
            "{} {}（{:.1} 秒）",
            if ok { "通过" } else { "失败" },
            r.name,
            r.seconds
        );
        if !ok {
            failed.push(r.name.as_str());
            print_log(&output.join(format!("{}.log", r.name)));
        }
    }
    if let Some(e) = &summary.error {
        bail!("沙盒里的脚本出错：{e}");
    }
    if !summary.admin {
        bail!("沙盒里的登录命令没有以管理员身份运行，结果不可信");
    }
    if !failed.is_empty() {
        bail!(
            "{} 个测试失败：{}（输出在 {}）",
            failed.len(),
            failed.join("、"),
            output.display()
        );
    }
    println!("全部 {} 个测试通过", summary.results.len());
    Ok(())
}

fn print_log(path: &Path) {
    match fs::read(path) {
        Ok(bytes) => println!(
            "----- {} -----\n{}",
            path.display(),
            String::from_utf8_lossy(&bytes)
        ),
        Err(e) => println!("（读不到 {}：{e}）", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_options() {
        let args: Vec<String> = ["--only", "wfp_vm", "--keep-open", "--timeout-mins", "5"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let o = parse_args(&args).expect("parse");
        assert_eq!(o.only, vec!["wfp_vm".to_owned()]);
        assert!(o.keep_open);
        assert_eq!(o.timeout, Duration::from_secs(300));
        assert!(parse_args(&["--timeout-mins".to_owned(), "0".to_owned()]).is_err());
        assert!(parse_args(&["--bogus".to_owned()]).is_err());
    }

    #[test]
    fn every_suite_name_is_unique() {
        let mut names: Vec<&str> = SUITES.iter().map(|s| s.test).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), SUITES.len());
    }
}
