// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask sandbox-dev [--timeout-mins <分钟>]`
//!
//! 在 Windows Sandbox 里运行真实的服务与界面，供手动联调（AGENTS 第 3.2 节「完整联调」的沙盒版）。
//! 开发机上不启动服务、不加载驱动、不改路由与 DNS（AGENTS 第 8 节第 5 条）；关闭沙盒即丢弃全部状态。
//!
//! 流程：
//!
//! 1. 前端生产构建（`pnpm build`）：真实的 IPC 客户端，不含模拟服务；
//! 2. 用静态 CRT 编译服务与界面（见 [`crate::sandbox`]）：
//!    - 服务是调试构建并开启 `insecure-skip-client-auth`：未签名的开发构建过不了客户端签名校验，
//!      C-SEC-02 只允许调试构建这样做；
//!    - 界面开启 `tauri/custom-protocol`，与 `tauri build` 一样嵌入生产前端；
//! 3. 连同锁定版本的 sing-box 放进 `target/sandbox/dev-in/install`，以只读方式映射进沙盒；
//! 4. 登录命令运行 `xtask/sandbox/dev.ps1`：装到 `C:\Program Files\ProcRoute`，在一个可见的控制台窗口里
//!    运行 `procroute-svc --console`（日志同时写到 `target/sandbox/dev-out/svc.log`），控制管道出现后
//!    启动界面（输出写到 `ui.log`），写出 `status.json`；
//! 5. 开发机读到 `status.json` 后报告结果并返回，沙盒保持打开，关掉沙盒窗口即结束。
//!
//! 沙盒的系统镜像不带界面需要的 WebView2 运行时，沙盒里也不一定能上网（开发机经本地代理上网时，
//! 沙盒的 NAT 不走那个代理）。所以把开发机上已安装的运行时（版本目录）只读映射进沙盒，由 `dev.ps1`
//! 当作固定版本运行时使用，不需要下载。
//!
//! 沙盒开启剪贴板重定向，便于粘贴节点分享链接；`sandbox-test` 仍关闭。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::sandbox::{self, WsbOptions};

const DEV_PS1: &str = include_str!("../sandbox/dev.ps1");
const SVC_CONSOLE_PS1: &str = include_str!("../sandbox/svc-console.ps1");
const KERNEL_FILE_NAME: &str = "sing-box.exe";
/// 开发机上的 WebView2 运行时在沙盒里的映射位置，与 `dev.ps1` 一致。
const SANDBOX_WEBVIEW2: &str = r"C:\procroute-webview2";

#[derive(Debug, Deserialize)]
struct Status {
    admin: bool,
    webview2: Option<String>,
    service: bool,
    ui: bool,
    error: Option<String>,
}

pub fn run(args: &[String]) -> Result<()> {
    let timeout = parse_args(args)?;
    let root = crate::workspace_root();
    sandbox::ensure_idle()?;
    let base = root.join("target").join("sandbox");
    let input = base.join("dev-in");
    let output = base.join("dev-out");
    sandbox::recreate(&input)?;
    sandbox::recreate(&output)?;

    let install = input.join("install");
    fs::create_dir_all(&install)?;
    stage_binaries(&root, &base.join("build"), &install)?;
    fs::write(input.join("dev.ps1"), DEV_PS1)?;
    fs::write(input.join("svc-console.ps1"), SVC_CONSOLE_PS1)?;

    let webview2 = host_webview2();
    match &webview2 {
        Some(dir) => println!("映射开发机上的 WebView2 运行时：{}", dir.display()),
        None => println!("警告：开发机上没有找到 WebView2 运行时，沙盒里的界面多半无法启动"),
    }
    let config = sandbox::wsb_config(
        &input,
        &output,
        &WsbOptions {
            script: "dev.ps1",
            clipboard: true,
            extra_read_only: webview2.as_deref().map(|dir| (dir, SANDBOX_WEBVIEW2)),
        },
    );
    sandbox::launch(&base.join("procroute-dev.wsb"), &config)?;
    println!(
        "等待沙盒里的服务与界面启动（最长 {} 分钟）……",
        timeout.as_secs() / 60
    );
    sandbox::wait_for(&output.join("ready"), timeout)?;
    report(&output)
}

/// 开发机上系统级安装的 WebView2 运行时的版本目录，有多个时取版本号最大的。
pub(crate) fn host_webview2() -> Option<PathBuf> {
    let base = PathBuf::from(std::env::var_os("ProgramFiles(x86)")?)
        .join(r"Microsoft\EdgeWebView\Application");
    fs::read_dir(base)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("msedgewebview2.exe").is_file())
        .filter_map(|e| Some((parse_version(e.file_name().to_str()?)?, e.path())))
        .max_by_key(|(version, _)| *version)
        .map(|(_, path)| path)
}

/// `156.0.4314.58` → `[156, 0, 4314, 58]`；不是四段数字时返回 `None`。
fn parse_version(s: &str) -> Option<[u32; 4]> {
    let mut parts = s.split('.').map(str::parse::<u32>);
    let v = [
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
        parts.next()?.ok()?,
    ];
    parts.next().is_none().then_some(v)
}

fn parse_args(args: &[String]) -> Result<Duration> {
    let mut timeout = Duration::from_secs(10 * 60);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--timeout-mins" => {
                let mins: u64 = match it.next().map(|v| v.parse()) {
                    Some(Ok(m)) if m > 0 => m,
                    _ => bail!("--timeout-mins 需要一个正整数"),
                };
                timeout = Duration::from_secs(mins * 60);
            }
            other => bail!("sandbox-dev 不认识参数 {other}"),
        }
    }
    Ok(timeout)
}

/// 编译服务与界面，连同锁定版本的 sing-box 放进安装目录。
fn stage_binaries(root: &Path, target_dir: &Path, install: &Path) -> Result<()> {
    println!("前端生产构建（pnpm build）");
    // pnpm 在 Windows 上是 .cmd 脚本，经 cmd 运行；参数固定
    let status = Command::new("cmd")
        .args(["/C", "pnpm", "build"])
        .current_dir(root.join("app"))
        .status()
        .context("运行 pnpm build")?;
    if !status.success() {
        bail!("pnpm build 失败");
    }

    println!("编译 procroute-svc（调试构建，--features insecure-skip-client-auth）");
    let svc = sandbox::cargo_build(
        root,
        target_dir,
        &[
            "build",
            "-p",
            "procroute-svc",
            "--features",
            "insecure-skip-client-auth",
        ],
        "bin",
        "procroute-svc",
    )?;
    println!("编译 procroute-ui（--features tauri/custom-protocol）");
    let ui = sandbox::cargo_build(
        root,
        target_dir,
        &[
            "build",
            "-p",
            "procroute-ui",
            "--features",
            "tauri/custom-protocol",
        ],
        "bin",
        "procroute-ui",
    )?;

    for (src, name) in [
        (svc, "procroute-svc.exe"),
        (ui, "procroute-ui.exe"),
        (
            root.join("third_party/sing-box/bin").join(KERNEL_FILE_NAME),
            KERNEL_FILE_NAME,
        ),
    ] {
        fs::copy(&src, install.join(name)).with_context(|| {
            format!(
                "复制 {}（sing-box 先运行 `cargo xtask fetch-deps`）",
                src.display()
            )
        })?;
    }
    Ok(())
}

fn report(output: &Path) -> Result<()> {
    let path = output.join("status.json");
    let status: Status = serde_json::from_str(&sandbox::read_text(&path)?)
        .with_context(|| format!("解析 {}", path.display()))?;
    let svc_log = output.join("svc.log");
    println!(
        "沙盒：管理员 {}，WebView2 {}，服务 {}，界面 {}",
        yes_no(status.admin),
        status.webview2.as_deref().unwrap_or("未找到"),
        yes_no(status.service),
        yes_no(status.ui)
    );
    if let Some(e) = &status.error {
        print_tail(&svc_log);
        if status.service {
            print_tail(&output.join("ui.log"));
        }
        bail!("沙盒里的启动脚本出错：{e}");
    }
    if !status.admin {
        bail!("沙盒里的登录命令没有以管理员身份运行，服务无法以控制台模式启动");
    }
    println!(
        "已就绪：服务在沙盒的控制台窗口里运行（Ctrl+C 停止），界面已打开。\n\
         服务日志同时写在 {}。关闭沙盒窗口即结束，沙盒里的全部状态随之丢弃。",
        svc_log.display()
    );
    Ok(())
}

fn yes_no(b: bool) -> &'static str {
    if b { "是" } else { "否" }
}

/// 打印日志的最后几十行，帮助判断启动失败的原因。
fn print_tail(path: &Path) {
    match sandbox::read_text(path) {
        Ok(text) => {
            let lines: Vec<&str> = text.lines().collect();
            let start = lines.len().saturating_sub(40);
            println!("----- {} -----", path.display());
            for l in &lines[start..] {
                println!("{l}");
            }
        }
        Err(e) => println!("（读不到服务日志：{e:#}）"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_timeout() {
        assert_eq!(parse_args(&[]).expect("default"), Duration::from_secs(600));
        let args = ["--timeout-mins".to_owned(), "3".to_owned()];
        assert_eq!(parse_args(&args).expect("3"), Duration::from_secs(180));
        assert!(parse_args(&["--timeout-mins".to_owned()]).is_err());
        assert!(parse_args(&["--keep-open".to_owned()]).is_err());
    }

    #[test]
    fn webview2_versions_compare_numerically() {
        assert_eq!(parse_version("156.0.4314.58"), Some([156, 0, 4314, 58]));
        assert!(parse_version("156.0.4314.58") > parse_version("156.0.4314.9"));
        assert_eq!(parse_version("SetupMetrics"), None);
        assert_eq!(parse_version("156.0.4314"), None);
        assert_eq!(parse_version("156.0.4314.58.1"), None);
    }

    #[test]
    fn status_json_from_powershell_parses() {
        let json = r#"{
    "admin":  true,
    "webview2":  "131.0.2903.70",
    "service":  true,
    "ui":  true,
    "error":  null
}"#;
        let s: Status = serde_json::from_str(json).expect("parse");
        assert!(s.admin && s.service && s.ui);
        assert_eq!(s.webview2.as_deref(), Some("131.0.2903.70"));
        assert!(s.error.is_none());
    }
}
