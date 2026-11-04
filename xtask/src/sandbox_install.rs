// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask sandbox-install [--keep-open] [--timeout-mins <分钟>]`
//!
//! 在 Windows Sandbox 里验证 `cargo xtask bundle` 打出的安装器（T-110，验收「安装 → 卸载后无残留」）。
//! 开发机上不安装、不注册服务、不加载驱动（AGENTS 第 8 节第 5 条；2026-11-04 定由用户自己在本机安装）。
//!
//! 沙盒里由 `xtask/sandbox/install.ps1`：信任本机签名证书（用户在本机做的那一步）→ 静默安装 → 检查文件、签名、
//! 服务（自动启动、LocalSystem、控制管道）→ 启动界面，确认签过名的界面被服务接受（C-SEC-02）→ 静默卸载 →
//! 检查服务、程序文件、进程、WinDivert 驱动、防火墙规则与开机自启项都没有留下（C-NET-06）。
//!
//! 沙盒镜像没有 WebView2、也上不了外网：与 `sandbox-dev` 一样映射开发机的运行时，并登记它的版本，
//! 免得安装器去下载引导程序。

use std::fs;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::sandbox::{self, WsbOptions};

const INSTALL_PS1: &str = include_str!("../sandbox/install.ps1");
const SANDBOX_WEBVIEW2: &str = r"C:\procroute-webview2";

#[derive(Debug, Deserialize)]
struct Report {
    admin: bool,
    #[serde(default)]
    steps: Vec<Step>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Step {
    name: String,
    ok: bool,
    #[serde(default)]
    detail: String,
}

pub fn run(args: &[String]) -> Result<()> {
    let mut keep_open = false;
    let mut timeout = Duration::from_secs(15 * 60);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--keep-open" => keep_open = true,
            "--timeout-mins" => {
                let mins: u64 = match it.next().map(|v| v.parse()) {
                    Some(Ok(m)) if m > 0 => m,
                    _ => bail!("--timeout-mins 需要一个正整数"),
                };
                timeout = Duration::from_secs(mins * 60);
            }
            other => bail!("sandbox-install 不认识参数 {other}"),
        }
    }
    let root = crate::workspace_root();
    let bundle = root.join("target").join("bundle");
    let installer = fs::read_dir(&bundle)
        .with_context(|| format!("读取 {}（先运行 `cargo xtask bundle`）", bundle.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.to_string_lossy().ends_with("-setup.exe"))
        .context("target/bundle 里没有安装器，先运行 `cargo xtask bundle`")?;

    sandbox::ensure_idle()?;
    let base = root.join("target").join("sandbox");
    let input = base.join("install-in");
    let output = base.join("install-out");
    sandbox::recreate(&input)?;
    sandbox::recreate(&output)?;
    let name = installer.file_name().context("安装器没有文件名")?;
    fs::copy(&installer, input.join(name)).context("复制安装器")?;
    let cer = bundle.join(crate::bundle::CERT_FILE);
    fs::copy(&cer, input.join(crate::bundle::CERT_FILE))
        .with_context(|| format!("复制 {}", cer.display()))?;
    fs::write(input.join("install.ps1"), INSTALL_PS1)?;
    if keep_open {
        fs::write(input.join("keep-open"), "")?;
    }
    let webview2 = crate::sandbox_dev::host_webview2();
    let config = sandbox::wsb_config(
        &input,
        &output,
        &WsbOptions {
            script: "install.ps1",
            clipboard: false,
            extra_read_only: webview2.as_deref().map(|d| (d, SANDBOX_WEBVIEW2)),
        },
    );
    println!("验证安装器：{}", installer.display());
    sandbox::launch(&base.join("procroute-install.wsb"), &config)?;
    println!(
        "等待沙盒里的安装、卸载检查结束（最长 {} 分钟）……",
        timeout.as_secs() / 60
    );
    sandbox::wait_for(&output.join("done"), timeout)?;

    let path = output.join("install.json");
    let report: Report = serde_json::from_str(&sandbox::read_text(&path)?)
        .with_context(|| format!("解析 {}", path.display()))?;
    let mut failed = 0;
    for s in &report.steps {
        println!(
            "{} {}{}",
            if s.ok { "通过" } else { "失败" },
            s.name,
            if s.detail.trim().is_empty() {
                String::new()
            } else {
                format!("（{}）", s.detail.trim())
            }
        );
        failed += usize::from(!s.ok);
    }
    if let Some(e) = &report.error {
        bail!("沙盒里的检查脚本出错：{e}（输出在 {}）", output.display());
    }
    if !report.admin {
        bail!("沙盒里的登录命令没有以管理员身份运行，结果不可信");
    }
    if failed > 0 {
        bail!("{failed} 项检查失败（输出在 {}）", output.display());
    }
    println!("全部 {} 项检查通过", report.steps.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_from_powershell_parses() {
        let json = r#"{
    "admin":  true,
    "steps":  [
                  { "name": "service running", "ok": true, "detail": "Running Auto LocalSystem" },
                  { "name": "no firewall rule is left", "ok": false, "detail": "" }
              ],
    "error":  null
}"#;
        let r: Report = serde_json::from_str(json).expect("parse");
        assert!(r.admin);
        assert_eq!(r.steps.len(), 2);
        assert!(r.steps[0].ok && !r.steps[1].ok);
        assert_eq!(r.steps[0].detail, "Running Auto LocalSystem");
    }

    #[test]
    fn the_sandbox_script_keeps_string_literals_ascii() {
        // Windows PowerShell 5.1 按 ANSI 代码页读取没有 BOM 的脚本
        for line in INSTALL_PS1.lines() {
            let code = line.split('#').next().unwrap_or("");
            assert!(code.is_ascii(), "{line}");
        }
    }
}
