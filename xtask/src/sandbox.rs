// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows Sandbox 的公共部分，`sandbox-test` 与 `sandbox-dev` 共用。
//!
//! Windows Sandbox 是基于 Hyper-V 的一次性虚拟机，关闭即丢弃全部状态（C-TEST-04 认可的虚拟机）。
//! 沙盒里没有 VC++ 运行库，也没有 Rust / Node 工具链：程序都在开发机上用静态 CRT 编译好，
//! 输出到独立的 `target/sandbox/build`（不影响平时的增量编译），再以只读方式映射进沙盒；
//! 另一个可写的映射目录用来取回结果。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// 沙盒里的映射位置，与 `xtask/sandbox/*.ps1` 一致。
pub const SANDBOX_IN: &str = r"C:\procroute-in";
pub const SANDBOX_OUT: &str = r"C:\procroute-out";

const TARGET: &str = "x86_64-pc-windows-msvc";

/// 沙盒配置里随用途变化的部分。
pub struct WsbOptions<'a> {
    /// 映射进沙盒的脚本名，作为登录命令运行。
    pub script: &'a str,
    /// 剪贴板重定向。只在手动联调时开启（粘贴节点分享链接），测试运行时关闭。
    pub clipboard: bool,
    /// 另一个只读映射：（开发机上的目录，沙盒里的位置）。
    pub extra_read_only: Option<(&'a Path, &'a str)>,
}

/// Windows Sandbox 配置。映射目录、登录命令与（可选的）剪贴板之外全部关闭。
/// 网络开启（默认的 NAT 网络，与开发机隔离）：WFP 测试要区分「被过滤器拒绝」与「没有路由」，联调要连代理服务器。
pub fn wsb_config(input: &Path, output: &Path, opts: &WsbOptions) -> String {
    let clipboard = if opts.clipboard { "Enable" } else { "Disable" };
    let extra = opts
        .extra_read_only
        .map(|(host, sandbox)| {
            format!(
                r#"
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>{}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>"#,
                xml_escape(&host_path(host)),
                xml_escape(sandbox)
            )
        })
        .unwrap_or_default();
    format!(
        r#"<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>{clipboard}</ClipboardRedirection>
  <PrinterRedirection>Disable</PrinterRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>{SANDBOX_IN}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>{SANDBOX_OUT}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>{extra}
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File {SANDBOX_IN}\{}</Command>
  </LogonCommand>
</Configuration>
"#,
        xml_escape(&host_path(input)),
        xml_escape(&host_path(output)),
        xml_escape(opts.script),
    )
}

/// `canonicalize` 在 Windows 上返回 `\\?\` 前缀的路径，Windows Sandbox 不认。
fn host_path(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_owned).unwrap_or(s)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn sandbox_exe() -> Result<PathBuf> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    let exe = Path::new(&root).join(r"System32\WindowsSandbox.exe");
    if !exe.is_file() {
        bail!(
            "找不到 {}：先在「Windows 功能」中启用 Windows 沙盒",
            exe.display()
        );
    }
    Ok(exe)
}

/// 确认 Windows Sandbox 可用且没有在运行（同时只能运行一个）。
pub fn ensure_idle() -> Result<()> {
    sandbox_exe()?;
    let out = Command::new("tasklist.exe")
        .args(["/FO", "CSV", "/NH"])
        .output()
        .context("运行 tasklist")?;
    if String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.starts_with("\"WindowsSandbox"))
    {
        bail!(
            "已有一个 Windows Sandbox 在运行（同时只能运行一个），关闭后重试；\
             客户机关机后客户端窗口偶尔不退出，关掉那个窗口即可"
        );
    }
    Ok(())
}

/// 写出 `.wsb` 并启动沙盒，不等它结束。
///
/// 启动器在沙盒关闭前一直运行。std 在 Windows 上创建子进程时总是继承全部可继承句柄，包括本进程
/// 从调用方继承来的输出管道，调用方（例如把输出接进管道的脚本）就要等沙盒关掉才读到结束；
/// `cmd /C start` 同样继承（实测）。所以经 PowerShell 的 `Start-Process` 启动：它用 ShellExecute
/// 创建进程，不继承句柄，PowerShell 随即退出。路径经环境变量传入，不用拼引号。
pub fn launch(wsb: &Path, config: &str) -> Result<()> {
    fs::write(wsb, config).with_context(|| format!("写入 {}", wsb.display()))?;
    println!("启动 Windows Sandbox：{}", wsb.display());
    let status = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Process -FilePath $env:PROCROUTE_SANDBOX_EXE \
             -ArgumentList ('\"' + $env:PROCROUTE_WSB + '\"')",
        ])
        .env("PROCROUTE_SANDBOX_EXE", sandbox_exe()?)
        .env("PROCROUTE_WSB", wsb)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("启动 WindowsSandbox.exe")?;
    if !status.success() {
        bail!("启动 WindowsSandbox.exe 失败：{status}");
    }
    Ok(())
}

pub fn recreate(dir: &Path) -> Result<()> {
    if dir.exists() {
        fs::remove_dir_all(dir).with_context(|| format!("清空 {}", dir.display()))?;
    }
    fs::create_dir_all(dir).with_context(|| format!("创建 {}", dir.display()))
}

/// 等沙盒写出标记文件。
pub fn wait_for(marker: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while !marker.exists() {
        if Instant::now() >= deadline {
            bail!("超时：沙盒没有写出 {}", marker.display());
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Ok(())
}

/// 读沙盒写出的文本文件。Windows PowerShell 5.1 的 `-Encoding utf8` 会写 BOM。
pub fn read_text(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("读取 {}", path.display()))?;
    Ok(text.trim_start_matches('\u{feff}').to_owned())
}

/// 用静态 CRT 为沙盒编译，返回指定目标（`kind` 为 `bin` 或 `test`）的可执行文件。
///
/// 显式指定目标三元组，使 RUSTFLAGS 不作用于构建脚本与过程宏。
pub fn cargo_build(
    root: &Path,
    target_dir: &Path,
    args: &[&str],
    kind: &str,
    name: &str,
) -> Result<PathBuf> {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let out = Command::new(cargo)
        .current_dir(root)
        .env("CARGO_TARGET_DIR", target_dir)
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .args(args)
        .args([
            "--message-format=json-render-diagnostics",
            "--target",
            TARGET,
        ])
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("运行 cargo {}", args.join(" ")))?;
    if !out.status.success() {
        bail!("编译 {name} 失败");
    }
    artifact_executable(&String::from_utf8_lossy(&out.stdout), kind, name)
        .with_context(|| format!("cargo 没有报告 {name} 的可执行文件"))
}

/// 从 `cargo --message-format=json` 的输出里找出指定目标的可执行文件。
fn artifact_executable(cargo_json: &str, kind: &str, name: &str) -> Option<PathBuf> {
    cargo_json
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == name)
        .filter(|m| {
            m["target"]["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|v| v == kind))
        })
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_executable_of_the_requested_target_kind() {
        let json = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"wfp_vm","kind":["lib"]},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"other","kind":["test"]},"executable":"C:\\o.exe"}"#,
            "\n",
            "not json\n",
            r#"{"reason":"compiler-artifact","target":{"name":"wfp_vm","kind":["test"]},"executable":"C:\\t\\wfp_vm-1.exe"}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"procroute-svc","kind":["bin"]},"executable":"C:\\b\\procroute-svc.exe"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        assert_eq!(
            artifact_executable(json, "test", "wfp_vm"),
            Some(PathBuf::from(r"C:\t\wfp_vm-1.exe"))
        );
        assert_eq!(artifact_executable(json, "test", "divert_vm"), None);
        assert_eq!(
            artifact_executable(json, "bin", "procroute-svc"),
            Some(PathBuf::from(r"C:\b\procroute-svc.exe"))
        );
        assert_eq!(artifact_executable(json, "test", "procroute-svc"), None);
    }

    #[test]
    fn wsb_maps_input_read_only_and_strips_the_verbatim_prefix() {
        let opts = WsbOptions {
            script: "run.ps1",
            clipboard: false,
            extra_read_only: None,
        };
        let wsb = wsb_config(Path::new(r"\\?\E:\a&b\in"), Path::new(r"E:\x\out"), &opts);
        assert!(wsb.contains(r"<HostFolder>E:\a&amp;b\in</HostFolder>"));
        assert!(wsb.contains(
            "<SandboxFolder>C:\\procroute-in</SandboxFolder>\n      <ReadOnly>true</ReadOnly>"
        ));
        assert!(wsb.contains(
            "<SandboxFolder>C:\\procroute-out</SandboxFolder>\n      <ReadOnly>false</ReadOnly>"
        ));
        assert!(wsb.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"));
        assert!(wsb.contains(r"-File C:\procroute-in\run.ps1</Command>"));
        assert_eq!(wsb.matches("<MappedFolder>").count(), 2);
    }

    #[test]
    fn clipboard_and_script_follow_the_options() {
        let runtime = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\156.0.4314.58";
        let opts = WsbOptions {
            script: "dev.ps1",
            clipboard: true,
            extra_read_only: Some((Path::new(runtime), r"C:\procroute-webview2")),
        };
        let wsb = wsb_config(Path::new(r"E:\in"), Path::new(r"E:\out"), &opts);
        assert!(wsb.contains("<ClipboardRedirection>Enable</ClipboardRedirection>"));
        assert!(wsb.contains(r"-File C:\procroute-in\dev.ps1</Command>"));
        assert!(wsb.contains(&format!(
            "<HostFolder>{runtime}</HostFolder>\n      \
             <SandboxFolder>C:\\procroute-webview2</SandboxFolder>\n      \
             <ReadOnly>true</ReadOnly>"
        )));
        assert_eq!(wsb.matches("<MappedFolder>").count(), 3);
    }
}
