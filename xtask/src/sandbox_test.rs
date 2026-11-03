// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask sandbox-test [--only <测试名>]... [--keep-open] [--timeout-mins <分钟>]`
//!
//! 在 Windows Sandbox 里运行只允许在虚拟机中运行的测试（C-TEST-04：加载驱动、改动网络行为、
//! 需要管理员权限的测试）。Windows Sandbox 是基于 Hyper-V 的一次性虚拟机，关闭即丢弃全部状态，
//! 开发机上不会加载驱动，也不会留下 WFP 过滤器或服务。
//!
//! 流程：
//!
//! 1. 在开发机上用静态 CRT 编译各测试程序（只编译、不运行；沙盒里没有 VC++ 运行库），
//!    输出到独立的 `target/sandbox/build`，不影响平时的增量编译；
//! 2. 把测试程序、锁定版本的 WinDivert 文件、`manifest.json` 与 `xtask/sandbox/run.ps1` 放进
//!    `target/sandbox/in`，以只读方式映射进沙盒；`target/sandbox/out` 可写，用来取回结果；
//! 3. 生成 `.wsb` 并启动沙盒，登录命令运行 `run.ps1`：复制到沙盒本地磁盘后逐个运行测试，
//!    写出 `summary.json` 与各测试的输出，然后关机；
//! 4. 开发机等待 `done` 标记，汇总结果；任一测试失败、或沙盒里不是管理员时返回失败。
//!
//! 只在 Windows 上编译（`main.rs` 里按平台分派）。沙盒启用网络（默认的 NAT 网络，与开发机隔离）：WFP 测试要区分「被过滤器拒绝」与「没有路由」。

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};

/// 一个只能在虚拟机里运行的集成测试。
struct Suite {
    package: &'static str,
    features: &'static str,
    /// `tests/<名字>.rs`
    test: &'static str,
}

const SUITES: [Suite; 4] = [
    Suite {
        package: "procroute-platform-win",
        features: "vm-tests",
        test: "wfp_vm",
    },
    Suite {
        package: "procroute-platform-win",
        features: "admin-tests",
        test: "etw_admin",
    },
    Suite {
        package: "procroute-procwatch",
        features: "admin-tests",
        test: "watcher_admin",
    },
    Suite {
        package: "procroute-intercept",
        features: "vm-tests",
        test: "divert_vm",
    },
];

/// 沙盒里的映射位置，与 `run.ps1` 一致。
const SANDBOX_IN: &str = r"C:\procroute-in";
const SANDBOX_OUT: &str = r"C:\procroute-out";

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
    imp::run(&crate::workspace_root(), &suites, &opts)
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

/// Windows Sandbox 配置。映射目录与登录命令之外全部关闭（剪贴板、打印机、音视频输入、vGPU）。
fn wsb_config(input: &Path, output: &Path) -> String {
    format!(
        r#"<Configuration>
  <VGpu>Disable</VGpu>
  <Networking>Enable</Networking>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <ClipboardRedirection>Disable</ClipboardRedirection>
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
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -NoProfile -ExecutionPolicy Bypass -File {SANDBOX_IN}\run.ps1</Command>
  </LogonCommand>
</Configuration>
"#,
        xml_escape(&host_path(input)),
        xml_escape(&host_path(output)),
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

/// 从 `cargo --message-format=json` 的输出里找出指定测试目标的可执行文件。
fn test_executable(cargo_json: &str, test: &str) -> Option<PathBuf> {
    cargo_json
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == test)
        .filter(|m| {
            m["target"]["kind"]
                .as_array()
                .is_some_and(|k| k.iter().any(|v| v == "test"))
        })
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
}

mod imp {
    use std::fs;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    use anyhow::Context;
    use serde::Deserialize;

    use super::*;

    const TARGET: &str = "x86_64-pc-windows-msvc";
    const RUN_PS1: &str = include_str!("../sandbox/run.ps1");
    const WINDIVERT_FILES: [&str; 2] = ["WinDivert.dll", "WinDivert64.sys"];

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

    pub fn run(root: &Path, suites: &[&Suite], opts: &Options) -> Result<()> {
        let launcher = sandbox_exe()?;
        if sandbox_running()? {
            bail!("已有一个 Windows Sandbox 在运行（同时只能运行一个），关闭后重试");
        }
        let base = root.join("target").join("sandbox");
        let input = base.join("in");
        let output = base.join("out");
        recreate(&input)?;
        recreate(&output)?;

        let mut manifest = Vec::new();
        for s in suites {
            let exe = build(root, &base.join("build"), s)?;
            let file = format!("{}.exe", s.test);
            fs::copy(&exe, input.join(&file)).with_context(|| format!("复制 {}", exe.display()))?;
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
        let wsb = base.join("procroute-tests.wsb");
        fs::write(&wsb, wsb_config(&input, &output))?;

        println!("启动 Windows Sandbox：{}", wsb.display());
        Command::new(launcher)
            .arg(&wsb)
            .spawn()
            .context("启动 WindowsSandbox.exe")?;
        wait_for(&output.join("done"), opts.timeout)?;
        report(&output)
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

    fn sandbox_running() -> Result<bool> {
        let out = Command::new("tasklist.exe")
            .args(["/FO", "CSV", "/NH"])
            .output()
            .context("运行 tasklist")?;
        Ok(String::from_utf8_lossy(&out.stdout)
            .lines()
            .any(|l| l.starts_with("\"WindowsSandbox")))
    }

    fn recreate(dir: &Path) -> Result<()> {
        if dir.exists() {
            fs::remove_dir_all(dir).with_context(|| format!("清空 {}", dir.display()))?;
        }
        fs::create_dir_all(dir).with_context(|| format!("创建 {}", dir.display()))
    }

    /// 只编译不运行；静态 CRT，显式指定目标使 RUSTFLAGS 不作用于构建脚本与过程宏。
    fn build(root: &Path, target_dir: &Path, s: &Suite) -> Result<PathBuf> {
        println!(
            "编译 {} 的 {}（--features {}）",
            s.package, s.test, s.features
        );
        let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
        let out = Command::new(cargo)
            .current_dir(root)
            .env("CARGO_TARGET_DIR", target_dir)
            .env("RUSTFLAGS", "-C target-feature=+crt-static")
            .args([
                "test",
                "--no-run",
                "--message-format=json-render-diagnostics",
            ])
            .args([
                "--target",
                TARGET,
                "-p",
                s.package,
                "--features",
                s.features,
            ])
            .args(["--test", s.test])
            .stderr(Stdio::inherit())
            .output()
            .context("运行 cargo test --no-run")?;
        if !out.status.success() {
            bail!("编译 {} 失败", s.test);
        }
        test_executable(&String::from_utf8_lossy(&out.stdout), s.test)
            .with_context(|| format!("cargo 没有报告 {} 的可执行文件", s.test))
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

    fn wait_for(marker: &Path, timeout: Duration) -> Result<()> {
        println!(
            "等待沙盒里的测试结束（最长 {} 分钟）……",
            timeout.as_secs() / 60
        );
        let deadline = Instant::now() + timeout;
        while !marker.exists() {
            if Instant::now() >= deadline {
                bail!("超时：沙盒没有写出 {}", marker.display());
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        Ok(())
    }

    fn report(output: &Path) -> Result<()> {
        let path = output.join("summary.json");
        let text = fs::read_to_string(&path).with_context(|| format!("读取 {}", path.display()))?;
        // Windows PowerShell 5.1 的 `-Encoding utf8` 会写 BOM
        let summary: Summary = serde_json::from_str(text.trim_start_matches('\u{feff}'))
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_the_test_executable_in_cargo_json() {
        let json = concat!(
            r#"{"reason":"compiler-artifact","target":{"name":"wfp_vm","kind":["lib"]},"executable":null}"#,
            "\n",
            r#"{"reason":"compiler-artifact","target":{"name":"other","kind":["test"]},"executable":"C:\\o.exe"}"#,
            "\n",
            "not json\n",
            r#"{"reason":"compiler-artifact","target":{"name":"wfp_vm","kind":["test"]},"executable":"C:\\t\\wfp_vm-1.exe"}"#,
            "\n",
            r#"{"reason":"build-finished","success":true}"#,
        );
        assert_eq!(
            test_executable(json, "wfp_vm"),
            Some(PathBuf::from(r"C:\t\wfp_vm-1.exe"))
        );
        assert_eq!(test_executable(json, "divert_vm"), None);
    }

    #[test]
    fn wsb_maps_input_read_only_and_strips_the_verbatim_prefix() {
        let wsb = wsb_config(Path::new(r"\\?\E:\a&b\in"), Path::new(r"E:\x\out"));
        assert!(wsb.contains(r"<HostFolder>E:\a&amp;b\in</HostFolder>"));
        assert!(wsb.contains(
            "<SandboxFolder>C:\\procroute-in</SandboxFolder>\n      <ReadOnly>true</ReadOnly>"
        ));
        assert!(wsb.contains(
            "<SandboxFolder>C:\\procroute-out</SandboxFolder>\n      <ReadOnly>false</ReadOnly>"
        ));
        assert!(wsb.contains("<ClipboardRedirection>Disable</ClipboardRedirection>"));
    }

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
