// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask bundle`：打包 Windows 安装器（T-110；一次性证书见 docs/adr/0002）。
//!
//! 1. 这次打包专用的一次性代码签名证书：在当前用户的证书库里新建（私钥不可导出），打包结束后连同私钥删除；
//! 2. 用静态 CRT 编译 release 版服务（不含 `insecure-skip-client-auth`，客户端校验照常，C-SEC-02），签名后与锁定
//!    版本的 sing-box、WinDivert（都不签名：它们按 SHA-256 锁定，C-DRV-01、C-DEP-04）及许可证放进
//!    `target/bundle-stage`；
//! 3. `tauri build --bundles nsis`：界面同样静态 CRT 的 release 构建；打包器要签的每个二进制（界面、NSIS 插件、
//!    卸载器、安装器、资源里的可执行文件）都交给 `xtask/bundle/sign.ps1`，签名策略全在那里：锁定的第三方二进制
//!    跳过，其余用同一张证书签名。打包器在自定义签名命令之外只用 signtool 判断「是否已签名」；本机没有 Windows SDK，
//!    `TAURI_WINDOWS_SIGNTOOL_PATH` 指向 `xtask/bundle/signtool-verify.cmd`，它一律回答「未签名」。安装器钩子
//!    `app/src-tauri/windows/hooks.nsh` 注册与卸载服务；
//! 4. 安装器与 `SHA256SUMS.txt` 放进 `target/bundle`（发版时由 `.github/workflows/release.yml` 上传）。
//!
//! 服务只要求界面与自己用同一张证书签名，不要求证书受信任，所以用户不需要改动证书信任，私钥也不需要留存。
//! 静态 CRT：安装的机器上不需要 VC++ 运行库。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use procroute_platform_win::hash;

use crate::sandbox;

/// 一次性证书的主题。服务比对的是证书本身（C-SEC-02），主题只在文件属性里给人看。
const CERT_SUBJECT: &str = "CN=ProcRoute Build";
/// 没有时间戳，证书过期后签名就失效、服务会拒绝界面，所以有效期要远长于一个版本的寿命。
/// 私钥打包后就删除，长有效期没有额外风险。
const CERT_YEARS: u32 = 20;
const SUMS_FILE: &str = "SHA256SUMS.txt";
const SIGN_PS1: &str = include_str!("../bundle/sign.ps1");
const SIGNTOOL_SHIM: &str = include_str!("../bundle/signtool-verify.cmd");
const TARGET: &str = "x86_64-pc-windows-msvc";

/// 安装目录里与界面放在一起的文件：（来源，安装后的文件名）。
fn staged_files(root: &Path) -> Vec<(PathBuf, &'static str)> {
    vec![
        (
            root.join("third_party/sing-box/bin/sing-box.exe"),
            "sing-box.exe",
        ),
        (
            root.join("third_party/windivert/bin/WinDivert.dll"),
            "WinDivert.dll",
        ),
        (
            root.join("third_party/windivert/bin/WinDivert64.sys"),
            "WinDivert64.sys",
        ),
        (root.join("LICENSE"), "licenses/LICENSE"),
        (root.join("NOTICE"), "licenses/NOTICE"),
        (
            root.join("third_party/sing-box/bin/LICENSE"),
            "licenses/sing-box-LICENSE",
        ),
        (
            root.join("third_party/windivert/bin/LICENSE"),
            "licenses/WinDivert-LICENSE",
        ),
    ]
}

pub fn run(args: &[String]) -> Result<()> {
    if let Some(a) = args.first() {
        bail!("bundle 不认识参数 {a}");
    }
    let root = crate::workspace_root();
    let out = root.join("target").join("bundle");
    let stage = root.join("target").join("bundle-stage");
    let build = root.join("target").join("bundle-build");
    sandbox::recreate(&stage)?;
    // 清掉旧产物：发版工作流会上传这个目录里的全部文件，沙盒验证也从这里找安装器
    sandbox::recreate(&out)?;

    let cert = BuildCert::create()?;
    let thumbprint = cert.thumbprint.as_str();
    println!("一次性代码签名证书（{CERT_SUBJECT}）：指纹 {thumbprint}");
    let sign_ps1 = stage.join("sign.ps1");
    fs::write(&sign_ps1, SIGN_PS1)?;
    let signtool_shim = stage.join("signtool-verify.cmd");
    fs::write(&signtool_shim, SIGNTOOL_SHIM)?;

    println!("编译 procroute-svc（release，静态 CRT）");
    let svc = sandbox::cargo_build(
        &root,
        &build,
        &["build", "--release", "-p", "procroute-svc"],
        "bin",
        "procroute-svc",
    )?;
    let staged_svc = stage.join("procroute-svc.exe");
    fs::copy(&svc, &staged_svc).with_context(|| format!("复制 {}", svc.display()))?;
    sign(&sign_ps1, &staged_svc, thumbprint)?;
    for (src, name) in staged_files(&root) {
        let dest = staged(&stage, name);
        if let Some(dir) = dest.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::copy(&src, &dest).with_context(|| {
            format!(
                "复制 {}（第三方二进制先运行 `cargo xtask fetch-deps`）",
                src.display()
            )
        })?;
    }

    let config = stage.join("tauri.bundle.conf.json");
    fs::write(
        &config,
        serde_json::to_string_pretty(&bundle_config(&root, &stage, &sign_ps1))?,
    )?;
    // 打包器不清理输出目录，换了版本号后旧的安装器还留在里面，不能被当成这次的产物
    let nsis = build.join(TARGET).join("release/bundle/nsis");
    sandbox::recreate(&nsis)?;
    println!("打包界面与安装器（tauri build --bundles nsis）");
    let status = Command::new("cmd")
        .args(["/C", "pnpm", "exec", "tauri", "build", "--bundles", "nsis"])
        .arg("--target")
        .arg(TARGET)
        .arg("--config")
        .arg(&config)
        .current_dir(root.join("app"))
        .env("CARGO_TARGET_DIR", &build)
        .env("RUSTFLAGS", "-C target-feature=+crt-static")
        .env("PROCROUTE_SIGN_THUMBPRINT", thumbprint)
        .env("TAURI_WINDOWS_SIGNTOOL_PATH", &signtool_shim)
        .status()
        .context("运行 tauri build")?;
    if !status.success() {
        bail!("tauri build 失败");
    }

    let installer = fs::read_dir(&nsis)
        .with_context(|| format!("读取 {}", nsis.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .find(|p| p.extension().is_some_and(|e| e == "exe"))
        .with_context(|| format!("{} 里没有安装器", nsis.display()))?;
    let name = installer
        .file_name()
        .context("安装器没有文件名")?
        .to_owned();
    let delivered = out.join(&name);
    fs::copy(&installer, &delivered).context("复制安装器")?;
    let digest = hash::sha256_file(&delivered)
        .with_context(|| format!("计算 {} 的哈希", delivered.display()))?;
    fs::write(
        out.join(SUMS_FILE),
        sums_line(&hash::to_hex(&digest), &name.to_string_lossy()),
    )?;
    println!(
        "\n完成：{}\n\n用一次性证书签名，安装前不需要信任任何证书；Windows 会提示未知发布者。",
        delivered.display()
    );
    Ok(())
}

/// `sha256sum -c` 能读的一行。
fn sums_line(hex: &str, name: &str) -> String {
    format!("{hex}  {name}\n")
}

/// 合并进 `tauri.conf.json` 的打包配置（路径都写绝对路径）。
fn bundle_config(root: &Path, stage: &Path, sign_ps1: &Path) -> serde_json::Value {
    let mut resources = serde_json::Map::new();
    resources.insert(
        path_str(&stage.join("procroute-svc.exe")),
        "procroute-svc.exe".into(),
    );
    for (_, name) in staged_files(root) {
        resources.insert(path_str(&staged(stage, name)), name.into());
    }
    serde_json::json!({
        "bundle": {
            "active": true,
            "targets": ["nsis"],
            "publisher": "ProcRoute",
            "resources": resources,
            "windows": {
                "signCommand": {
                    "cmd": "pwsh",
                    "args": ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                             "-File", path_str(sign_ps1), "%1"],
                },
                "webviewInstallMode": { "type": "downloadBootstrapper" },
                "nsis": {
                    "installMode": "perMachine",
                    "installerHooks": path_str(&root.join("app/src-tauri/windows/hooks.nsh")),
                },
            },
        },
    })
}

/// 暂存目录里的文件（`name` 用 `/` 分隔子目录）。
fn staged(stage: &Path, name: &str) -> PathBuf {
    name.split('/')
        .fold(stage.to_path_buf(), |p, part| p.join(part))
}

fn path_str(p: &Path) -> String {
    let s = p.display().to_string();
    s.strip_prefix(r"\\?\").map(str::to_owned).unwrap_or(s)
}

/// 这次打包专用的代码签名证书，离开作用域时连同私钥从证书库删除（打包失败时也一样）。
struct BuildCert {
    thumbprint: String,
}

impl BuildCert {
    fn create() -> Result<Self> {
        // 先清掉上次被强行中断时留下的（只清这个主题）
        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             $subject = '{CERT_SUBJECT}'; \
             Get-ChildItem Cert:\\CurrentUser\\My | Where-Object {{ $_.Subject -eq $subject }} | \
               ForEach-Object {{ Remove-Item -Path \"Cert:\\CurrentUser\\My\\$($_.Thumbprint)\" -DeleteKey }}; \
             $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject $subject \
               -CertStoreLocation Cert:\\CurrentUser\\My -KeyExportPolicy NonExportable \
               -KeyAlgorithm RSA -KeyLength 3072 -HashAlgorithm SHA256 \
               -NotAfter (Get-Date).AddYears({CERT_YEARS}); \
             $cert.Thumbprint"
        );
        let out = pwsh()
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .stderr(Stdio::inherit())
            .output()
            .context("运行 PowerShell 新建签名证书")?;
        if !out.status.success() {
            bail!("新建签名证书失败");
        }
        let thumbprint = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        if thumbprint.len() != 40 || !thumbprint.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("PowerShell 没有给出证书指纹：{thumbprint:?}");
        }
        Ok(Self { thumbprint })
    }
}

impl Drop for BuildCert {
    fn drop(&mut self) {
        let removed = pwsh()
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference = 'Stop'; \
                 Remove-Item -Path \"Cert:\\CurrentUser\\My\\$env:PROCROUTE_SIGN_THUMBPRINT\" -DeleteKey",
            ])
            .env("PROCROUTE_SIGN_THUMBPRINT", &self.thumbprint)
            .status();
        if !removed.is_ok_and(|s| s.success()) {
            eprintln!(
                "警告：没能删除一次性证书 {}，下次打包时会再次清理",
                self.thumbprint
            );
        }
    }
}

fn sign(sign_ps1: &Path, file: &Path, thumbprint: &str) -> Result<()> {
    let status = pwsh()
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(sign_ps1)
        .arg(file)
        .env("PROCROUTE_SIGN_THUMBPRINT", thumbprint)
        .status()
        .context("运行签名脚本")?;
    if !status.success() {
        bail!("签名 {} 失败", file.display());
    }
    Ok(())
}

/// PowerShell 7（`pwsh`）。Windows PowerShell 5.1 在混用环境里可能加载不到 PKI 与签名模块，所以要求 7。
fn pwsh() -> Command {
    Command::new("pwsh")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bundle_config_places_the_service_next_to_the_ui_and_signs_with_the_script() {
        let root = Path::new(r"E:\repo");
        let stage = Path::new(r"\\?\E:\repo\target\bundle-stage");
        let c = bundle_config(root, stage, &stage.join("sign.ps1"));
        let resources = c["bundle"]["resources"].as_object().expect("resources");
        assert_eq!(
            resources[r"E:\repo\target\bundle-stage\procroute-svc.exe"],
            "procroute-svc.exe"
        );
        assert_eq!(
            resources[r"E:\repo\target\bundle-stage\WinDivert64.sys"],
            "WinDivert64.sys"
        );
        assert_eq!(
            resources[r"E:\repo\target\bundle-stage\licenses\sing-box-LICENSE"],
            "licenses/sing-box-LICENSE"
        );
        let sign = &c["bundle"]["windows"]["signCommand"];
        assert_eq!(sign["cmd"], "pwsh");
        let args: Vec<&str> = sign["args"]
            .as_array()
            .expect("args")
            .iter()
            .filter_map(|a| a.as_str())
            .collect();
        assert_eq!(args.last(), Some(&"%1"));
        assert!(args.contains(&r"E:\repo\target\bundle-stage\sign.ps1"));
        assert_eq!(c["bundle"]["windows"]["nsis"]["installMode"], "perMachine");
    }

    #[test]
    fn the_checksum_file_uses_the_sha256sum_format() {
        assert_eq!(sums_line("ab12", "x-setup.exe"), "ab12  x-setup.exe\n");
    }
}
