// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask fetch-deps`
//!
//! 按 `third_party/sing-box/lock.json` 拉取 sing-box 发布包，校验发布包与取出文件的 SHA256，
//! 放进 `third_party/sing-box/bin/`（C-DEP-04）。任何一步的哈希不一致都直接失败，不留下未校验的文件。
//!
//! 只用系统自带的工具：`curl.exe` 下载、`tar.exe`（bsdtar，可解 zip）解包，哈希用 Windows CNG
//! （`procroute-platform-win::hash`），不为一次性的开发任务引入 HTTP、zip 或哈希库。
//! 锁文件只有 Windows x64 一项（C-DRV-05），所以命令只在 Windows 上可用。
//! WinDivert（T-071）锁定后在这里追加。

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

const LOCK: &str = "third_party/sing-box/lock.json";
const PLATFORM: &str = "windows-x86_64";

/// 锁文件里的 `tag`、`revision`、`license`、`source` 只供人阅读与 NOTICE 对照，这里不读。
#[derive(Debug, Deserialize)]
struct Lock {
    name: String,
    version: String,
    assets: BTreeMap<String, Asset>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Asset {
    url: String,
    sha256: String,
    files: Vec<LockedFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LockedFile {
    /// 发布包内的相对路径。
    archive_path: String,
    /// 取出后在 `bin/` 下的文件名。
    name: String,
    sha256: String,
}

pub fn run() -> Result<()> {
    let root = crate::workspace_root();
    let lock = read_lock(&root.join(LOCK))?;
    let Some(asset) = lock.assets.get(PLATFORM) else {
        bail!("{LOCK} 中没有 {PLATFORM} 的发布包");
    };
    imp::fetch(&root, &lock, asset)
}

fn read_lock(path: &Path) -> Result<Lock> {
    let text = std::fs::read_to_string(path).with_context(|| format!("读取 {}", path.display()))?;
    parse_lock(&text).with_context(|| format!("解析 {}", path.display()))
}

fn parse_lock(text: &str) -> Result<Lock> {
    let lock: Lock = serde_json::from_str(text)?;
    if lock.assets.is_empty() {
        bail!("没有任何发布包");
    }
    for (platform, asset) in &lock.assets {
        if !asset.url.starts_with("https://") {
            bail!("{platform}：发布包地址必须是 https");
        }
        check_sha256(&asset.sha256).with_context(|| format!("{platform} 发布包"))?;
        if asset.files.is_empty() {
            bail!("{platform}：没有列出要取出的文件");
        }
        for f in &asset.files {
            check_sha256(&f.sha256).with_context(|| format!("{platform} 的 {}", f.name))?;
            // 取出的文件名直接拼进 bin/，不允许带路径分隔符或 `..`
            if f.name.is_empty() || f.name.contains(['/', '\\']) || f.name.starts_with('.') {
                bail!("{platform}：非法的文件名 {:?}", f.name);
            }
            if f.archive_path
                .split(['/', '\\'])
                .any(|c| c == ".." || c.is_empty())
            {
                bail!("{platform}：非法的包内路径 {:?}", f.archive_path);
            }
        }
    }
    Ok(lock)
}

fn check_sha256(hex: &str) -> Result<()> {
    if hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        bail!("SHA256 必须是 64 位小写十六进制：{hex:?}")
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub(super) fn fetch(_root: &Path, lock: &Lock, _asset: &Asset) -> Result<()> {
        bail!(
            "{} {} 目前只锁定了 {PLATFORM}，fetch-deps 只能在 Windows 上运行",
            lock.name,
            lock.version
        )
    }
}

#[cfg(windows)]
mod imp {
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    use procroute_platform_win::hash;

    use super::*;

    const BIN_DIR: &str = "third_party/sing-box/bin";

    pub(super) fn fetch(root: &Path, lock: &Lock, asset: &Asset) -> Result<()> {
        let bin = root.join(BIN_DIR);
        if up_to_date(&bin, asset)? {
            println!("{} {} 已是锁定版本，无需下载", lock.name, lock.version);
            return Ok(());
        }

        let work = root
            .join("target")
            .join("xtask")
            .join("fetch-deps")
            .join(format!("{}-{}", lock.name, lock.version));
        if work.exists() {
            fs::remove_dir_all(&work).with_context(|| format!("清理 {}", work.display()))?;
        }
        let staging = work.join("extract");
        fs::create_dir_all(&staging).with_context(|| format!("创建 {}", staging.display()))?;

        let file_name = asset.url.rsplit('/').next().unwrap_or("asset.zip");
        let archive = work.join(file_name);
        println!("下载 {}", asset.url);
        run_tool(
            Command::new(system_tool("curl.exe"))
                .args([
                    "--fail",
                    "--location",
                    "--silent",
                    "--show-error",
                    "--retry",
                    "3",
                ])
                .args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2"])
                .arg("--output")
                .arg(&archive)
                .arg(&asset.url),
        )?;
        verify(&archive, &asset.sha256)?;

        run_tool(
            Command::new(system_tool("tar.exe"))
                .arg("-x")
                .arg("-f")
                .arg(&archive)
                .arg("-C")
                .arg(&staging)
                .args(asset.files.iter().map(|f| f.archive_path.as_str())),
        )?;
        // 先全部校验，再整体放进 bin/：任一文件不符时 bin/ 保持原样
        for f in &asset.files {
            verify(&staging.join(&f.archive_path), &f.sha256)?;
        }
        fs::create_dir_all(&bin).with_context(|| format!("创建 {}", bin.display()))?;
        for f in &asset.files {
            let dest = bin.join(&f.name);
            fs::copy(staging.join(&f.archive_path), &dest)
                .with_context(|| format!("写入 {}", dest.display()))?;
            verify(&dest, &f.sha256)?;
        }
        fs::remove_dir_all(&work).with_context(|| format!("清理 {}", work.display()))?;
        println!(
            "{} {} 已放入 {BIN_DIR}/，哈希校验通过",
            lock.name, lock.version
        );
        Ok(())
    }

    /// `bin/` 下所有文件都存在且哈希一致。
    fn up_to_date(bin: &Path, asset: &Asset) -> Result<bool> {
        for f in &asset.files {
            let path = bin.join(&f.name);
            if !path.is_file() {
                return Ok(false);
            }
            if hash::to_hex(&hash::sha256_file(&path)?) != f.sha256 {
                println!("{} 与锁文件不一致，重新下载", path.display());
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn verify(path: &Path, expected: &str) -> Result<()> {
        let actual = hash::to_hex(
            &hash::sha256_file(path).with_context(|| format!("计算 {} 的哈希", path.display()))?,
        );
        if actual != expected {
            bail!(
                "{} 的 SHA256 不符：期望 {expected}，实际 {actual}",
                path.display()
            );
        }
        Ok(())
    }

    /// `%SystemRoot%\System32` 下的系统工具。不走 PATH，避免拿到 Git Bash 等自带的同名程序
    /// （GNU tar 不能解 zip）。
    fn system_tool(name: &str) -> PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        PathBuf::from(root).join("System32").join(name)
    }

    fn run_tool(cmd: &mut Command) -> Result<()> {
        let program = cmd.get_program().to_string_lossy().into_owned();
        let status = cmd
            .status()
            .with_context(|| format!("无法运行 {program}"))?;
        if !status.success() {
            bail!("{program} 失败：{status}");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_lock_file_is_valid() {
        let lock = read_lock(&crate::workspace_root().join(LOCK)).expect("lock.json");
        assert_eq!(lock.name, "sing-box");
        let asset = lock.assets.get(PLATFORM).expect("windows x64 asset");
        assert!(
            asset.url.contains(&format!("/v{}/", lock.version)),
            "{}",
            asset.url
        );
        assert!(asset.files.iter().any(|f| f.name == "sing-box.exe"));
        assert!(asset.files.iter().any(|f| f.name == "LICENSE"));
    }

    fn lock_with(url: &str, sha: &str, name: &str, archive_path: &str) -> String {
        format!(
            r#"{{"name":"x","version":"1","tag":"v1","revision":"r","license":"l","source":"s",
               "assets":{{"windows-x86_64":{{"url":"{url}","sha256":"{sha}",
               "files":[{{"archive_path":"{archive_path}","name":"{name}","sha256":"{sha}"}}]}}}}}}"#
        )
    }

    const SHA: &str = "99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df";

    #[test]
    fn rejects_bad_entries() {
        assert!(parse_lock(&lock_with("https://e/a.zip", SHA, "a.exe", "d/a.exe")).is_ok());
        // 非 https
        assert!(parse_lock(&lock_with("http://e/a.zip", SHA, "a.exe", "d/a.exe")).is_err());
        // 大写或长度不对的哈希
        assert!(
            parse_lock(&lock_with(
                "https://e/a.zip",
                &SHA.to_uppercase(),
                "a.exe",
                "d/a.exe"
            ))
            .is_err()
        );
        assert!(parse_lock(&lock_with("https://e/a.zip", &SHA[1..], "a.exe", "d/a.exe")).is_err());
        // 目标文件名带路径，或包内路径越界
        assert!(parse_lock(&lock_with("https://e/a.zip", SHA, "../a.exe", "d/a.exe")).is_err());
        assert!(parse_lock(&lock_with("https://e/a.zip", SHA, r"x\\a.exe", "d/a.exe")).is_err());
        assert!(parse_lock(&lock_with("https://e/a.zip", SHA, "a.exe", "d/../../a.exe")).is_err());
        // 文件条目里拼错的字段不会被静默忽略
        assert!(
            parse_lock(
                &lock_with("https://e/a.zip", SHA, "a.exe", "d/a.exe").replacen(
                    "\"archive_path\"",
                    "\"archive\"",
                    1
                )
            )
            .is_err()
        );
    }
}
