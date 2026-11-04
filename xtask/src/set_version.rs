// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask set-version <版本或 tag>`：把工作区与前端的版本号改成指定版本。
//!
//! 安装包文件名、界面显示的版本和服务上报的版本都来自这两处。发版工作流在构建前按 tag 运行一次，
//! 所以安装包的版本总是跟随 tag（`v1.2.3`、`v1.2` 分别得到 `1.2.3`、`1.2.0`）。`Cargo.lock` 里的工作区版本
//! 由下一条 cargo 命令自动同步。

use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

pub fn run(args: &[String]) -> Result<()> {
    let [input] = args else {
        bail!("用法：cargo xtask set-version <版本或 tag，例如 v1.2.3>");
    };
    let version = parse_version(input)?;
    let root = crate::workspace_root();
    update(&root.join("Cargo.toml"), |t| {
        set_workspace_version(t, &version)
    })?;
    update(&root.join("app").join("package.json"), |t| {
        set_package_version(t, &version)
    })?;
    println!("版本号已改为 {version}");
    Ok(())
}

fn update(path: &Path, change: impl Fn(&str) -> Result<String>) -> Result<()> {
    let text = fs::read_to_string(path).with_context(|| format!("读取 {}", path.display()))?;
    let changed = change(&text).with_context(|| format!("修改 {}", path.display()))?;
    fs::write(path, changed).with_context(|| format!("写入 {}", path.display()))
}

/// `X.Y.Z` 或 `X.Y`，可带前缀 `v`。安装器要求版本是纯数字，预发布由 GitHub Release 的选项表示。
fn parse_version(input: &str) -> Result<String> {
    let bare = input.strip_prefix('v').unwrap_or(input);
    let parts: Vec<&str> = bare.split('.').collect();
    let number = |p: &&str| {
        !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && (*p == "0" || !p.starts_with('0'))
    };
    if !matches!(parts.len(), 2 | 3) || !parts.iter().all(number) {
        bail!("{input} 不是 vX.Y.Z 或 vX.Y 形式的版本");
    }
    Ok(if parts.len() == 2 {
        format!("{bare}.0")
    } else {
        bare.to_owned()
    })
}

/// 改 `[workspace.package]` 里的 `version`，其余内容原样保留。
fn set_workspace_version(text: &str, version: &str) -> Result<String> {
    let mut section = false;
    let mut done = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if line.starts_with('[') {
            section = line.trim_end() == "[workspace.package]";
        }
        if section && !done && line.starts_with("version") {
            out.push_str(&format!("version = \"{version}\"\n"));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    if !done {
        bail!("[workspace.package] 里没有 version");
    }
    Ok(out)
}

/// 改顶层的 `"version"`（依赖表里的版本是包名作键，不会匹配），其余内容原样保留。
fn set_package_version(text: &str, version: &str) -> Result<String> {
    let mut done = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if !done && line.starts_with("  \"version\":") {
            out.push_str(&format!("  \"version\": \"{version}\",\n"));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    if !done {
        bail!("没有顶层的 version");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 只有 `want` 这一行与原文不同。
    fn only_line_changed(before: &str, after: &str, want: &str) {
        let diff: Vec<&str> = before
            .lines()
            .zip(after.lines())
            .filter(|(a, b)| a != b)
            .map(|(_, b)| b.trim())
            .collect();
        assert_eq!(before.lines().count(), after.lines().count());
        assert_eq!(diff, [want]);
    }

    #[test]
    fn tags_and_bare_versions_are_accepted() {
        assert_eq!(parse_version("v1.2.3").expect("tag"), "1.2.3");
        assert_eq!(parse_version("1.2.3").expect("bare"), "1.2.3");
        assert_eq!(parse_version("v1.0").expect("short tag"), "1.0.0");
        assert_eq!(parse_version("v0.10.0").expect("zero major"), "0.10.0");
    }

    #[test]
    fn anything_the_installer_cannot_use_is_rejected() {
        for bad in [
            "",
            "v",
            "1",
            "v1",
            "1.2.3.4",
            "v1.2.3-rc.1",
            "1..3",
            "01.2.3",
            "latest",
            "v1.2.x",
        ] {
            assert!(parse_version(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_real_workspace_manifest_changes_in_one_line() {
        let before = include_str!("../../Cargo.toml");
        let after = set_workspace_version(before, "9.8.7").expect("set");
        only_line_changed(before, &after, "version = \"9.8.7\"");
        assert!(after.contains("rust-version = "), "other fields stay");
    }

    #[test]
    fn the_real_package_json_changes_in_one_line() {
        let before = include_str!("../../app/package.json");
        let after = set_package_version(before, "9.8.7").expect("set");
        only_line_changed(before, &after, "\"version\": \"9.8.7\",");
        let parsed: serde_json::Value = serde_json::from_str(&after).expect("still JSON");
        assert_eq!(parsed["version"], "9.8.7");
    }

    #[test]
    fn a_manifest_without_a_version_is_an_error() {
        assert!(set_workspace_version("[workspace]\nversion = \"1\"\n", "1.0.0").is_err());
        assert!(set_package_version("{\n  \"name\": \"x\"\n}\n", "1.0.0").is_err());
    }
}
