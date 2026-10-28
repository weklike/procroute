// SPDX-License-Identifier: GPL-3.0-or-later
//! `cargo xtask gen-types [--check]`
//!
//! 从 `crates/proto` 生成 `app/src/api/generated.ts`（C-ARCH-04）。
//! `--check` 只比较不写入，供 CI 判断生成文件是否过期。

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};

const TARGET: &str = "app/src/api/generated.ts";

pub fn run(check: bool) -> Result<()> {
    let path = crate::workspace_root().join(TARGET);
    let content = procroute_proto::ts::typescript_bindings();
    let existing = read_if_exists(&path)?;

    if check {
        if existing.as_deref() == Some(content.as_str()) {
            println!("{TARGET} 是最新的");
            return Ok(());
        }
        bail!("{TARGET} 已过期或不存在，请运行 `cargo xtask gen-types` 并提交结果");
    }

    if existing.as_deref() == Some(content.as_str()) {
        println!("{TARGET} 无变化");
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("创建目录 {}", dir.display()))?;
    }
    fs::write(&path, content).with_context(|| format!("写入 {}", path.display()))?;
    println!("已生成 {TARGET}");
    Ok(())
}

fn read_if_exists(path: &PathBuf) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("读取 {}", path.display())),
    }
}
