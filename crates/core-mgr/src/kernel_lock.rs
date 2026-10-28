// SPDX-License-Identifier: GPL-3.0-or-later
//! 编译进二进制的 sing-box 版本锁（C-DEP-04、C-SEC-06）。
//!
//! `third_party/sing-box/lock.json` 在编译时嵌入，服务据此校验安装目录里的 `sing-box.exe`，
//! 运行时不读取任何可被改写的锁文件。升级 sing-box 时锁文件改变，重新编译即生效。

use serde_json::Value;
use thiserror::Error;

/// 锁文件原文。
const LOCK_JSON: &str = include_str!("../../../third_party/sing-box/lock.json");

/// 本平台在锁文件里的键（支持矩阵见 C-DRV-05）。
const PLATFORM: &str = "windows-x86_64";

/// 内核可执行文件名，与安装目录里的文件名一致。
pub const KERNEL_FILE_NAME: &str = "sing-box.exe";

/// 锁定的内核版本与可执行文件哈希。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedKernel {
    pub version: String,
    /// 小写十六进制的 SHA-256。
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LockError {
    #[error("嵌入的 sing-box 锁文件无法解析")]
    Malformed,
    #[error("嵌入的 sing-box 锁文件没有 {PLATFORM} 的 {KERNEL_FILE_NAME}")]
    MissingKernel,
    #[error("嵌入的 sing-box 锁文件里的 SHA-256 格式不正确")]
    BadDigest,
}

/// 读取嵌入的锁文件。
pub fn locked_kernel() -> Result<LockedKernel, LockError> {
    parse(LOCK_JSON)
}

fn parse(text: &str) -> Result<LockedKernel, LockError> {
    let lock: Value = serde_json::from_str(text).map_err(|_| LockError::Malformed)?;
    let version = lock["version"]
        .as_str()
        .ok_or(LockError::Malformed)?
        .to_owned();
    let sha256 = lock["assets"][PLATFORM]["files"]
        .as_array()
        .ok_or(LockError::MissingKernel)?
        .iter()
        .find(|f| f["name"] == KERNEL_FILE_NAME)
        .and_then(|f| f["sha256"].as_str())
        .ok_or(LockError::MissingKernel)?;
    let well_formed = sha256.len() == 64
        && sha256
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !well_formed {
        return Err(LockError::BadDigest);
    }
    Ok(LockedKernel {
        version,
        sha256: sha256.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_lock_names_a_well_formed_kernel_digest() {
        let k = locked_kernel().expect("embedded lock");
        assert_eq!(k.sha256.len(), 64);
        assert!(!k.version.is_empty());
    }

    #[test]
    fn rejects_locks_without_the_kernel_or_with_bad_digests() {
        assert_eq!(parse("not json"), Err(LockError::Malformed));
        assert_eq!(
            parse(r#"{"version":"1","assets":{}}"#),
            Err(LockError::MissingKernel)
        );
        let other_file = r#"{"version":"1","assets":{"windows-x86_64":{"files":[
            {"name":"LICENSE","sha256":"00"}]}}}"#;
        assert_eq!(parse(other_file), Err(LockError::MissingKernel));
        let upper = format!(
            r#"{{"version":"1","assets":{{"windows-x86_64":{{"files":[
            {{"name":"sing-box.exe","sha256":"{}"}}]}}}}}}"#,
            "A".repeat(64)
        );
        assert_eq!(parse(&upper), Err(LockError::BadDigest));
        let ok = upper.replace(&"A".repeat(64), &"a".repeat(64));
        assert_eq!(parse(&ok).expect("valid").sha256, "a".repeat(64));
    }
}
