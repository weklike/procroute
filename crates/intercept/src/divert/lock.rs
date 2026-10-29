// SPDX-License-Identifier: GPL-3.0-or-later
//! 编译进二进制的 WinDivert 版本锁（C-DRV-01、C-DEP-04）。
//!
//! `third_party/windivert/lock.json` 在编译时嵌入；服务加载 `WinDivert.dll` 与驱动前据此校验安装目录里的
//! 文件，运行时不读取任何可被改写的锁文件。

use serde_json::Value;
use thiserror::Error;

const LOCK_JSON: &str = include_str!("../../../../third_party/windivert/lock.json");

const PLATFORM: &str = "windows-x86_64";

/// 用户态库的文件名。
pub const DLL_FILE_NAME: &str = "WinDivert.dll";
/// 64 位驱动的文件名；`WinDivert.dll` 在自己所在的目录里找它。
pub const DRIVER_FILE_NAME: &str = "WinDivert64.sys";

/// 锁定的版本与两个文件的 SHA-256（小写十六进制）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDriver {
    pub version: String,
    pub dll_sha256: String,
    pub driver_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LockError {
    #[error("嵌入的 WinDivert 锁文件无法解析")]
    Malformed,
    #[error("嵌入的 WinDivert 锁文件缺少 {0}")]
    MissingFile(&'static str),
    #[error("嵌入的 WinDivert 锁文件里 {0} 的 SHA-256 格式不正确")]
    BadDigest(&'static str),
}

pub fn locked_driver() -> Result<LockedDriver, LockError> {
    parse(LOCK_JSON)
}

fn parse(text: &str) -> Result<LockedDriver, LockError> {
    let lock: Value = serde_json::from_str(text).map_err(|_| LockError::Malformed)?;
    let version = lock["version"]
        .as_str()
        .ok_or(LockError::Malformed)?
        .to_owned();
    let files = lock["assets"][PLATFORM]["files"]
        .as_array()
        .ok_or(LockError::Malformed)?;
    let digest = |name: &'static str| -> Result<String, LockError> {
        let sha = files
            .iter()
            .find(|f| f["name"] == name)
            .and_then(|f| f["sha256"].as_str())
            .ok_or(LockError::MissingFile(name))?;
        let ok = sha.len() == 64 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        ok.then(|| sha.to_owned()).ok_or(LockError::BadDigest(name))
    };
    Ok(LockedDriver {
        version,
        dll_sha256: digest(DLL_FILE_NAME)?,
        driver_sha256: digest(DRIVER_FILE_NAME)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_lock_names_both_files() {
        let l = locked_driver().expect("embedded lock");
        assert_eq!(l.version, "2.2.2");
        assert_ne!(l.dll_sha256, l.driver_sha256);
    }

    #[test]
    fn incomplete_locks_are_rejected() {
        assert_eq!(parse("{"), Err(LockError::Malformed));
        let only_dll = r#"{"version":"1","assets":{"windows-x86_64":{"files":[
            {"name":"WinDivert.dll","sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}}}"#;
        assert_eq!(
            parse(only_dll),
            Err(LockError::MissingFile(DRIVER_FILE_NAME))
        );
        let bad = only_dll
            .replace("WinDivert.dll", "WinDivert64.sys")
            .replace(r#"]}}}"#, r#",{"name":"WinDivert.dll","sha256":"ZZ"}]}}}"#);
        assert_eq!(parse(&bad), Err(LockError::BadDigest(DLL_FILE_NAME)));
    }
}
