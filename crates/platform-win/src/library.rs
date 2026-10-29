// SPDX-License-Identifier: GPL-3.0-or-later
//! 按哈希校验后锁定的文件，以及按完整路径加载的已校验 DLL。
//!
//! 第三方二进制只能使用锁文件里的版本（C-DRV-01、C-DEP-04）。[`LockedFile`] 以「只允许他人读」的共享方式
//! 打开文件并校验 SHA-256：持有期间文件无法被写入、删除或替换，所以「校验」与「使用」之间没有替换窗口；
//! 驱动加载期间一直持有它，也就满足了「加载期间禁止删除或替换 `.sys`」（C-DRV-02）。
//!
//! [`VerifiedLibrary`] 只按完整路径加载 DLL，依赖只在 DLL 所在目录与 System32 里查找，
//! 不会被当前目录或 PATH 里的同名文件劫持。
#![allow(unsafe_code)] // 需要调用 LoadLibraryExW / GetProcAddress / FreeLibrary；每处都有 SAFETY 注释

use std::ffi::{CStr, c_void};
use std::fs::File;
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
};

use crate::hash::{HashError, sha256_reader, to_hex};
use crate::wide::to_wide;

/// 只允许他人读。
const FILE_SHARE_READ: u32 = 0x0000_0001;

#[derive(Debug, thiserror::Error)]
pub enum LibraryError {
    #[error("cannot open {path}: {source}")]
    Open { path: PathBuf, source: io::Error },
    #[error("cannot hash {path}: {source}")]
    Hash { path: PathBuf, source: HashError },
    #[error("{path} does not match the locked SHA-256")]
    HashMismatch { path: PathBuf },
    #[error("cannot load {path}: {source}")]
    Load { path: PathBuf, source: io::Error },
}

/// 已按哈希校验、在持有期间不能被改动的文件。
#[derive(Debug)]
pub struct LockedFile {
    path: PathBuf,
    _file: File,
}

impl LockedFile {
    /// 打开并校验 `path`。`expected_sha256` 是小写十六进制。
    pub fn open(path: &Path, expected_sha256: &str) -> Result<Self, LibraryError> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|source| LibraryError::Open {
                path: path.to_owned(),
                source,
            })?;
        let digest = sha256_reader(&mut file).map_err(|source| LibraryError::Hash {
            path: path.to_owned(),
            source,
        })?;
        if to_hex(&digest) != expected_sha256 {
            return Err(LibraryError::HashMismatch {
                path: path.to_owned(),
            });
        }
        Ok(Self {
            path: path.to_owned(),
            _file: file,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 按完整路径加载、加载前校验过哈希的 DLL。丢弃时卸载。
#[derive(Debug)]
pub struct VerifiedLibrary {
    module: HMODULE,
    // 声明顺序即析构顺序：先卸载模块，再放开文件
    _file: LockedFile,
}

// SAFETY: HMODULE 只是模块基址，可以在线程间传递；本类型不提供可变状态，
// 卸载只在 Drop 里发生一次。
unsafe impl Send for VerifiedLibrary {}
// SAFETY: 同上；GetProcAddress 是线程安全的。
unsafe impl Sync for VerifiedLibrary {}

impl VerifiedLibrary {
    /// 校验 `path` 的 SHA-256 后加载。`path` 必须是完整路径。
    pub fn load(path: &Path, expected_sha256: &str) -> Result<Self, LibraryError> {
        if !path.is_absolute() {
            return Err(LibraryError::Load {
                path: path.to_owned(),
                source: io::Error::new(io::ErrorKind::InvalidInput, "path must be absolute"),
            });
        }
        // 先锁定并校验，加载期间文件不可能被换掉
        let file = LockedFile::open(path, expected_sha256)?;
        let wide = to_wide(&path.to_string_lossy());
        // SAFETY: `wide` 以 NUL 结尾、是完整路径；文件句柄参数必须为空；依赖只在 DLL 所在目录与
        // System32 中查找。成功时返回本进程持有一份引用计数的模块句柄。
        let module = unsafe {
            LoadLibraryExW(
                wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(LibraryError::Load {
                path: path.to_owned(),
                source: io::Error::last_os_error(),
            });
        }
        Ok(Self {
            module,
            _file: file,
        })
    }

    /// 导出符号的地址；没有这个符号时为空。把它转成函数指针由调用方负责（需要 `unsafe`）。
    pub fn symbol(&self, name: &CStr) -> Option<NonNull<c_void>> {
        // SAFETY: 模块句柄在 `self` 存活期间有效；`name` 以 NUL 结尾。
        let proc = unsafe { GetProcAddress(self.module, name.as_ptr().cast()) };
        proc.and_then(|f| NonNull::new(f as *mut c_void))
    }

    pub fn path(&self) -> &Path {
        self._file.path()
    }
}

impl Drop for VerifiedLibrary {
    fn drop(&mut self) {
        // SAFETY: 模块句柄由 LoadLibraryExW 返回，只在这里释放一次；释放后不再使用。
        unsafe { FreeLibrary(self.module) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha256_file;

    fn system_dll(name: &str) -> PathBuf {
        Path::new(&std::env::var("SystemRoot").expect("SystemRoot"))
            .join("System32")
            .join(name)
    }

    fn sha(path: &Path) -> String {
        to_hex(&sha256_file(path).expect("hash"))
    }

    #[test]
    fn verified_library_resolves_exports() {
        let dll = system_dll("version.dll");
        let lib = VerifiedLibrary::load(&dll, &sha(&dll)).expect("load");
        assert!(lib.symbol(c"GetFileVersionInfoSizeW").is_some());
        assert!(lib.symbol(c"NoSuchExport").is_none());
        assert_eq!(lib.path(), dll);
    }

    #[test]
    fn hash_mismatch_refuses_to_load() {
        let dll = system_dll("version.dll");
        assert!(matches!(
            VerifiedLibrary::load(&dll, &"0".repeat(64)),
            Err(LibraryError::HashMismatch { .. })
        ));
        assert!(matches!(
            VerifiedLibrary::load(Path::new("version.dll"), &sha(&dll)),
            Err(LibraryError::Load { .. })
        ));
    }

    #[test]
    fn locked_files_cannot_be_written_deleted_or_renamed() {
        let dir = std::env::temp_dir().join(format!("procroute-locked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("driver.sys");
        std::fs::write(&file, b"pretend driver").expect("write");
        let guard = LockedFile::open(&file, &sha(&file)).expect("lock");
        assert!(std::fs::OpenOptions::new().write(true).open(&file).is_err());
        assert!(std::fs::remove_file(&file).is_err());
        assert!(std::fs::rename(&file, dir.join("other.sys")).is_err());
        drop(guard);
        std::fs::remove_file(&file).expect("released");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
