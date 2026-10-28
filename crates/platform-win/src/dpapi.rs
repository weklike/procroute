// SPDX-License-Identifier: GPL-3.0-or-later
//! 机器范围 DPAPI 加解密，节点凭据落盘前加密（T-053，C-SEC-04）。
//!
//! 使用 `CRYPTPROTECT_LOCAL_MACHINE`：服务以 LocalSystem 运行，凭据要能跨用户会话、
//! 在服务重启后解开，所以不能绑定某个用户的密钥。机器范围意味着本机任何进程理论上都能解密，
//! 真正的访问控制靠配置目录的 ACL（C-SEC-05）；这里额外带一段固定熵，避免其他程序
//! 不经意地用默认参数解开我们的数据。
#![allow(unsafe_code)] // 需要调用 CryptProtectData / CryptUnprotectData；每处都有 SAFETY 注释

use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    CryptUnprotectData,
};

use crate::secret::Secret;

/// 附加熵。改动它会让已有密文全部无法解开，只能随落盘格式版本一起升级。
const ENTROPY: &[u8] = b"ProcRoute.credential.v1";

/// DPAPI 失败。错误里不带任何明文或密文内容。
#[derive(Debug, thiserror::Error)]
pub enum DpapiError {
    #[error("input is too large for DPAPI")]
    TooLarge,
    #[error("CryptProtectData failed: {0}")]
    Protect(#[source] io::Error),
    #[error("CryptUnprotectData failed (corrupted data or wrong machine): {0}")]
    Unprotect(#[source] io::Error),
}

/// 用机器范围密钥加密。
pub fn protect(plain: &[u8]) -> Result<Vec<u8>, DpapiError> {
    let input = blob(plain)?;
    let entropy = blob(ENTROPY)?;
    let mut out = empty_blob();
    // SAFETY: `input` 与 `entropy` 指向调用期间存活的只读缓冲区（API 不会写入它们）；
    // 描述、保留参数和提示结构允许为空；`out` 由 API 用 LocalAlloc 填充，下面负责释放。
    let ok = unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(DpapiError::Protect(io::Error::last_os_error()));
    }
    // 密文不是机密，不需要清零。
    Ok(take_blob(out, false))
}

/// 解密 [`protect`] 的输出。明文直接包进 [`Secret`]，不经过可打印的中间类型。
pub fn unprotect(cipher: &[u8]) -> Result<Secret<Vec<u8>>, DpapiError> {
    let input = blob(cipher)?;
    let entropy = blob(ENTROPY)?;
    let mut out = empty_blob();
    // SAFETY: 同 `protect`：输入缓冲区在调用期间存活且只读；`out` 由 API 分配，下面负责释放。
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &entropy,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut out,
        )
    };
    if ok == 0 {
        return Err(DpapiError::Unprotect(io::Error::last_os_error()));
    }
    Ok(Secret::new(take_blob(out, true)))
}

fn blob(data: &[u8]) -> Result<CRYPT_INTEGER_BLOB, DpapiError> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(data.len()).map_err(|_| DpapiError::TooLarge)?,
        // API 声明为 *mut，但输入 blob 只会被读取。
        pbData: data.as_ptr().cast_mut(),
    })
}

fn empty_blob() -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    }
}

/// 把 API 分配的输出拷进 `Vec` 并释放原缓冲区；`wipe` 为真时先清零（明文）。
fn take_blob(out: CRYPT_INTEGER_BLOB, wipe: bool) -> Vec<u8> {
    if out.pbData.is_null() {
        return Vec::new();
    }
    let len = out.cbData as usize;
    // SAFETY: 调用成功时 `pbData` 指向 API 分配的 `cbData` 字节，在 LocalFree 之前一直有效。
    let data = unsafe { std::slice::from_raw_parts(out.pbData, len) }.to_vec();
    if wipe {
        for i in 0..len {
            // SAFETY: `i < len`，写入仍在上面同一块缓冲区内；volatile 防止清零被优化掉。
            unsafe { ptr::write_volatile(out.pbData.add(i), 0) };
        }
    }
    // SAFETY: `pbData` 由 CryptProtectData / CryptUnprotectData 用 LocalAlloc 分配，只释放这一次。
    unsafe { LocalFree(out.pbData.cast()) };
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for plain in [&b""[..], b"x", "密码-🔑-p@ss".as_bytes(), &[0u8; 4096]] {
            let cipher = protect(plain).expect("protect");
            assert_eq!(unprotect(&cipher).expect("unprotect").expose(), plain);
        }
    }

    #[test]
    fn ciphertext_does_not_contain_the_plaintext() {
        let plain = b"hunter2-very-secret-password";
        let cipher = protect(plain).expect("protect");
        assert!(cipher.len() > plain.len());
        assert!(!cipher.windows(plain.len()).any(|w| w == plain));
    }

    #[test]
    fn same_input_encrypts_differently_each_time() {
        assert_ne!(
            protect(b"same").expect("protect"),
            protect(b"same").expect("protect")
        );
    }

    #[test]
    fn tampered_or_garbage_input_is_rejected() {
        let mut cipher = protect(b"secret").expect("protect");
        let last = cipher.len() - 1;
        cipher[last] ^= 0xff;
        assert!(matches!(unprotect(&cipher), Err(DpapiError::Unprotect(_))));
        assert!(matches!(
            unprotect(b"definitely not a dpapi blob"),
            Err(DpapiError::Unprotect(_))
        ));
    }

    #[test]
    fn decrypted_value_is_masked_in_debug_output() {
        let cipher = protect(b"hunter2").expect("protect");
        let plain = unprotect(&cipher).expect("unprotect");
        assert!(!format!("{plain:?}").contains("hunter2"));
    }
}
