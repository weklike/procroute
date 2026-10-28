// SPDX-License-Identifier: GPL-3.0-or-later
//! 系统 CSPRNG（Windows CNG）。
//!
//! sing-box 控制 API 的密钥每次启动随机生成（C-NET-08），这里提供随机字节；
//! 不为此引入第三方随机数库（C-DEP-03）。
#![allow(unsafe_code)] // 需要调用 BCryptGenRandom；有 SAFETY 注释

use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("BCryptGenRandom failed with NTSTATUS {0:#010x}")]
pub struct RandomError(pub u32);

/// 用系统首选的 CSPRNG 填满 `buf`。
pub fn fill_random(buf: &mut [u8]) -> Result<(), RandomError> {
    // 单次调用的长度是 u32，超长缓冲区分段填充。
    for part in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: 使用系统首选 RNG 时算法句柄必须为空；`part` 可写且长度不超过 u32::MAX。
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                part.as_mut_ptr(),
                part.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(RandomError(status as u32));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_the_buffer_with_varying_bytes() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill_random(&mut a).expect("random");
        fill_random(&mut b).expect("random");
        // 64 字节全零或两次相同的概率可以忽略。
        assert_ne!(a, [0u8; 64]);
        assert_ne!(a, b);
        fill_random(&mut []).expect("empty buffer is fine");
    }
}
