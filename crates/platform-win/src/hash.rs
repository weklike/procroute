// SPDX-License-Identifier: GPL-3.0-or-later
//! SHA-256（Windows CNG）。
//!
//! 第三方二进制必须按锁文件校验 SHA256（C-DEP-04、C-SEC-06）：`cargo xtask fetch-deps` 校验下载结果，
//! 服务启动 sing-box 前（T-056）校验安装目录里的可执行文件。两处共用这里的实现，
//! 不为同一功能再引入第二个哈希库（C-DEP-03）。
//!
//! 使用 `BCRYPT_SHA256_ALG_HANDLE` 伪句柄，不必打开算法提供程序；Windows 10 起可用（C-DRV-05）。
#![allow(unsafe_code)] // 需要调用 BCryptCreateHash / BCryptHashData / BCryptFinishHash；每处都有 SAFETY 注释

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::NTSTATUS;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_HASH_HANDLE, BCRYPT_SHA256_ALG_HANDLE, BCryptCreateHash, BCryptDestroyHash,
    BCryptFinishHash, BCryptHashData,
};

/// SHA-256 摘要长度（字节）。
pub const SHA256_LEN: usize = 32;

/// 读文件时每次送进哈希的块大小。
const CHUNK: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("{call} failed with NTSTATUS {status:#010x}")]
    Cng { call: &'static str, status: u32 },
    #[error("reading input failed: {0}")]
    Io(#[from] io::Error),
}

/// 增量计算 SHA-256。
pub struct Sha256 {
    handle: BCRYPT_HASH_HANDLE,
}

impl Sha256 {
    pub fn new() -> Result<Self, HashError> {
        let mut handle: BCRYPT_HASH_HANDLE = ptr::null_mut();
        // SAFETY: 伪句柄 BCRYPT_SHA256_ALG_HANDLE 不需要打开或释放；哈希对象缓冲区传空，由 CNG 自行分配；
        // 不是 HMAC，所以密钥为空；`handle` 是有效的输出位置。
        let status = unsafe {
            BCryptCreateHash(
                BCRYPT_SHA256_ALG_HANDLE,
                &mut handle,
                ptr::null_mut(),
                0,
                ptr::null(),
                0,
                0,
            )
        };
        check("BCryptCreateHash", status)?;
        Ok(Self { handle })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), HashError> {
        // 单次调用的长度是 u32，超长输入分段送入。
        for part in data.chunks(u32::MAX as usize) {
            // SAFETY: `self.handle` 由 BCryptCreateHash 创建且尚未销毁；`part` 在调用期间存活且只读，
            // 长度不超过 u32::MAX。
            let status =
                unsafe { BCryptHashData(self.handle, part.as_ptr(), part.len() as u32, 0) };
            check("BCryptHashData", status)?;
        }
        Ok(())
    }

    pub fn finish(self) -> Result<[u8; SHA256_LEN], HashError> {
        let mut out = [0u8; SHA256_LEN];
        // SAFETY: `self.handle` 有效；`out` 恰好是 SHA-256 的摘要长度。句柄随后由 Drop 销毁。
        let status =
            unsafe { BCryptFinishHash(self.handle, out.as_mut_ptr(), SHA256_LEN as u32, 0) };
        check("BCryptFinishHash", status)?;
        Ok(out)
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        // SAFETY: 句柄由 BCryptCreateHash 创建，只在这里销毁一次。
        unsafe { BCryptDestroyHash(self.handle) };
    }
}

/// 计算一段内存的 SHA-256。
pub fn sha256(data: &[u8]) -> Result<[u8; SHA256_LEN], HashError> {
    let mut h = Sha256::new()?;
    h.update(data)?;
    h.finish()
}

/// 流式计算 `reader` 全部内容的 SHA-256。
pub fn sha256_reader(mut reader: impl Read) -> Result<[u8; SHA256_LEN], HashError> {
    let mut h = Sha256::new()?;
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        h.update(&buf[..n])?;
    }
    h.finish()
}

/// 计算文件的 SHA-256。
pub fn sha256_file(path: &Path) -> Result<[u8; SHA256_LEN], HashError> {
    sha256_reader(File::open(path)?)
}

/// 小写十六进制，与锁文件里的写法一致。
pub fn to_hex(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

fn check(call: &'static str, status: NTSTATUS) -> Result<(), HashError> {
    if status >= 0 {
        Ok(())
    } else {
        Err(HashError::Cng {
            call,
            status: status as u32,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // FIPS 180-2 附录 B 的测试向量。
    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const TWO_BLOCKS: &str = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

    #[test]
    fn known_vectors() {
        assert_eq!(to_hex(&sha256(b"").expect("hash")), EMPTY);
        assert_eq!(to_hex(&sha256(b"abc").expect("hash")), ABC);
        assert_eq!(
            to_hex(
                &sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").expect("hash")
            ),
            TWO_BLOCKS
        );
    }

    #[test]
    fn incremental_matches_one_shot() {
        let data: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let mut h = Sha256::new().expect("new");
        for part in data.chunks(7919) {
            h.update(part).expect("update");
        }
        assert_eq!(h.finish().expect("finish"), sha256(&data).expect("hash"));
        assert_eq!(
            sha256_reader(&data[..]).expect("reader"),
            sha256(&data).expect("hash")
        );
    }

    #[test]
    fn hashes_files_and_reports_missing_ones() {
        let dir = std::env::temp_dir().join(format!("procroute-hash-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("abc.txt");
        std::fs::write(&file, b"abc").expect("write");
        assert_eq!(to_hex(&sha256_file(&file).expect("hash")), ABC);
        assert!(matches!(
            sha256_file(&dir.join("missing")),
            Err(HashError::Io(_))
        ));
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(to_hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }
}
