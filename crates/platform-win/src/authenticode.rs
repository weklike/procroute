// SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticode 签名校验：服务据此确认控制管道客户端与自己用同一张证书签名（C-SEC-02，docs/adr/0002）。
//!
//! 只认文件内嵌的签名（`WINTRUST_ACTION_GENERIC_VERIFY_V2` + 文件），不查系统编录：
//! ProcRoute 自己的可执行文件都带内嵌签名。为遵守「不得主动发起网络请求」（C-SEC-08），
//! 校验时关闭吊销检查，并且只使用本地缓存的 URL 数据。
//!
//! 发版用的证书是一次性的自签名证书，机器上不存在信任它的根，因此「根不受信任」不算失败；
//! 文件被改动、证书过期或被明确吊销等其他任何结果都算失败。身份由调用方比对 [`SignerCert`] 确定。
#![allow(unsafe_code)] // 需要调用 WinVerifyTrust 与证书 API；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    CERT_SHA256_HASH_PROP_ID, CertGetCertificateContextProperty,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};

use crate::wide::to_wide;

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001_u32 as i32;
const CERT_E_UNTRUSTEDROOT: i32 = 0x800B_0109_u32 as i32;

/// 签名校验失败的原因。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureError {
    #[error("file has no embedded Authenticode signature")]
    NotSigned,
    #[error("Authenticode verification failed (HRESULT {0:#010x})")]
    Invalid(u32),
    #[error("signature verified but the signer certificate could not be read")]
    NoSigner,
}

/// 签名证书的身份：DER 编码的 SHA-256。
///
/// 比对的是证书本身而不是主题：自签名证书的主题任何人都能照抄。
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignerCert([u8; 32]);

impl SignerCert {
    /// 由已知的摘要构造，供测试使用。
    pub const fn from_sha256(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

impl std::fmt::Debug for SignerCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// 校验文件的内嵌签名（文件未被改动、证书在有效期内），返回签名证书。
///
/// 证书链不需要接到受信任的根，见模块文档。
pub fn verified_signer_cert(path: &str) -> Result<SignerCert, SignatureError> {
    let wide = to_wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: wide.as_ptr(),
        hFile: ptr::null_mut(),
        pgKnownSubject: ptr::null_mut(),
    };
    // SAFETY: WINTRUST_DATA 是纯数据结构，全零是合法的初始值，下面逐个填写需要的字段。
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    // SAFETY: `data` 与它指向的 `file`、`wide` 都在本函数内存活；不弹界面（hwnd 为 -1 也可，
    // 这里配合 WTD_UI_NONE 传空）。VERIFY 成功后必须用 CLOSE 释放状态，见下方。
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&raw mut data).cast::<c_void>(),
        )
    };
    let result = if status == 0 || status == CERT_E_UNTRUSTEDROOT {
        // SAFETY: 这两种结果下 `hWVTStateData` 都持有提供者数据，在 CLOSE 之前有效。
        unsafe { signer_cert(&data) }.ok_or(SignatureError::NoSigner)
    } else if matches!(
        status,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN
    ) {
        Err(SignatureError::NotSigned)
    } else {
        Err(SignatureError::Invalid(status as u32))
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: 用同一个 WINTRUST_DATA 释放 VERIFY 分配的状态；失败时状态为空，CLOSE 也安全。
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&raw mut data).cast::<c_void>(),
        )
    };
    result
}

/// 从 WinVerifyTrust 的状态数据里取第一个签名者的证书。
///
/// # Safety
///
/// `data.hWVTStateData` 必须来自一次 `WTD_STATEACTION_VERIFY`，且尚未 CLOSE。
unsafe fn signer_cert(data: &WINTRUST_DATA) -> Option<SignerCert> {
    // SAFETY: 由调用方保证状态数据有效；各 WTHelper 函数返回指向该状态内部的指针或空。
    let cert = unsafe {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return None;
        }
        let signer = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if signer.is_null() {
            return None;
        }
        let cert = WTHelperGetProvCertFromChain(signer, 0);
        if cert.is_null() || (*cert).pCert.is_null() {
            return None;
        }
        (*cert).pCert
    };
    let mut digest = [0u8; 32];
    let mut len = digest.len() as u32;
    // SAFETY: `cert` 是有效的证书上下文；`digest` 可写 `len` 字节。
    let ok = unsafe {
        CertGetCertificateContextProperty(
            cert,
            CERT_SHA256_HASH_PROP_ID,
            digest.as_mut_ptr().cast::<c_void>(),
            &mut len,
        )
    };
    (ok != 0 && len as usize == digest.len()).then_some(SignerCert(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `tests/fixtures/authenticode`（生成方式见其中的 generate.ps1）。
    fn fixture(name: &str) -> String {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .ancestors()
            .nth(2)
            .expect("the workspace root");
        root.join("tests/fixtures/authenticode")
            .join(name)
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn unsigned_binaries_are_reported_as_not_signed() {
        let exe = std::env::current_exe().expect("current exe");
        assert_eq!(
            verified_signer_cert(&exe.to_string_lossy()),
            Err(SignatureError::NotSigned)
        );
    }

    #[test]
    fn missing_files_are_not_trusted() {
        assert!(verified_signer_cert(r"C:\no\such\file.exe").is_err());
    }

    #[test]
    fn embedded_microsoft_signatures_verify() {
        // 系统目录里多数文件用编录签名，但总有一些带内嵌签名（例如 MRT.exe、MpSigStub.exe）。
        let sys32 = std::path::Path::new(&std::env::var("SystemRoot").expect("SystemRoot"))
            .join("System32");
        std::fs::read_dir(&sys32)
            .expect("read System32")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
            .find_map(|p| verified_signer_cert(&p.to_string_lossy()).ok())
            .expect("at least one System32 executable carries an embedded signature");
    }

    #[test]
    fn a_self_signed_certificate_without_a_trusted_root_identifies_the_signer() {
        let a1 = verified_signer_cert(&fixture("a1.dll")).expect("a1");
        let a2 = verified_signer_cert(&fixture("a2.dll")).expect("a2");
        assert_eq!(a1, a2, "same certificate, different files");
    }

    #[test]
    fn a_different_certificate_with_the_same_subject_is_a_different_signer() {
        let a = verified_signer_cert(&fixture("a1.dll")).expect("a1");
        let b = verified_signer_cert(&fixture("b.dll")).expect("b");
        assert_ne!(a, b);
    }

    #[test]
    fn a_file_changed_after_signing_is_rejected() {
        assert!(matches!(
            verified_signer_cert(&fixture("a1-tampered.dll")),
            Err(SignatureError::Invalid(_))
        ));
    }

    #[test]
    fn the_debug_form_is_the_hex_digest() {
        let cert = SignerCert::from_sha256([0xAB; 32]);
        assert_eq!(format!("{cert:?}"), "ab".repeat(32));
    }
}
