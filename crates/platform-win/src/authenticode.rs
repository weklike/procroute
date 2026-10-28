// SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticode 签名校验：服务据此确认控制管道客户端与自己出自同一签名主体（C-SEC-02）。
//!
//! 只认文件内嵌的签名（`WINTRUST_ACTION_GENERIC_VERIFY_V2` + 文件），不查系统编录：
//! ProcRoute 自己的可执行文件都带内嵌签名。为遵守「不得主动发起网络请求」（C-SEC-08），
//! 校验时关闭吊销检查，并且只使用本地缓存的 URL 数据。
#![allow(unsafe_code)] // 需要调用 WinVerifyTrust 与证书 API；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::ptr;

use windows_sys::Win32::Security::Cryptography::{
    CERT_NAME_RDN_TYPE, CERT_X500_NAME_STR, CertGetNameStringW,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTHelperGetProvCertFromChain,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};

use crate::wide::{from_wide, to_wide};

const TRUST_E_NOSIGNATURE: i32 = 0x800B_0100_u32 as i32;
const TRUST_E_SUBJECT_FORM_UNKNOWN: i32 = 0x800B_0003_u32 as i32;
const TRUST_E_PROVIDER_UNKNOWN: i32 = 0x800B_0001_u32 as i32;

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

/// 校验文件的内嵌签名，成功时返回签名证书的完整主题（X.500 形式，例如
/// `C=CN, L=City, O=Example Ltd, CN=Example Ltd`）。
pub fn verified_signer_subject(path: &str) -> Result<String, SignatureError> {
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
    let result = if status == 0 {
        // SAFETY: 校验成功后 `hWVTStateData` 持有提供者数据，在 CLOSE 之前有效。
        unsafe { signer_subject(&data) }.ok_or(SignatureError::NoSigner)
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

/// 从 WinVerifyTrust 的状态数据里取第一个签名者证书的主题。
///
/// # Safety
///
/// `data.hWVTStateData` 必须来自一次成功的 `WTD_STATEACTION_VERIFY`，且尚未 CLOSE。
unsafe fn signer_subject(data: &WINTRUST_DATA) -> Option<String> {
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
    let str_type: u32 = CERT_X500_NAME_STR;
    let type_para = (&raw const str_type).cast::<c_void>();
    // SAFETY: `cert` 是有效的证书上下文；第一次调用只取长度（含 NUL）。
    let len =
        unsafe { CertGetNameStringW(cert, CERT_NAME_RDN_TYPE, 0, type_para, ptr::null_mut(), 0) };
    if len <= 1 {
        return None;
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` 可写 `len` 个 u16。
    let n = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_RDN_TYPE,
            0,
            type_para,
            buf.as_mut_ptr(),
            len,
        )
    };
    (n > 1).then(|| from_wide(&buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsigned_binaries_are_reported_as_not_signed() {
        let exe = std::env::current_exe().expect("current exe");
        assert_eq!(
            verified_signer_subject(&exe.to_string_lossy()),
            Err(SignatureError::NotSigned)
        );
    }

    #[test]
    fn missing_files_are_not_trusted() {
        assert!(verified_signer_subject(r"C:\no\such\file.exe").is_err());
    }

    #[test]
    fn embedded_microsoft_signatures_verify() {
        // 系统目录里多数文件用编录签名，但总有一些带内嵌签名（例如 MRT.exe、MpSigStub.exe）。
        let sys32 = std::path::Path::new(&std::env::var("SystemRoot").expect("SystemRoot"))
            .join("System32");
        let subject = std::fs::read_dir(&sys32)
            .expect("read System32")
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("exe")))
            .find_map(|p| verified_signer_subject(&p.to_string_lossy()).ok())
            .expect("at least one System32 executable carries an embedded signature");
        assert!(subject.contains("O=Microsoft Corporation"), "{subject}");
        // CertGetNameStringW 默认按证书里的编码顺序输出（通常 `C=…` 在前、`CN=…` 在后）；
        // 服务只比较两份同样方式得到的字符串，顺序无关紧要。
        assert!(subject.contains("CN="), "{subject}");
    }
}
