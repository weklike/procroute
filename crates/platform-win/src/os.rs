// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows 版本与内存完整性开关，写进诊断包（T-112）。
//!
//! 从注册表读：`GetVersionEx` 受应用清单影响，可能返回兼容模式的版本号；`RtlGetVersion` 没有
//! 修订号（UBR）与「24H2」这样的显示版本。只读 `HKLM`，不需要管理员。
#![allow(unsafe_code)] // 需要调用 RegGetValueW；有 SAFETY 注释

use std::ptr;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegGetValueW,
};

use crate::wide::{from_wide, to_wide};

const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
const HVCI: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";

/// 字符串值的读取上限（UTF-16 单元，含结尾 NUL）。这里读的值都很短，超长视为读不到。
const MAX_STRING_UNITS: usize = 256;

/// 系统版本。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsVersion {
    /// `主.次.内部版本.修订`，例如 `10.0.26100.2314`。
    pub build: String,
    /// 例如 `24H2`；较早的系统没有这一项。
    pub display_version: Option<String>,
}

/// 读系统版本；注册表里缺少主要的几项时为 `None`。
pub fn windows_version() -> Option<WindowsVersion> {
    let major = read_dword(CURRENT_VERSION, "CurrentMajorVersionNumber")?;
    let minor = read_dword(CURRENT_VERSION, "CurrentMinorVersionNumber")?;
    let build = read_string(CURRENT_VERSION, "CurrentBuildNumber")?;
    let ubr = read_dword(CURRENT_VERSION, "UBR").unwrap_or(0);
    Some(WindowsVersion {
        build: format!("{major}.{minor}.{build}.{ubr}"),
        display_version: read_string(CURRENT_VERSION, "DisplayVersion"),
    })
}

/// 内存完整性（HVCI）的配置开关，会影响第三方驱动能否加载。没有这一项（从未配置）时为 `None`。
pub fn memory_integrity_enabled() -> Option<bool> {
    read_dword(HVCI, "Enabled").map(|v| v != 0)
}

fn read_dword(key: &str, value: &str) -> Option<u32> {
    let key = to_wide(key);
    let value = to_wide(value);
    let mut data = 0u32;
    let mut size = size_of::<u32>() as u32;
    // SAFETY: 键名与值名是以 NUL 结尾的 UTF-16；`data` 可写且 `size` 如实给出其字节数；
    // 不需要值类型，类型指针为空。
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_DWORD,
            ptr::null_mut(),
            (&raw mut data).cast(),
            &mut size,
        )
    };
    (status == ERROR_SUCCESS).then_some(data)
}

fn read_string(key: &str, value: &str) -> Option<String> {
    let key = to_wide(key);
    let value = to_wide(value);
    let mut buf = [0u16; MAX_STRING_UNITS];
    let mut size = (MAX_STRING_UNITS * size_of::<u16>()) as u32;
    // SAFETY: 同上；`buf` 可写且 `size` 是它的字节数。RRF_RT_REG_SZ 保证成功时结果以 NUL 结尾，
    // 缓冲区不够时返回 ERROR_MORE_DATA 而不写越界。
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return None;
    }
    let text = from_wide(&buf);
    (!text.is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_running_windows_version() {
        let v = windows_version().expect("version");
        let parts: Vec<u32> = v
            .build
            .split('.')
            .map(|p| p.parse().expect("numeric part"))
            .collect();
        assert_eq!(parts.len(), 4, "{}", v.build);
        assert_eq!(&parts[..2], &[10, 0]);
        // 支持矩阵的最低版本是 Windows 10 22H2（19045，C-DRV-05）
        assert!(parts[2] >= 19045, "{}", v.build);
    }

    #[test]
    fn missing_values_read_as_none() {
        assert_eq!(read_dword(CURRENT_VERSION, "NoSuchValueProcRoute"), None);
        assert_eq!(read_string(r"SOFTWARE\NoSuchKeyProcRoute", "x"), None);
        // 类型不符也读不到，而不是读成别的值
        assert_eq!(read_dword(CURRENT_VERSION, "CurrentBuildNumber"), None);
        // 值存在与否取决于机器配置，只要求调用本身不出错
        let _ = memory_integrity_enabled();
    }
}
