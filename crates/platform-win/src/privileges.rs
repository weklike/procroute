// SPDX-License-Identifier: GPL-3.0-or-later
//! 收窄当前进程令牌的特权（C-SEC-06）。
//!
//! 服务以 LocalSystem 运行，令牌里带着二十多项特权，绝大多数用不到。启动后把不在白名单里的特权
//! 从令牌中**移除**（`SE_PRIVILEGE_REMOVED`，不可再启用），之后创建的子进程（sing-box）继承的也是
//! 收窄后的令牌。
#![allow(unsafe_code)] // 需要调用 OpenProcessToken / GetTokenInformation / AdjustTokenPrivileges；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeNameW,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenPrivileges,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::wide::from_wide;

/// 当前进程令牌里的全部特权名（不论是否启用）。
pub fn current_privileges() -> io::Result<Vec<String>> {
    let token = open_current_token(TOKEN_QUERY)?;
    let mut privileges = TokenPrivilegeList::query(&token)?;
    privileges
        .entries_mut()
        .iter()
        .map(|e| privilege_name(&e.Luid))
        .collect()
}

/// 从当前进程令牌中移除 `keep` 以外的全部特权（名字不区分大小写），返回被移除的特权名。
/// `keep` 里令牌本来就没有的特权直接忽略。
pub fn retain_privileges(keep: &[&str]) -> io::Result<Vec<String>> {
    let token = open_current_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
    let mut privileges = TokenPrivilegeList::query(&token)?;
    let mut removed = Vec::new();
    let mut to_remove = Vec::new();
    for entry in privileges.entries_mut().iter() {
        let name = privilege_name(&entry.Luid)?;
        if !keep.iter().any(|k| k.eq_ignore_ascii_case(&name)) {
            to_remove.push(entry.Luid);
            removed.push(name);
        }
    }
    if to_remove.is_empty() {
        return Ok(removed);
    }
    // 只把要移除的项放进请求，其余特权保持原状（属性写 0 会把它们禁用，不能这样做）。
    privileges.set_entries(&to_remove);
    // SAFETY: 令牌句柄有效且带 TOKEN_ADJUST_PRIVILEGES；`privileges` 是一个完整的 TOKEN_PRIVILEGES，
    // PrivilegeCount 与随后的数组长度一致；不需要旧状态，后两个参数为空。
    let ok = unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle() as HANDLE,
            0,
            privileges.as_ptr(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // 函数成功也可能只处理了一部分，要看最后错误码。
    // SAFETY: 无参数。
    if unsafe { GetLastError() } == ERROR_NOT_ALL_ASSIGNED {
        return Err(io::Error::from_raw_os_error(ERROR_NOT_ALL_ASSIGNED as i32));
    }
    Ok(removed)
}

fn open_current_token(access: u32) -> io::Result<OwnedHandle> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭；成功时 `token` 是新句柄，交给 OwnedHandle。
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 上面调用成功，`token` 是本进程独占的有效句柄。
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// 按 8 字节对齐保存的 TOKEN_PRIVILEGES（头部 + 变长数组）。
struct TokenPrivilegeList {
    buf: Vec<u64>,
}

impl TokenPrivilegeList {
    fn query(token: &OwnedHandle) -> io::Result<Self> {
        let handle = token.as_raw_handle() as HANDLE;
        let mut len = 0u32;
        // SAFETY: 第一次调用只取所需长度，缓冲区为空、长度为 0。
        unsafe { GetTokenInformation(handle, TokenPrivileges, ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buf = vec![0u64; (len as usize).div_ceil(size_of::<u64>())];
        // SAFETY: `buf` 至少 `len` 字节且按 8 字节对齐，足以容纳 TOKEN_PRIVILEGES 及其数组。
        let ok = unsafe {
            GetTokenInformation(
                handle,
                TokenPrivileges,
                buf.as_mut_ptr().cast::<c_void>(),
                len,
                &mut len,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { buf })
    }

    fn as_ptr(&self) -> *const TOKEN_PRIVILEGES {
        self.buf.as_ptr().cast()
    }

    fn entries_mut(&mut self) -> &mut [LUID_AND_ATTRIBUTES] {
        // SAFETY: 缓冲区由 GetTokenInformation 填写（或由 set_entries 缩短），开头是一个对齐的
        // TOKEN_PRIVILEGES，紧随其后有 PrivilegeCount 个 LUID_AND_ATTRIBUTES，全部位于 `buf` 内；
        // 返回的切片借用 `self`，期间缓冲区不会被移动或释放。
        unsafe {
            let header = self.buf.as_mut_ptr().cast::<TOKEN_PRIVILEGES>();
            let count = (*header).PrivilegeCount as usize;
            let first = (&raw mut (*header).Privileges).cast::<LUID_AND_ATTRIBUTES>();
            std::slice::from_raw_parts_mut(first, count)
        }
    }

    /// 把数组改成「移除这些特权」的请求。`luids` 不多于原有项数，原地写入不会越界。
    fn set_entries(&mut self, luids: &[LUID]) {
        let entries = self.entries_mut();
        let n = luids.len().min(entries.len());
        for (entry, luid) in entries.iter_mut().zip(luids) {
            entry.Luid = *luid;
            entry.Attributes = SE_PRIVILEGE_REMOVED;
        }
        // SAFETY: 开头是对齐的 TOKEN_PRIVILEGES；只把项数改小，数组仍在缓冲区内。
        unsafe {
            (*self.buf.as_mut_ptr().cast::<TOKEN_PRIVILEGES>()).PrivilegeCount = n as u32;
        }
    }
}

fn privilege_name(luid: &LUID) -> io::Result<String> {
    let mut buf = vec![0u16; 64];
    loop {
        let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: 本机查询（系统名为空）；`luid` 在调用期间有效；`buf` 可写 `len` 个 u16，
        // 成功时 `len` 是写入的字符数（不含 NUL），缓冲区不够时是所需长度。
        let ok = unsafe { LookupPrivilegeNameW(ptr::null(), luid, buf.as_mut_ptr(), &mut len) };
        if ok != 0 {
            return Ok(from_wide(&buf[..len as usize]));
        }
        // SAFETY: 无参数。
        if unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER || len as usize <= buf.len() {
            return Err(io::Error::last_os_error());
        }
        buf = vec![0u16; len as usize + 1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 普通用户令牌里通常都有、移除了也不影响其他测试的特权。
    const HARMLESS: [&str; 4] = [
        "SeTimeZonePrivilege",
        "SeUndockPrivilege",
        "SeIncreaseWorkingSetPrivilege",
        "SeShutdownPrivilege",
    ];

    #[test]
    fn lists_privileges_by_name() {
        let names = current_privileges().expect("privileges");
        assert!(
            names.iter().any(|n| n == "SeChangeNotifyPrivilege"),
            "{names:?}"
        );
    }

    #[test]
    fn privileges_outside_the_allow_list_are_removed() {
        let before = current_privileges().expect("privileges");
        let victim = HARMLESS
            .iter()
            .find(|h| before.iter().any(|n| n == *h))
            .expect("the test token holds at least one harmless privilege");
        let keep: Vec<&str> = before
            .iter()
            .map(String::as_str)
            .filter(|n| n != victim)
            .collect();
        // 白名单大小写不敏感
        let keep_upper: Vec<String> = keep.iter().map(|n| n.to_uppercase()).collect();
        let keep_upper: Vec<&str> = keep_upper.iter().map(String::as_str).collect();
        let removed = retain_privileges(&keep_upper).expect("retain");
        assert_eq!(removed, vec![victim.to_string()]);
        let after = current_privileges().expect("privileges");
        assert_eq!(after, keep);
        // 已经移除的不会再出现，再调用一次无事可做
        assert!(retain_privileges(&keep).expect("retain again").is_empty());
    }
}
