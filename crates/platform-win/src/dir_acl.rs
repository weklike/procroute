// SPDX-License-Identifier: GPL-3.0-or-later
//! 配置目录的访问控制（C-SEC-05）：`%ProgramData%\ProcRoute\` 的写权限只授予 SYSTEM 与 Administrators。
//!
//! [`secure_directory`] 创建目录（已存在则沿用）并把 DACL 设为受保护（不再继承 `ProgramData` 上
//! 「Users 可创建文件」的 ACE）。目录若是别人预先创建的，所有者可以随时改回 DACL，
//! 因此所有者不在信任列表里时直接拒绝，而不是在一个被抢注的目录里存放配置。
#![allow(unsafe_code)] // 需要调用 Get/SetNamedSecurityInfoW；每处都有 SAFETY 注释

use std::io;
use std::path::{Path, PathBuf};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

use crate::acl::{SecurityDescriptor, sid_to_string, take_local_wide_string};
use crate::wide::to_wide;

/// 配置目录的 DACL：SYSTEM 与 Administrators 完全控制，子目录与文件继承；其他人没有任何权限。
/// 界面只通过 IPC 读写配置（C-ARCH-05），普通用户也不需要读权限。
pub const CONFIG_DIR_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// Administrators 组的 SID。
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// 配置根目录 `%ProgramData%\ProcRoute`。
pub fn config_root() -> io::Result<PathBuf> {
    let program_data = std::env::var_os("ProgramData")
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "%ProgramData% is not set"))?;
    Ok(PathBuf::from(program_data).join("ProcRoute"))
}

/// 创建（或沿用）目录并应用受保护的 DACL。
///
/// 目录所有者的 SID 必须在 `trusted_owners` 中，否则返回 `PermissionDenied` 且不做任何修改。
/// 服务传入 SYSTEM 与 Administrators。
pub fn secure_directory(path: &Path, sddl: &str, trusted_owners: &[&str]) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    let owner = path_owner_sid(path)?;
    if !trusted_owners.contains(&owner.as_str()) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is owned by untrusted {owner}", path.display()),
        ));
    }
    let sd = SecurityDescriptor::from_sddl(sddl)?;
    let mut present = 0i32;
    let mut defaulted = 0i32;
    let mut dacl: *mut ACL = ptr::null_mut();
    // SAFETY: `sd.0` 是有效的自相对安全描述符；输出参数都是可写的局部变量。
    // 返回的 DACL 指针指向 `sd` 内部，`sd` 存活期间有效。
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if present == 0 || dacl.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "SDDL must contain a DACL",
        ));
    }
    let wide = to_wide(&path.to_string_lossy());
    // SAFETY: `wide` 以 NUL 结尾；只设置 DACL（受保护），所有者与组不变，传空；`dacl` 在 `sd` 存活期间有效。
    let rc = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    win32_result(rc)
}

/// 文件或目录所有者的 SID。
pub fn path_owner_sid(path: &Path) -> io::Result<String> {
    let wide = to_wide(&path.to_string_lossy());
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` 以 NUL 结尾；只请求所有者；`sd` 由 API 分配，下面释放；`owner` 指向 `sd` 内部。
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    win32_result(rc)?;
    // SAFETY: 调用成功时 `owner` 指向 `sd` 内的合法 SID，`sd` 尚未释放。
    let result = unsafe { sid_to_string(owner) };
    // SAFETY: `sd` 由 GetNamedSecurityInfoW 分配，`owner` 不再使用，只释放一次。
    unsafe { LocalFree(sd) };
    result
}

/// 文件或目录当前 DACL 的 SDDL 形式（诊断与测试用）。
pub fn path_dacl_sddl(path: &Path) -> io::Result<String> {
    let wide = to_wide(&path.to_string_lossy());
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` 以 NUL 结尾；只请求 DACL，DACL 指针不需要（传空）；`sd` 由 API 分配，下面释放。
    let rc = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    win32_result(rc)?;
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `sd` 有效；`text` 由 API 用 LocalAlloc 分配，交给 take_local_wide_string 释放。
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            ptr::null_mut(),
        )
    };
    let result = if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: 调用成功时 `text` 是 LocalAlloc 分配、以 NUL 结尾的字符串。
        Ok(unsafe { take_local_wide_string(text) })
    };
    // SAFETY: `sd` 由 GetNamedSecurityInfoW 分配，只释放一次。
    unsafe { LocalFree(sd) };
    result
}

fn win32_result(rc: u32) -> io::Result<()> {
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc as i32))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{SYSTEM_SID, current_process_is_elevated, current_user_sid};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("procroute-diracl-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    /// 新建目录的所有者：未提升时是当前用户；提升的管理员令牌默认所有者是 Administrators 组
    /// （CI 的 Windows 运行器就是这种情况）。
    fn create_owned_dir(tag: &str) -> (PathBuf, String) {
        let dir = temp_dir(tag);
        std::fs::create_dir_all(&dir).expect("create");
        let owner = path_owner_sid(&dir).expect("owner");
        let me = current_user_sid().expect("sid");
        assert!(
            owner == me || owner == ADMINISTRATORS_SID,
            "unexpected owner {owner} of a directory created by {me}"
        );
        (dir, owner)
    }

    /// 测试结束后把 DACL 改回只给自己，然后删除（所有者始终保有 WRITE_DAC）。
    fn cleanup(dir: &Path, owner: &str) {
        let me = current_user_sid().expect("sid");
        secure_directory(dir, &format!("D:P(A;OICI;FA;;;{me})"), &[owner]).expect("reset acl");
        std::fs::remove_dir_all(dir).expect("remove");
    }

    #[test]
    fn secured_directory_admits_only_system_and_administrators() {
        // 所有者信任检查由下一个测试覆盖；这里只验证 DACL 的效果，所以信任实际的所有者。
        let (dir, owner) = create_owned_dir("secure");
        secure_directory(&dir, CONFIG_DIR_SDDL, &[&owner]).expect("secure");

        let dacl = path_dacl_sddl(&dir).expect("dacl");
        assert!(dacl.starts_with("D:PAI"), "{dacl}");
        assert!(dacl.contains("(A;OICI;FA;;;SY)"), "{dacl}");
        assert!(dacl.contains("(A;OICI;FA;;;BA)"), "{dacl}");
        assert_eq!(dacl.matches("(A;").count(), 2, "no other principal: {dacl}");

        let write = std::fs::write(dir.join("probe.txt"), b"x");
        if current_process_is_elevated().expect("elevation") {
            assert!(write.is_ok(), "administrators may write");
        } else {
            let err = write.expect_err("plain users must not write");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        }
        cleanup(&dir, &owner);
    }

    #[test]
    fn directories_with_untrusted_owners_are_refused() {
        let dir = temp_dir("owner");
        std::fs::create_dir_all(&dir).expect("create");
        let owner = path_owner_sid(&dir).expect("owner");
        let before = path_dacl_sddl(&dir).expect("dacl");
        let result = secure_directory(&dir, CONFIG_DIR_SDDL, &[SYSTEM_SID, ADMINISTRATORS_SID]);
        if owner == SYSTEM_SID || owner == ADMINISTRATORS_SID {
            // 提升的令牌创建的对象归 Administrators 所有，这时应当放行。
            result.expect("trusted owner");
        } else {
            let err = result.expect_err("untrusted owner");
            assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
            assert_eq!(
                path_dacl_sddl(&dir).expect("dacl"),
                before,
                "nothing changed"
            );
        }
        std::fs::remove_dir_all(&dir).expect("remove");
    }

    #[test]
    fn config_root_is_under_program_data() {
        let root = config_root().expect("root");
        assert!(root.ends_with("ProcRoute"), "{}", root.display());
        let pd = std::env::var("ProgramData").expect("ProgramData");
        assert!(root.starts_with(pd));
    }
}
