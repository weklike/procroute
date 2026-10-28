// SPDX-License-Identifier: GPL-3.0-or-later
//! 控制管道的安全描述符：只授予 SYSTEM、Administrators 与当前交互用户，拒绝远程客户端（T-054，C-SEC-01）。
//!
//! 安全描述符（SDDL）：
//!
//! ```text
//! D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;<交互用户 SID>)
//! ```
//!
//! - `P`：不继承父对象的 ACE；
//! - `(D;;GA;;;NU)`：拒绝 NETWORK 登录的令牌，配合 `PIPE_REJECT_REMOTE_CLIENTS` 双重拒绝远程；
//! - 交互用户拿到 `GRGW`（FILE_GENERIC_READ | FILE_GENERIC_WRITE）：标准的客户端打开方式
//!   （`GENERIC_READ | GENERIC_WRITE`，tokio 的 `ClientOptions` 与 UI 都是这样）会请求
//!   `FILE_APPEND_DATA` 与 `FILE_WRITE_EA`，少给任何一项都会让 UI 连不上；而自定义访问掩码打开
//!   需要 `unsafe`，UI 侧不允许（C-CODE-01、C-ARCH-02）。
//!
//! 代价：`FILE_APPEND_DATA` 对管道而言就是 `FILE_CREATE_PIPE_INSTANCE`，交互用户本人可以给这个
//! 名字再添加实例。这不越权——能这样做的只有与 UI 同一身份的进程，它本来就能直接篡改 UI；
//! 其他非管理员用户不在 ACL 里，既连不上也加不了实例。服务启动时用 [`create_pipe_server`] 的
//! `first_instance` 要求 `FILE_FLAG_FIRST_PIPE_INSTANCE`，名字被预先抢注时直接失败，不会加入对方的管道；
//! 服务端对每个客户端还要做可执行路径与签名校验（C-SEC-02）。
#![allow(unsafe_code)] // 需要调用安全描述符、令牌与会话相关的 Win32 API；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use windows_sys::Win32::Foundation::{HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_QUERY,
    TOKEN_USER, TokenElevation, TokenUser,
};
use windows_sys::Win32::System::RemoteDesktop::{
    WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW, WTSActive, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSGetActiveConsoleSessionId, WTSQueryUserToken,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::wide::{from_wide, to_wide};

/// 控制管道名（C-SEC-01）。
pub const CONTROL_PIPE_NAME: &str = r"\\.\pipe\ProcRoute.Control";

/// LocalSystem 的 SID。
pub const SYSTEM_SID: &str = "S-1-5-18";

/// 交互用户的访问权限，取舍见模块文档。
const CLIENT_ACCESS: &str = "GRGW";

/// 生成控制管道的 SDDL。`user_sid` 为空（例如没有用户登录）时只放行 SYSTEM 与 Administrators。
pub fn control_pipe_sddl(user_sid: Option<&str>) -> String {
    let mut sddl = String::from("D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = user_sid {
        sddl.push_str(&format!("(A;;{CLIENT_ACCESS};;;{sid})"));
    }
    sddl
}

/// 自相对格式的安全描述符，由 LocalAlloc 分配，Drop 时释放。
#[derive(Debug)]
pub struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

// SAFETY: 描述符创建后只读，内存归本对象独占，跨线程移动或共享引用都不会产生数据竞争。
unsafe impl Send for SecurityDescriptor {}
// SAFETY: 同上，所有访问都是只读的。
unsafe impl Sync for SecurityDescriptor {}

impl SecurityDescriptor {
    /// 由 SDDL 字符串构造。
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide = to_wide(sddl);
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: `wide` 以 NUL 结尾且在调用期间存活；`sd` 由 API 分配，所有权交给返回的对象；
        // 不需要返回长度，传空指针。
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 || sd.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sd))
    }

    /// 控制管道的描述符，见 [`control_pipe_sddl`]。
    pub fn control_pipe(user_sid: Option<&str>) -> io::Result<Self> {
        Self::from_sddl(&control_pipe_sddl(user_sid))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: 指针由 ConvertStringSecurityDescriptorToSecurityDescriptorW 分配，只在这里释放一次。
        unsafe { LocalFree(self.0) };
    }
}

/// 用给定的安全描述符创建一个字节模式的管道实例，并拒绝远程客户端。
///
/// `first_instance` 为真时要求这是该名字的第一个实例（服务启动时），防止名字被抢注。
pub fn create_pipe_server(
    name: &str,
    sd: &SecurityDescriptor,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.pipe_mode(PipeMode::Byte)
        .reject_remote_clients(true)
        .first_pipe_instance(first_instance);
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: `attrs` 是合法的 SECURITY_ATTRIBUTES，其中的描述符由 `sd` 持有，
    // 在调用期间存活；CreateNamedPipeW 只在调用期间读取它们。
    unsafe { opts.create_with_security_attributes_raw(name, (&raw mut attrs).cast::<c_void>()) }
}

/// 当前进程令牌的用户 SID，例如 `S-1-5-21-…-1001`。
pub fn current_user_sid() -> io::Result<String> {
    token_user_sid(&current_process_token()?)
}

/// 当前进程是否以提升的（管理员）令牌运行。
pub fn current_process_is_elevated() -> io::Result<bool> {
    let token = current_process_token()?;
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: 令牌句柄有效且带 TOKEN_QUERY；输出缓冲区就是一个 TOKEN_ELEVATION，大小如实传入。
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw_handle() as HANDLE,
            TokenElevation,
            (&raw mut elevation).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(elevation.TokenIsElevated != 0)
}

/// 当前交互用户的 SID。
///
/// - 以 LocalSystem 运行（正式服务）时：取活动会话（优先物理控制台，其次远程桌面）的登录用户；
///   没有用户登录时返回 `None`。
/// - 以普通账户运行（控制台模式开发、测试）时：就是当前进程的用户。
pub fn interactive_user_sid() -> io::Result<Option<String>> {
    let me = current_user_sid()?;
    if me != SYSTEM_SID {
        return Ok(Some(me));
    }
    for session in active_session_ids() {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: SYSTEM 具备 SeTcbPrivilege；`token` 成功时是新句柄，立刻交给 OwnedHandle 管理。
        if unsafe { WTSQueryUserToken(session, &mut token) } == 0 {
            continue;
        }
        // SAFETY: 上面调用成功，`token` 是本进程独占的有效句柄。
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        return token_user_sid(&token).map(Some);
    }
    Ok(None)
}

/// 活动会话 id：物理控制台会话（若有）排在最前。
fn active_session_ids() -> Vec<u32> {
    // SAFETY: 无参数，返回控制台会话 id；没有时为 0xFFFFFFFF。
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    let mut ids = Vec::new();
    if console != u32::MAX {
        ids.push(console);
    }
    let mut info: *mut WTS_SESSION_INFOW = ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: 查询本机会话；`info` 由 API 分配，下面用 WTSFreeMemory 释放。
    let ok =
        unsafe { WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut info, &mut count) };
    if ok == 0 || info.is_null() {
        return ids;
    }
    // SAFETY: 调用成功时 `info` 指向 `count` 个连续的 WTS_SESSION_INFOW。
    let sessions = unsafe { std::slice::from_raw_parts(info, count as usize) };
    ids.extend(
        sessions
            .iter()
            .filter(|s| s.State == WTSActive && s.SessionId != console)
            .map(|s| s.SessionId),
    );
    // SAFETY: `info` 由 WTSEnumerateSessionsW 分配，上面的切片不再使用，只释放一次。
    unsafe { WTSFreeMemory(info.cast()) };
    ids
}

fn current_process_token() -> io::Result<OwnedHandle> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess 返回伪句柄，无需关闭；成功时 `token` 是新句柄，交给 OwnedHandle。
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 上面调用成功，`token` 是本进程独占的有效句柄。
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

/// 读取令牌的用户 SID 并转成字符串形式。
fn token_user_sid(token: &OwnedHandle) -> io::Result<String> {
    let handle = token.as_raw_handle() as HANDLE;
    let mut len = 0u32;
    // SAFETY: 第一次调用只取所需长度，缓冲区为空、长度为 0。
    unsafe { GetTokenInformation(handle, TokenUser, ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return Err(io::Error::last_os_error());
    }
    // 用 u64 数组保证 TOKEN_USER 所需的对齐。
    let mut buf = vec![0u64; (len as usize).div_ceil(size_of::<u64>())];
    // SAFETY: `buf` 至少 `len` 字节且按 8 字节对齐，足以容纳 TOKEN_USER 及其后的 SID。
    let ok = unsafe {
        GetTokenInformation(
            handle,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            len,
            &mut len,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 调用成功，缓冲区开头是一个已初始化且对齐的 TOKEN_USER。
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut text: *mut u16 = ptr::null_mut();
    // SAFETY: `user.User.Sid` 指向 `buf` 内的合法 SID；`text` 由 API 用 LocalAlloc 分配。
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 调用成功时 `text` 是以 NUL 结尾的 UTF-16 字符串；读到 NUL 为止。
    let sid = unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        from_wide(std::slice::from_raw_parts(text, len))
    };
    // SAFETY: `text` 由 ConvertSidToStringSidW 分配，只释放一次。
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::net::windows::named_pipe::ClientOptions;

    use super::*;

    const ERROR_ACCESS_DENIED: i32 = 5;

    fn unique_pipe_name() -> String {
        static N: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\ProcRoute.Test.{}.{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn elevated() -> bool {
        current_process_is_elevated().expect("query elevation")
    }

    #[test]
    fn sddl_denies_network_first_and_grants_only_the_three_principals() {
        let sddl = control_pipe_sddl(Some("S-1-5-21-1-2-3-1001"));
        assert!(sddl.starts_with("D:P(D;;GA;;;NU)"), "{sddl}");
        assert!(sddl.contains("(A;;GA;;;SY)") && sddl.contains("(A;;GA;;;BA)"));
        assert!(sddl.ends_with("(A;;GRGW;;;S-1-5-21-1-2-3-1001)"), "{sddl}");
        assert_eq!(sddl.matches("(A;").count(), 3, "{sddl}");
        assert_eq!(
            control_pipe_sddl(None),
            "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)"
        );
    }

    #[test]
    fn current_user_sid_is_well_formed() {
        let sid = current_user_sid().expect("sid");
        assert!(sid.starts_with("S-1-5-"), "{sid}");
        assert_eq!(
            interactive_user_sid().expect("interactive"),
            Some(sid),
            "a non-SYSTEM process treats itself as the interactive user"
        );
    }

    #[test]
    fn rejects_malformed_sddl() {
        assert!(SecurityDescriptor::from_sddl("not sddl").is_err());
    }

    #[tokio::test]
    async fn interactive_user_can_connect() {
        let name = unique_pipe_name();
        let me = current_user_sid().expect("sid");
        let sd = SecurityDescriptor::control_pipe(Some(&me)).expect("sd");
        let server = create_pipe_server(&name, &sd, true).expect("create pipe");
        let client = ClientOptions::new()
            .open(&name)
            .expect("authorized user connects");
        server.connect().await.expect("server accepts");
        drop(client);
    }

    #[tokio::test]
    async fn users_outside_the_acl_are_denied() {
        let name = unique_pipe_name();
        // 只放行 SYSTEM、Administrators 和 Guests：当前用户（未提升时）不在其中。
        let sd = SecurityDescriptor::control_pipe(Some("S-1-5-32-546")).expect("sd");
        let _server = create_pipe_server(&name, &sd, true).expect("create pipe");
        let result = ClientOptions::new().open(&name);
        if elevated() {
            // 提升的令牌里 Administrators 组生效，按设计应当放行。
            assert!(result.is_ok(), "administrators must be allowed");
        } else {
            let err = result.expect_err("unauthorized user must be denied");
            assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{err}");
        }
    }

    #[tokio::test]
    async fn users_outside_the_acl_cannot_add_instances() {
        let name = unique_pipe_name();
        let sd = SecurityDescriptor::control_pipe(Some("S-1-5-32-546")).expect("sd");
        let _first = create_pipe_server(&name, &sd, true).expect("create pipe");
        let second = create_pipe_server(&name, &sd, false);
        if elevated() {
            assert!(second.is_ok(), "administrators may add instances");
        } else {
            let err = second.expect_err("users outside the ACL lack FILE_CREATE_PIPE_INSTANCE");
            assert_eq!(err.raw_os_error(), Some(ERROR_ACCESS_DENIED), "{err}");
        }
    }

    #[tokio::test]
    async fn interactive_user_can_serve_several_instances() {
        // 服务端每接受一个客户端就要创建下一个实例；控制台模式下以交互用户身份运行也必须可行。
        let name = unique_pipe_name();
        let me = current_user_sid().expect("sid");
        let sd = SecurityDescriptor::control_pipe(Some(&me)).expect("sd");
        let _first = create_pipe_server(&name, &sd, true).expect("create pipe");
        create_pipe_server(&name, &sd, false).expect("second instance");
    }

    #[tokio::test]
    async fn first_instance_flag_refuses_a_squatted_name() {
        let name = unique_pipe_name();
        let open = SecurityDescriptor::from_sddl("D:P(A;;GA;;;WD)").expect("sd");
        let _squatter = create_pipe_server(&name, &open, true).expect("squat");
        let sd =
            SecurityDescriptor::control_pipe(Some(&current_user_sid().expect("sid"))).expect("sd");
        assert!(create_pipe_server(&name, &sd, true).is_err());
    }
}
