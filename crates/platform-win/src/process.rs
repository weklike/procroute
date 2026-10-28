// SPDX-License-Identifier: GPL-3.0-or-later
//! 进程身份查询：管道客户端 PID、进程映像路径、进程用户 SID。
//!
//! 服务据此校验控制管道的客户端（C-SEC-02）并在审计日志里记录调用者 SID（C-SEC-03）。
#![allow(unsafe_code)] // 需要调用 GetNamedPipeClientProcessId / OpenProcess 等；每处都有 SAFETY 注释

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};

use crate::acl::token_user_sid;
use crate::wide::from_wide;

/// 已连接的命名管道服务端句柄对面的客户端 PID。
pub fn pipe_client_pid(pipe: &impl AsRawHandle) -> io::Result<u32> {
    let mut pid = 0u32;
    // SAFETY: 句柄由调用方的管道对象持有，调用期间有效；`pid` 是可写的 u32。
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// 进程映像的 Win32 路径，例如 `C:\Program Files\ProcRoute\procroute-ui.exe`。
pub fn process_image_path(pid: u32) -> io::Result<String> {
    let process = open_process(pid)?;
    let mut buf = vec![0u16; 1024];
    for _ in 0..2 {
        let mut len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: 进程句柄有效且带 PROCESS_QUERY_LIMITED_INFORMATION；`buf` 可写 `len` 个 u16，
        // 成功时 `len` 被改为写入的字符数（不含 NUL）。
        let ok = unsafe {
            QueryFullProcessImageNameW(
                process.as_raw_handle() as HANDLE,
                PROCESS_NAME_WIN32,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if ok != 0 {
            return Ok(from_wide(&buf[..len as usize]));
        }
        // 长路径（启用了长路径支持时可超过 1024 字符）扩容重试一次。
        buf = vec![0u16; 32 * 1024];
    }
    Err(io::Error::last_os_error())
}

/// 进程令牌的用户 SID。
pub fn process_user_sid(pid: u32) -> io::Result<String> {
    let process = open_process(pid)?;
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: 进程句柄有效；成功时 `token` 是新句柄，立刻交给 OwnedHandle 管理。
    if unsafe { OpenProcessToken(process.as_raw_handle() as HANDLE, TOKEN_QUERY, &mut token) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 上面调用成功，`token` 是本进程独占的有效句柄。
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    token_user_sid(&token)
}

fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: 只请求受限查询权限、不继承句柄；失败返回空句柄。
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `h` 是刚打开的有效句柄，所有权交给 OwnedHandle。
    Ok(unsafe { OwnedHandle::from_raw_handle(h) })
}

#[cfg(test)]
mod tests {
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

    use super::*;
    use crate::acl::current_user_sid;

    #[test]
    fn own_image_path_and_sid() {
        let me = std::process::id();
        let exe = std::env::current_exe().expect("current exe");
        assert_eq!(
            process_image_path(me).expect("image").to_lowercase(),
            exe.to_string_lossy().to_lowercase()
        );
        assert_eq!(
            process_user_sid(me).expect("sid"),
            current_user_sid().expect("sid")
        );
    }

    #[test]
    fn nonexistent_process_is_an_error() {
        // PID 必须是 4 的倍数，奇数 PID 永远不存在。
        assert!(process_image_path(3).is_err());
    }

    #[tokio::test]
    async fn pipe_client_pid_is_reported() {
        let name = format!(r"\\.\pipe\ProcRoute.Test.pid.{}", std::process::id());
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&name)
            .expect("pipe");
        let _client = ClientOptions::new().open(&name).expect("client");
        server.connect().await.expect("connect");
        assert_eq!(pipe_client_pid(&server).expect("pid"), std::process::id());
    }
}
