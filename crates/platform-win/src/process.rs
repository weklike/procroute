// SPDX-License-Identifier: GPL-3.0-or-later
//! 进程身份查询：管道客户端 PID、进程映像路径、进程用户 SID、所在会话，以及进程快照。
//!
//! 服务据此校验控制管道的客户端（C-SEC-02）、在审计日志里记录调用者 SID（C-SEC-03），
//! 并为界面列出运行中的进程（`process.list`）。
#![allow(unsafe_code)] // 需要调用 GetNamedPipeClientProcessId / OpenProcess / Toolhelp 等；每处都有 SAFETY 注释

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
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

/// 进程所在的 Windows 会话（终端服务会话）id。
pub fn process_session_id(pid: u32) -> io::Result<u32> {
    let mut session = 0u32;
    // SAFETY: 只读查询；`session` 是可写的 u32。
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

/// 进程快照里的一项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    /// 可执行文件名，例如 `MyGame.exe`（不含路径）。
    pub name: String,
}

/// 当前运行的全部进程（Toolhelp 快照）。完整路径另用 [`process_image_path`] 查询。
pub fn list_processes() -> io::Result<Vec<ProcessEntry>> {
    // SAFETY: 快照全部进程时进程 id 参数被忽略；失败返回 INVALID_HANDLE_VALUE。
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: 上面调用成功，`raw` 是本进程独占的有效句柄，所有权交给 OwnedHandle。
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let handle = snapshot.as_raw_handle() as HANDLE;
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut out = Vec::new();
    // SAFETY: 快照句柄有效；`entry` 的 dwSize 已按结构体大小设置，可写。
    let mut ok = unsafe { Process32FirstW(handle, &mut entry) };
    while ok != 0 {
        out.push(ProcessEntry {
            pid: entry.th32ProcessID,
            parent_pid: entry.th32ParentProcessID,
            name: from_wide(&entry.szExeFile),
        });
        // SAFETY: 同上；每次调用覆盖 `entry`。
        ok = unsafe { Process32NextW(handle, &mut entry) };
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
        Ok(out)
    } else {
        Err(err)
    }
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
        assert!(process_session_id(3).is_err());
    }

    #[test]
    fn snapshot_lists_this_process_and_its_parent() {
        let me = std::process::id();
        let all = list_processes().expect("snapshot");
        let entry = all.iter().find(|p| p.pid == me).expect("this process");
        let exe = std::env::current_exe().expect("current exe");
        let file = exe.file_name().expect("file name").to_string_lossy();
        assert!(entry.name.eq_ignore_ascii_case(&file), "{entry:?}");
        assert_ne!(entry.parent_pid, 0);
        assert!(
            all.len() > 2,
            "a running system has more than two processes"
        );
    }

    #[test]
    fn this_process_runs_in_an_interactive_or_service_session() {
        let me = std::process::id();
        let session = process_session_id(me).expect("session");
        // 父进程（测试运行器）与本进程在同一会话
        let parent = list_processes()
            .expect("snapshot")
            .into_iter()
            .find(|p| p.pid == me)
            .expect("this process")
            .parent_pid;
        if let Ok(parent_session) = process_session_id(parent) {
            assert_eq!(parent_session, session);
        }
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
