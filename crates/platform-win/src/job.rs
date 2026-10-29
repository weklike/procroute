// SPDX-License-Identifier: GPL-3.0-or-later
//! 关闭即终止的作业对象：把子进程绑定到服务的生命周期（T-056，C-NET-06）。
//!
//! 服务正常停止、崩溃或被强杀时，系统都会关闭服务持有的作业句柄，作业里的进程随之被终止。
//! sing-box 因此不会比服务活得更久：TUN 模式下它一退出，TUN 网卡与路由就随之撤销。
#![allow(unsafe_code)] // 需要调用 CreateJobObjectW / SetInformationJobObject 等；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::io;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};

/// 作业被 [`KillOnCloseJob::terminate`] 终止时，作业内进程的退出码。
pub const TERMINATED_EXIT_CODE: u32 = 1;

/// 匿名作业对象：句柄关闭（包括本进程退出）时终止其中的全部进程。
#[derive(Debug)]
pub struct KillOnCloseJob {
    handle: OwnedHandle,
}

impl KillOnCloseJob {
    pub fn new() -> io::Result<Self> {
        // SAFETY: 两个参数都可以为空：默认安全属性、匿名作业。成功时返回本进程独占的新句柄。
        let raw = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: 上面调用成功，`raw` 是有效且无人持有的句柄。
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        // SAFETY: JOBOBJECT_EXTENDED_LIMIT_INFORMATION 是纯数据结构，全零是合法值（不设任何限制）。
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: 句柄有效；输入缓冲区就是一个 JOBOBJECT_EXTENDED_LIMIT_INFORMATION，大小如实传入。
        let ok = unsafe {
            SetInformationJobObject(
                handle.as_raw_handle() as HANDLE,
                JobObjectExtendedLimitInformation,
                (&raw const info).cast::<c_void>(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    /// 把进程加入作业。进程已经退出时可能失败，调用方应再检查一次进程是否还在运行。
    pub fn assign(&self, process: &impl AsHandle) -> io::Result<()> {
        // SAFETY: 两个句柄都由安全类型持有，调用期间有效。
        let ok = unsafe {
            AssignProcessToJobObject(
                self.handle.as_raw_handle() as HANDLE,
                process.as_handle().as_raw_handle() as HANDLE,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// 立即终止作业里的全部进程；作业本身仍可继续使用。
    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: 句柄有效且带 JOB_OBJECT_TERMINATE（创建者拥有全部访问权）。
        let ok = unsafe {
            TerminateJobObject(self.handle.as_raw_handle() as HANDLE, TERMINATED_EXIT_CODE)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// 作业里仍在运行的进程数。
    pub fn active_processes(&self) -> io::Result<u32> {
        // SAFETY: 纯数据结构，全零合法；下面由系统填写。
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: 句柄有效且带 JOB_OBJECT_QUERY；输出缓冲区大小如实传入，返回长度可以为空。
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle.as_raw_handle() as HANDLE,
                JobObjectBasicAccountingInformation,
                (&raw mut info).cast::<c_void>(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(info.ActiveProcesses)
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    /// 一个一直运行到被终止的进程：cmd 在等待标准输入，测试持有输入端不关闭。
    fn idle_child() -> Child {
        Command::new("cmd.exe")
            .arg("/q")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn cmd.exe")
    }

    fn wait_exit(child: &mut Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status;
            }
            assert!(Instant::now() < deadline, "child did not exit");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn dropping_the_job_kills_its_processes() {
        let job = KillOnCloseJob::new().expect("job");
        let mut child = idle_child();
        job.assign(&child).expect("assign");
        assert_eq!(job.active_processes().expect("query"), 1);
        assert!(child.try_wait().expect("try_wait").is_none());
        drop(job);
        wait_exit(&mut child);
    }

    #[test]
    fn terminate_kills_processes_and_the_job_stays_usable() {
        let job = KillOnCloseJob::new().expect("job");
        let mut first = idle_child();
        job.assign(&first).expect("assign");
        job.terminate().expect("terminate");
        let status = wait_exit(&mut first);
        assert_eq!(status.code(), Some(TERMINATED_EXIT_CODE as i32));

        let mut second = idle_child();
        job.assign(&second).expect("assign again");
        assert_eq!(job.active_processes().expect("query"), 1);
        drop(job);
        wait_exit(&mut second);
    }

    #[test]
    fn processes_outside_the_job_are_untouched() {
        let job = KillOnCloseJob::new().expect("job");
        let mut outside = idle_child();
        job.terminate().expect("terminate empty job");
        drop(job);
        std::thread::sleep(Duration::from_millis(100));
        assert!(outside.try_wait().expect("try_wait").is_none());
        outside.kill().expect("kill");
        wait_exit(&mut outside);
    }
}
