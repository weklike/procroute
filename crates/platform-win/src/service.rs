// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows 服务入口：服务控制分派器与状态上报。
//!
//! 只负责「作为服务运行」这一半；服务的注册、删除由安装器负责（T-110）。
//! 注册或启动服务的测试只能在虚拟机里跑（C-TEST-04），这里的单测只覆盖不需要 SCM 的部分。
#![allow(unsafe_code)] // 需要调用 StartServiceCtrlDispatcherW 等；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::io;
use std::ptr;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};

use crate::wide::to_wide;

/// 服务控制管理器发来的、需要服务响应的请求。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceControl {
    Stop,
    Shutdown,
}

/// 上报给服务控制管理器的状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    StartPending,
    Running,
    StopPending,
    Stopped,
}

/// 挂起状态的等待提示：3 秒，与「停止后 3 秒内撤销全部过滤器」一致（C-NET-06）。
const PENDING_WAIT_HINT_MS: u32 = 3000;

/// 服务的主函数：拿到状态句柄和控制请求的接收端，返回即视为服务结束。
pub type ServiceMain = fn(ServiceStatusHandle, Receiver<ServiceControl>);

struct Registration {
    name: Vec<u16>,
    main: ServiceMain,
}

static REGISTRATION: OnceLock<Registration> = OnceLock::new();

/// 状态上报句柄。
#[derive(Debug)]
pub struct ServiceStatusHandle {
    handle: SERVICE_STATUS_HANDLE,
    checkpoint: AtomicU32,
}

// SAFETY: SERVICE_STATUS_HANDLE 只是一个不透明的值，文档允许在任意线程调用 SetServiceStatus。
unsafe impl Send for ServiceStatusHandle {}
// SAFETY: 同上；内部可变状态只有原子计数器。
unsafe impl Sync for ServiceStatusHandle {}

impl ServiceStatusHandle {
    /// 上报状态。`exit_code` 只在 [`ServiceState::Stopped`] 时有意义（0 表示正常）。
    pub fn report(&self, state: ServiceState, exit_code: u32) -> io::Result<()> {
        let (current, accepted, pending) = match state {
            ServiceState::StartPending => (SERVICE_START_PENDING, 0, true),
            ServiceState::Running => (
                SERVICE_RUNNING,
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
                false,
            ),
            ServiceState::StopPending => (SERVICE_STOP_PENDING, 0, true),
            ServiceState::Stopped => (SERVICE_STOPPED, 0, false),
        };
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: current,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: exit_code,
            dwServiceSpecificExitCode: 0,
            dwCheckPoint: if pending {
                self.checkpoint.fetch_add(1, Ordering::Relaxed) + 1
            } else {
                0
            },
            dwWaitHint: if pending { PENDING_WAIT_HINT_MS } else { 0 },
        };
        // SAFETY: 句柄来自 RegisterServiceCtrlHandlerExW；`status` 在调用期间有效。
        if unsafe { SetServiceStatus(self.handle, &status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// 把当前线程交给服务控制管理器，直到服务停止。
///
/// 不是由服务控制管理器启动时（例如在控制台直接运行）返回
/// `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`（1063）。每个进程只能调用一次。
pub fn run_service_dispatcher(name: &str, main: ServiceMain) -> io::Result<()> {
    REGISTRATION
        .set(Registration {
            name: to_wide(name),
            main,
        })
        .map_err(|_| io::Error::new(io::ErrorKind::AlreadyExists, "dispatcher already started"))?;
    let Some(reg) = REGISTRATION.get() else {
        return Err(io::Error::other("service registration missing"));
    };
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: reg.name.as_ptr().cast_mut(),
            lpServiceProc: Some(ffi_service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: 表以全空项结尾；服务名存放在静态的 REGISTRATION 中，在整个进程生命周期有效，
    // 分派器只读不写它。
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// 服务控制管理器在新线程上调用的服务主函数。
unsafe extern "system" fn ffi_service_main(_argc: u32, _argv: *mut *mut u16) {
    let Some(reg) = REGISTRATION.get() else {
        return;
    };
    let (tx, rx) = channel::<ServiceControl>();
    // 控制处理函数可能一直被调用到进程退出，上下文因此有意泄漏（每个进程只有这一份）。
    let ctx: *mut Sender<ServiceControl> = Box::into_raw(Box::new(tx));
    // SAFETY: 服务名是静态存储的 NUL 结尾宽字符串；`ctx` 在进程生命周期内有效，
    // 只会被下面的处理函数以共享引用读取。
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(reg.name.as_ptr(), Some(ffi_control_handler), ctx.cast())
    };
    if handle.is_null() {
        return;
    }
    let status = ServiceStatusHandle {
        handle,
        checkpoint: AtomicU32::new(0),
    };
    // 失败时服务控制管理器会按超时处理，这里没有更好的上报途径。
    let _ = status.report(ServiceState::StartPending, 0);
    (reg.main)(status, rx);
}

/// 服务控制处理函数，在分派器线程上调用。
unsafe extern "system" fn ffi_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    ctx: *mut c_void,
) -> u32 {
    let request = match control {
        SERVICE_CONTROL_STOP => ServiceControl::Stop,
        SERVICE_CONTROL_SHUTDOWN => ServiceControl::Shutdown,
        SERVICE_CONTROL_INTERROGATE => return NO_ERROR,
        _ => return ERROR_CALL_NOT_IMPLEMENTED,
    };
    // SAFETY: `ctx` 是 ffi_service_main 泄漏的 Box<Sender>，永不释放；Sender 是 Sync，共享引用安全。
    let tx = unsafe { &*ctx.cast::<Sender<ServiceControl>>() };
    // 服务主函数已经返回时接收端不存在，忽略即可。
    let _ = tx.send(request);
    NO_ERROR
}

#[cfg(test)]
mod tests {
    use super::*;

    const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;

    fn noop(_: ServiceStatusHandle, _: Receiver<ServiceControl>) {}

    #[test]
    fn dispatcher_outside_the_scm_fails_cleanly_and_only_once() {
        let err = run_service_dispatcher("ProcRouteTest", noop).expect_err("not under the SCM");
        assert_eq!(
            err.raw_os_error(),
            Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT),
            "{err}"
        );
        let again = run_service_dispatcher("ProcRouteTest", noop).expect_err("second call");
        assert_eq!(again.kind(), io::ErrorKind::AlreadyExists);
    }
}
