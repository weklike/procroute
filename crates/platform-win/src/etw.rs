// SPDX-License-Identifier: GPL-3.0-or-later
//! ETW 实时会话：`Microsoft-Windows-Kernel-Process` 的进程启动 / 退出事件（T-079，设计文档 6.4）。
//!
//! 只订阅 `WINEVENT_KEYWORD_PROCESS`：启动是事件 1，退出是事件 2。负载按清单模板的定长前缀解码，
//! 偏移随事件版本变化（版本 3 起在 `CreateTime` 前插入了 `ProcessSequenceNumber`），见 [`layout`]；
//! 单元测试会对照本机已安装的清单核对这张偏移表。
//!
//! - 控制实时会话需要管理员或 LocalSystem（服务以 LocalSystem 运行）；普通用户启动会得到拒绝访问。
//! - 会话名由调用方给出。服务异常退出后残留的同名会话，下次启动时先停掉再重建。
//! - 缓冲区每 [`FLUSH_MS`] 毫秒刷新一次，事件延迟在这个量级。
//! - 回调在调用 `ProcessTrace` 的专用线程上串行执行；回调里不能 panic（跨 FFI 边界会中止进程）。
#![allow(unsafe_code)] // 需要调用 StartTraceW / EnableTraceEx2 / OpenTraceW / ProcessTrace；每处都有 SAFETY 注释

use std::io;
use std::mem::{offset_of, size_of};
use std::ptr;
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE, ProcessTrace, StartTraceW,
    TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

use crate::wide::to_wide;

/// `Microsoft-Windows-Kernel-Process`。
const KERNEL_PROCESS_PROVIDER: GUID = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
/// `WINEVENT_KEYWORD_PROCESS`。
const KEYWORD_PROCESS: u64 = 0x10;
/// 事件 id：进程启动 / 退出。
const EVENT_START: u16 = 1;
const EVENT_STOP: u16 = 2;
/// evntrace.h 的 `EVENT_TRACE_USE_MS_FLUSH_TIMER`：`FlushTimer` 以毫秒计（windows-sys 未收录）。
const EVENT_TRACE_USE_MS_FLUSH_TIMER: u32 = 0x0000_0010;
/// 缓冲区刷新间隔（毫秒）。
pub const FLUSH_MS: u32 = 100;
/// 会话名的最大字符数。
const MAX_NAME: usize = 255;

/// 进程事件。`created_at` 是 FILETIME，与 [`crate::process::process_creation_time`] 同源，
/// 和 `pid` 一起构成进程身份（C-DRV-04）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessEvent {
    Started {
        pid: u32,
        parent_pid: u32,
        created_at: u64,
        session_id: u32,
    },
    Stopped {
        pid: u32,
        created_at: u64,
    },
}

/// 事件定长前缀里用到的字段偏移（`ProcessID` 恒在 0）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Layout {
    create_time: usize,
    /// 只有启动事件有。
    parent_pid: Option<usize>,
    session_id: Option<usize>,
    /// 负载至少要有的字节数（最后一个用到的字段结束处）。
    min_len: usize,
}

/// 按清单模板（`Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process`）得出的偏移。
/// 比已知版本更新的事件按最新布局解码：新版本只在模板末尾追加字段。
fn layout(id: u16, version: u8) -> Option<Layout> {
    match (id, version) {
        // ProcessID u32, CreateTime FILETIME, ParentProcessID u32, SessionID u32, ...
        (EVENT_START, 0..=2) => Some(Layout {
            create_time: 4,
            parent_pid: Some(12),
            session_id: Some(16),
            min_len: 20,
        }),
        // ProcessID u32, ProcessSequenceNumber u64, CreateTime, ParentProcessID u32,
        // ParentProcessSequenceNumber u64, SessionID u32, ...
        (EVENT_START, _) => Some(Layout {
            create_time: 12,
            parent_pid: Some(20),
            session_id: Some(32),
            min_len: 36,
        }),
        // ProcessID u32, CreateTime, ExitTime, ...
        (EVENT_STOP, 0..=1) => Some(Layout {
            create_time: 4,
            parent_pid: None,
            session_id: None,
            min_len: 12,
        }),
        // ProcessID u32, ProcessSequenceNumber u64, CreateTime, ExitTime, ...
        (EVENT_STOP, _) => Some(Layout {
            create_time: 12,
            parent_pid: None,
            session_id: None,
            min_len: 20,
        }),
        _ => None,
    }
}

/// 解码一条事件的负载。不认识的事件或负载过短时返回 `None`。
fn decode(id: u16, version: u8, data: &[u8]) -> Option<ProcessEvent> {
    let l = layout(id, version)?;
    if data.len() < l.min_len {
        return None;
    }
    let u32_at = |at: usize| {
        data.get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
    };
    let u64_at = |at: usize| {
        data.get(at..at + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    };
    let pid = u32_at(0)?;
    let created_at = u64_at(l.create_time)?;
    match (l.parent_pid, l.session_id) {
        (Some(parent), Some(session)) => Some(ProcessEvent::Started {
            pid,
            parent_pid: u32_at(parent)?,
            created_at,
            session_id: u32_at(session)?,
        }),
        _ => Some(ProcessEvent::Stopped { pid, created_at }),
    }
}

type Sink = Box<dyn FnMut(ProcessEvent) + Send>;

/// 运行中的实时会话与消费线程。丢弃即停止会话、等消费线程结束。
pub struct ProcessEventTrace {
    name: Vec<u16>,
    trace: u64,
    thread: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ProcessEventTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessEventTrace")
            .field("running", &self.is_running())
            .finish_non_exhaustive()
    }
}

impl ProcessEventTrace {
    /// 启动名为 `name` 的实时会话，事件交给 `sink`（在专用线程上调用，不能阻塞太久、不能 panic）。
    pub fn start(name: &str, sink: impl FnMut(ProcessEvent) + Send + 'static) -> io::Result<Self> {
        if name.is_empty() || name.encode_utf16().count() > MAX_NAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid ETW session name",
            ));
        }
        let mut wide = to_wide(name);
        let session = start_session(&wide)?;
        // 之后任何一步失败都要把会话停掉
        // SAFETY: 会话句柄刚由 StartTraceW 返回；提供者 GUID 是静态常量；不传额外的启用参数。
        let err = unsafe {
            EnableTraceEx2(
                session,
                &KERNEL_PROCESS_PROVIDER,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION as u8,
                KEYWORD_PROCESS,
                0,
                0,
                ptr::null(),
            )
        };
        if let Err(e) = check(err) {
            stop_session(&wide);
            return Err(e);
        }

        let context = Box::into_raw(Box::new(Box::new(sink) as Sink));
        let mut logfile = EVENT_TRACE_LOGFILEW {
            LoggerName: wide.as_mut_ptr(),
            Context: context.cast(),
            ..Default::default()
        };
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        // SAFETY: `logfile` 已按实时、EVENT_RECORD 回调方式填好；LoggerName 指向以 NUL 结尾、
        // 调用期间有效的缓冲区。
        let trace = unsafe { OpenTraceW(&mut logfile) };
        if is_invalid(trace) {
            let e = io::Error::last_os_error();
            // SAFETY: 打开失败，回调不会被调用；`context` 只在这里收回一次。
            drop(unsafe { Box::from_raw(context) });
            stop_session(&wide);
            return Err(e);
        }
        let trace = trace.Value;
        let context_addr = context as usize;
        let spawned = std::thread::Builder::new()
            .name("etw-process-events".to_owned())
            .spawn(move || {
                let handle = PROCESSTRACE_HANDLE { Value: trace };
                // SAFETY: 句柄由 OpenTraceW 返回；阻塞到会话停止或句柄被关闭为止。
                unsafe { ProcessTrace(&handle, 1, ptr::null(), ptr::null()) };
                // SAFETY: ProcessTrace 已返回，不会再有回调使用 `context`；只在这里收回一次。
                drop(unsafe { Box::from_raw(context_addr as *mut Sink) });
            });
        match spawned {
            Ok(thread) => Ok(Self {
                name: wide,
                trace,
                thread: Some(thread),
            }),
            Err(e) => {
                // SAFETY: 句柄由 OpenTraceW 返回、尚未关闭；没有线程在处理它。
                unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: trace }) };
                // SAFETY: 没有调用过 ProcessTrace，回调不会再使用 `context`。
                drop(unsafe { Box::from_raw(context_addr as *mut Sink) });
                stop_session(&wide);
                Err(e)
            }
        }
    }

    /// 消费线程还在运行。会话被外部停掉时变为 `false`，调用方应改用其他方式追踪进程。
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// 停止会话并等消费线程结束。
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        stop_session(&self.name);
        // SAFETY: 句柄由 OpenTraceW 返回，只在这里关闭一次；ProcessTrace 随之返回。
        unsafe { CloseTrace(PROCESSTRACE_HANDLE { Value: self.trace }) };
        let _ = thread.join();
    }
}

impl Drop for ProcessEventTrace {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// `EVENT_TRACE_PROPERTIES` 后面紧跟会话名的缓冲区（ETW 把会话名写在这里）。
#[repr(C)]
struct Properties {
    props: EVENT_TRACE_PROPERTIES,
    name: [u16; MAX_NAME + 1],
}

fn properties() -> Box<Properties> {
    let mut p = Box::new(Properties {
        props: EVENT_TRACE_PROPERTIES::default(),
        name: [0; MAX_NAME + 1],
    });
    p.props.Wnode.BufferSize = size_of::<Properties>() as u32;
    p.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    // 时间戳用 QPC
    p.props.Wnode.ClientContext = 1;
    p.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_USE_MS_FLUSH_TIMER;
    p.props.FlushTimer = FLUSH_MS;
    p.props.LoggerNameOffset = offset_of!(Properties, name) as u32;
    p
}

/// 启动会话；同名会话已存在（上次异常退出的残留）时先停掉再试一次。
fn start_session(name: &[u16]) -> io::Result<CONTROLTRACE_HANDLE> {
    let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
    let mut props = properties();
    // SAFETY: `name` 以 NUL 结尾；`props` 的 BufferSize 覆盖后面的会话名缓冲区，调用期间有效。
    let mut err = unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut props.props) };
    if err == ERROR_ALREADY_EXISTS {
        stop_session(name);
        props = properties();
        // SAFETY: 同上。
        err = unsafe { StartTraceW(&mut handle, name.as_ptr(), &mut props.props) };
    }
    check(err)?;
    Ok(handle)
}

/// 按名字停止会话；会话不存在时什么也不做。
fn stop_session(name: &[u16]) {
    let mut props = properties();
    // SAFETY: 句柄为 0 时按以 NUL 结尾的 `name` 查找会话；`props` 调用期间有效、可写。
    unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            &mut props.props,
            EVENT_TRACE_CONTROL_STOP,
        )
    };
}

fn check(err: WIN32_ERROR) -> io::Result<()> {
    if err == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(err as i32))
    }
}

/// `INVALID_PROCESSTRACE_HANDLE`：64 位上是全 1；32 位进程在 64 位系统上为低 32 位全 1。
fn is_invalid(h: PROCESSTRACE_HANDLE) -> bool {
    h.Value == u64::MAX || h.Value == u64::from(u32::MAX)
}

fn is_provider(g: &GUID) -> bool {
    let p = &KERNEL_PROCESS_PROVIDER;
    g.data1 == p.data1 && g.data2 == p.data2 && g.data3 == p.data3 && g.data4 == p.data4
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    // SAFETY: ETW 保证回调期间记录有效；这里只读。
    let Some(record) = (unsafe { record.as_ref() }) else {
        return;
    };
    if !is_provider(&record.EventHeader.ProviderId) {
        return;
    }
    let data: &[u8] = if record.UserData.is_null() || record.UserDataLength == 0 {
        &[]
    } else {
        // SAFETY: UserData 指向 UserDataLength 字节的负载，回调期间有效。
        unsafe {
            std::slice::from_raw_parts(
                record.UserData.cast::<u8>(),
                usize::from(record.UserDataLength),
            )
        }
    };
    let descriptor = &record.EventHeader.EventDescriptor;
    let Some(event) = decode(descriptor.Id, descriptor.Version, data) else {
        return;
    };
    let sink = record.UserContext.cast::<Sink>();
    if sink.is_null() {
        return;
    }
    // SAFETY: UserContext 是 start() 里 Box::into_raw 得到的 Sink，ProcessTrace 返回后才释放；
    // 回调都在调用 ProcessTrace 的那一个线程上串行执行，不存在别的引用。
    unsafe { (*sink)(event) };
}

#[cfg(test)]
mod tests;
