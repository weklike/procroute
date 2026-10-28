// SPDX-License-Identifier: GPL-3.0-or-later
//! sing-box 子进程守护（T-056）。
//!
//! - 只启动调用方给定的、安装目录里的 `sing-box.exe`。每次（重新）启动前按编译进来的锁文件校验
//!   SHA-256；从校验到进程创建完成，一直以「只允许读」的共享方式持有文件句柄，期间文件无法被改写、
//!   删除或替换（C-SEC-06）。
//! - 配置经标准输入（`-c stdin`）交给 sing-box：含凭据明文的配置从不落盘（C-SEC-04），
//!   每次启动由服务重新生成，也就无从手改（C-ARCH-05）。
//! - 子进程加入关闭即终止的作业对象：服务停止、崩溃或被强杀时内核一同退出（C-NET-06）。
//! - 异常退出后按 [`RestartPolicy`] 重启；1 分钟内超过 3 次即停止，并上报 [`StopReason::CrashLoop`]
//!   （C-PERF-05），由调用方决定是否进入阻断状态。
//! - sing-box 的标准输出与错误输出直接丢弃：它的日志会带上网关、目标地址等，不能进服务日志。
//!
//! 等待子进程退出是阻塞调用，放在专用 OS 线程里，不占用异步运行时（C-CODE-05）。
//! [`Supervisor::start`] 与 [`Supervisor::stop`] 同样会阻塞，异步代码应经 `spawn_blocking` 调用。
//! 状态变化通过回调通知，回调在守护线程上执行，应当很快返回。

use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procroute_platform_win::hash::{sha256_reader, to_hex};
use procroute_platform_win::job::KillOnCloseJob;
use procroute_platform_win::secret::Secret;
use thiserror::Error;

use crate::restart::{RestartBudget, RestartPolicy};

/// 不为控制台子进程创建窗口。
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// 只允许其他人读：持有期间文件不能被写入、删除或改名。
const FILE_SHARE_READ: u32 = 0x0000_0001;
/// 等待就绪时两次探测的间隔与单次连接超时。
const PROBE_INTERVAL: Duration = Duration::from_millis(50);
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_millis(200);

/// 启动内核所需的全部信息。
#[derive(Debug, Clone)]
pub struct KernelLaunch {
    /// 安装目录里的 `sing-box.exe`。
    pub exe: PathBuf,
    /// 锁文件里的 SHA-256（小写十六进制），见 [`crate::kernel_lock`]。
    pub expected_sha256: String,
    /// 完整配置，含凭据明文；每次（重新）启动都经标准输入交给 sing-box。
    pub config: Secret<String>,
    /// sing-box 的工作目录（`-D`）。
    pub working_dir: PathBuf,
    /// 控制 API 地址：首次启动时等它可以连接才算就绪。为空则进程创建后即视为就绪。
    pub ready_probe: Option<SocketAddr>,
}

/// 内核状态。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KernelState {
    Running {
        pid: u32,
    },
    /// 异常退出，等待重启；`attempt` 是当前窗口内的第几次重启。
    Restarting {
        attempt: u32,
    },
    /// 守护结束，不会再有新的状态。
    Stopped(StopReason),
}

/// 守护结束的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// 调用方要求停止。
    Requested,
    /// 1 分钟内异常退出超过重启上限（C-PERF-05）。
    CrashLoop,
    /// 重启时无法启动，例如文件被替换导致哈希不符。
    LaunchFailed(LaunchError),
}

/// 启动失败。不含配置内容。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LaunchError {
    #[error("sing-box 可执行文件的 SHA-256 与锁文件不一致")]
    HashMismatch,
    #[error("无法读取 sing-box 可执行文件：{0}")]
    Read(String),
    #[error("无法启动 sing-box：{0}")]
    Spawn(String),
    #[error("无法把 sing-box 加入作业对象：{0}")]
    Job(String),
    #[error("sing-box 启动后立即退出（退出码 {0:?}）")]
    ExitedDuringStartup(Option<i32>),
    #[error("sing-box 没有在限定时间内就绪")]
    StartupTimeout,
}

/// 运行中的守护。丢弃时终止内核但不等待守护线程；需要等待时调用 [`Supervisor::stop`]。
#[derive(Debug)]
pub struct Supervisor {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

#[derive(Debug)]
struct Shared {
    job: KillOnCloseJob,
    stopping: Mutex<bool>,
    wake: Condvar,
}

impl Supervisor {
    /// 校验并启动内核，等它就绪后开始守护。首次启动失败直接返回错误，不计入重启预算。
    ///
    /// 成功时回调先收到一次 [`KernelState::Running`]。
    pub fn start<F>(
        launch: KernelLaunch,
        policy: RestartPolicy,
        on_state: F,
    ) -> Result<Self, LaunchError>
    where
        F: Fn(KernelState) + Send + 'static,
    {
        let job = KillOnCloseJob::new().map_err(|e| LaunchError::Job(e.to_string()))?;
        let shared = Arc::new(Shared {
            job,
            stopping: Mutex::new(false),
            wake: Condvar::new(),
        });
        let mut child = spawn_verified(&launch, &shared.job)?;
        if let Err(e) = wait_ready(&mut child, launch.ready_probe, policy.startup_timeout) {
            let _ = shared.job.terminate();
            let _ = child.wait();
            return Err(e);
        }
        let thread_shared = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("sing-box-supervisor".to_owned())
            .spawn(move || {
                on_state(KernelState::Running { pid: child.id() });
                supervise(child, &launch, &policy, &thread_shared, &on_state);
            });
        match thread {
            Ok(thread) => Ok(Self {
                shared,
                thread: Some(thread),
            }),
            Err(e) => {
                // 线程没起来：终止作业，刚启动的内核随之退出
                let _ = shared.job.terminate();
                Err(LaunchError::Spawn(e.to_string()))
            }
        }
    }

    /// 停止内核并等待守护线程结束；回调最后收到 `Stopped(Requested)`。
    pub fn stop(mut self) {
        self.request_stop();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }

    fn request_stop(&self) {
        // 持锁终止作业：守护线程只在持锁且未在停止时创建新进程，所以不会漏掉刚启动的内核
        let mut stopping = lock(&self.shared.stopping);
        *stopping = true;
        let _ = self.shared.job.terminate();
        self.shared.wake.notify_all();
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.request_stop();
        }
    }
}

impl Shared {
    fn stopping(&self) -> bool {
        *lock(&self.stopping)
    }

    /// 等待 `delay`；期间收到停止请求时提前返回 `true`。
    fn sleep_unless_stopping(&self, delay: Duration) -> bool {
        let deadline = Instant::now() + delay;
        let mut stopping = lock(&self.stopping);
        while !*stopping {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            stopping = self
                .wake
                .wait_timeout(stopping, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        true
    }
}

/// 锁里只有一个布尔值，持锁方 panic 也不会让它处于不一致状态。
fn lock(m: &Mutex<bool>) -> MutexGuard<'_, bool> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// 守护线程：等子进程退出，按预算重启，直到被要求停止或预算用尽。
fn supervise(
    mut child: Child,
    launch: &KernelLaunch,
    policy: &RestartPolicy,
    shared: &Shared,
    on_state: &dyn Fn(KernelState),
) {
    let mut budget = RestartBudget::new(policy);
    let reason = loop {
        // 正常停止时作业被终止，这里同样返回
        let _ = child.wait();
        if shared.stopping() {
            break StopReason::Requested;
        }
        let Some(attempt) = budget.on_crash(Instant::now()) else {
            break StopReason::CrashLoop;
        };
        on_state(KernelState::Restarting { attempt });
        if shared.sleep_unless_stopping(policy.delay) {
            break StopReason::Requested;
        }
        let spawned = {
            let stopping = lock(&shared.stopping);
            if *stopping {
                break StopReason::Requested;
            }
            spawn_verified(launch, &shared.job)
        };
        match spawned {
            Ok(next) => {
                child = next;
                on_state(KernelState::Running { pid: child.id() });
            }
            Err(e) => break StopReason::LaunchFailed(e),
        }
    };
    on_state(KernelState::Stopped(reason));
}

/// 校验哈希后启动 sing-box、加入作业，再把配置写进它的标准输入。
fn spawn_verified(launch: &KernelLaunch, job: &KillOnCloseJob) -> Result<Child, LaunchError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&launch.exe)
        .map_err(|e| LaunchError::Read(e.to_string()))?;
    let digest = sha256_reader(&mut file).map_err(|e| LaunchError::Read(e.to_string()))?;
    if to_hex(&digest) != launch.expected_sha256 {
        return Err(LaunchError::HashMismatch);
    }
    let mut child = Command::new(&launch.exe)
        .args(["run", "-c", "stdin", "--disable-color", "-D"])
        .arg(&launch.working_dir)
        .current_dir(&launch.working_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| LaunchError::Spawn(e.to_string()))?;
    // 进程已经创建，映像文件此后由系统锁定，可以放开校验用的句柄
    drop(file);
    if let Err(e) = job.assign(&child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(LaunchError::Job(e.to_string()));
    }
    if let Some(stdin) = child.stdin.take() {
        feed_config(stdin, launch.config.clone());
    }
    Ok(child)
}

/// 在短命线程里写入配置并关闭标准输入，免得 sing-box 迟迟不读时卡住调用方。
/// 写入失败说明进程已经退出，由守护线程按退出处理。
fn feed_config(mut stdin: ChildStdin, config: Secret<String>) {
    let _ = std::thread::Builder::new()
        .name("sing-box-config".to_owned())
        .spawn(move || {
            let _ = stdin.write_all(config.expose().as_bytes());
        });
}

/// 等内核就绪：进程仍在运行，且控制 API（若给了地址）可以连接。
fn wait_ready(
    child: &mut Child,
    probe: Option<SocketAddr>,
    timeout: Duration,
) -> Result<(), LaunchError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(LaunchError::ExitedDuringStartup(status.code()));
        }
        let ready = match probe {
            None => true,
            Some(addr) => TcpStream::connect_timeout(&addr, PROBE_CONNECT_TIMEOUT).is_ok(),
        };
        if ready {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(LaunchError::StartupTimeout);
        }
        std::thread::sleep(PROBE_INTERVAL);
    }
}

#[cfg(test)]
mod tests;
