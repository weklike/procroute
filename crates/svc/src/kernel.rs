// SPDX-License-Identifier: GPL-3.0-or-later
//! 内核（sing-box）的启动方式。
//!
//! 正式实现是 [`SupervisedKernel`]：安装目录里的 `sing-box.exe` 经 `procroute-core-mgr` 的守护进程
//! 启动（锁文件校验、配置走标准输入、随服务退出、1 分钟 3 次重启上限，见 T-056）。
//! 会话处理只依赖 [`KernelLauncher`]，测试里换成假实现：开发机上不能真的建 TUN（C-TEST-04）。

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use procroute_core_mgr::kernel_lock::{KERNEL_FILE_NAME, LockError, locked_kernel};
use procroute_core_mgr::restart::RestartPolicy;
use procroute_core_mgr::supervisor::{KernelLaunch, KernelState, LaunchError, Supervisor};
use procroute_platform_win::secret::Secret;

/// 内核状态回调，在守护线程上执行。
pub type StateCallback = Box<dyn Fn(KernelState) + Send + 'static>;

/// 启动内核。
pub trait KernelLauncher: Send + Sync + 'static {
    /// 用给定配置启动内核并等控制 API 就绪。阻塞调用，异步代码应经 `spawn_blocking` 调用。
    fn launch(
        &self,
        config: Secret<String>,
        api: SocketAddr,
        on_state: StateCallback,
    ) -> Result<Box<dyn RunningKernel>, LaunchError>;
}

/// 运行中的内核。
pub trait RunningKernel: Send {
    /// 停止内核并等它退出。阻塞调用。
    fn stop(self: Box<Self>);
}

impl RunningKernel for Supervisor {
    fn stop(self: Box<Self>) {
        Supervisor::stop(*self);
    }
}

/// 安装目录里、按锁文件校验的 sing-box。
#[derive(Debug, Clone)]
pub struct SupervisedKernel {
    exe: PathBuf,
    sha256: String,
    working_dir: PathBuf,
}

impl SupervisedKernel {
    /// `install_dir` 是服务可执行文件所在目录（只有管理员可写，C-SEC-06）；
    /// `working_dir` 是 `<配置根>\run`。
    pub fn new(install_dir: &Path, working_dir: PathBuf) -> Result<Self, LockError> {
        Ok(Self {
            exe: install_dir.join(KERNEL_FILE_NAME),
            sha256: locked_kernel()?.sha256,
            working_dir,
        })
    }
}

impl KernelLauncher for SupervisedKernel {
    fn launch(
        &self,
        config: Secret<String>,
        api: SocketAddr,
        on_state: StateCallback,
    ) -> Result<Box<dyn RunningKernel>, LaunchError> {
        std::fs::create_dir_all(&self.working_dir)
            .map_err(|e| LaunchError::Spawn(e.to_string()))?;
        let launch = KernelLaunch {
            exe: self.exe.clone(),
            expected_sha256: self.sha256.clone(),
            config,
            working_dir: self.working_dir.clone(),
            ready_probe: Some(api),
        };
        let supervisor = Supervisor::start(launch, RestartPolicy::default(), on_state)?;
        Ok(Box::new(supervisor))
    }
}
