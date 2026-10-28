// SPDX-License-Identifier: GPL-3.0-or-later
//! `procroute-svc`：ProcRoute 的 Windows 服务（T-057、T-058）。
//!
//! 唯一的特权进程，也是唯一的组装点（C-ARCH-01、C-ARCH-02）。配置与日志放在
//! `%ProgramData%\ProcRoute\`，启动时设置只有 SYSTEM 与 Administrators 可访问的 DACL（C-SEC-05）。
//! 启动方式：
//!
//! - 由服务控制管理器启动（正式安装）：不带参数；
//! - `procroute-svc --console`：在控制台里前台运行，Ctrl+C 停止。只用于测试虚拟机里的联调
//!   （`cargo xtask dev`），不要在开发机上以管理员身份运行（AGENTS 第 8 节第 5 条）。
#![forbid(unsafe_code)]

#[cfg(all(feature = "insecure-skip-client-auth", not(debug_assertions)))]
compile_error!(
    "feature `insecure-skip-client-auth` is only allowed in debug builds (C-SEC-02); \
     release builds must verify pipe clients"
);

#[cfg(windows)]
mod client_auth;
#[cfg(windows)]
mod handlers;
#[cfg(windows)]
mod ipc_server;
#[cfg(windows)]
mod store;

#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    eprintln!("procroute-svc only runs on Windows");
    std::process::ExitCode::FAILURE
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows_main::run()
}

#[cfg(windows)]
mod windows_main {
    use std::fs::{File, OpenOptions};
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::Receiver;
    use std::sync::{Arc, Mutex};

    use anyhow::Context;
    use procroute_platform_win::acl::{CONTROL_PIPE_NAME, SYSTEM_SID};
    use procroute_platform_win::dir_acl::{
        ADMINISTRATORS_SID, CONFIG_DIR_SDDL, config_root, secure_directory,
    };
    use procroute_platform_win::service::{
        ServiceControl, ServiceState, ServiceStatusHandle, run_service_dispatcher,
    };
    use tokio::sync::watch;

    use crate::client_auth::ClientAuth;
    use crate::handlers::Services;
    use crate::ipc_server::{ServerConfig, serve};
    use crate::store::ProfileStore;

    /// 服务名，与安装器注册时一致。
    const SERVICE_NAME: &str = "ProcRoute";

    pub fn run() -> anyhow::Result<()> {
        if std::env::args().skip(1).any(|a| a == "--console") {
            init_logging(LogTarget::Stderr)?;
            return run_console();
        }
        run_service_dispatcher(SERVICE_NAME, service_main).context(
            "not started by the service control manager (use --console for a foreground run)",
        )
    }

    enum LogTarget {
        Stderr,
        File(File),
    }

    fn init_logging(target: LogTarget) -> anyhow::Result<()> {
        let filter = tracing_subscriber::EnvFilter::try_from_env("PROCROUTE_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let builder = tracing_subscriber::fmt().with_env_filter(filter);
        let result = match target {
            LogTarget::Stderr => builder.with_writer(std::io::stderr).try_init(),
            LogTarget::File(f) => builder
                .with_ansi(false)
                .with_writer(Mutex::new(f))
                .try_init(),
        };
        result.map_err(|e| anyhow::anyhow!("cannot install the log subscriber: {e}"))
    }

    /// 创建（或沿用）配置根目录并设置受保护的 DACL（C-SEC-05），子目录继承它。
    fn prepare_config_root() -> anyhow::Result<PathBuf> {
        let root = config_root()?;
        secure_directory(&root, CONFIG_DIR_SDDL, &[SYSTEM_SID, ADMINISTRATORS_SID])
            .with_context(|| format!("cannot secure {}", root.display()))?;
        Ok(root)
    }

    fn open_log_file(root: &Path) -> anyhow::Result<File> {
        let dir = root.join("logs");
        std::fs::create_dir_all(&dir)?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("svc.log"))
            .context("open svc.log")
    }

    fn services(root: &Path) -> anyhow::Result<Arc<Services>> {
        let profiles = ProfileStore::open(root.join("profiles")).context("open profile store")?;
        Ok(Arc::new(Services::new(profiles)))
    }

    fn server_config() -> ServerConfig {
        ServerConfig {
            pipe_name: CONTROL_PIPE_NAME.to_owned(),
            client_auth: client_auth(),
        }
    }

    #[cfg(feature = "insecure-skip-client-auth")]
    fn client_auth() -> ClientAuth {
        tracing::warn!("pipe client verification is DISABLED (debug build feature)");
        ClientAuth::Disabled
    }

    #[cfg(not(feature = "insecure-skip-client-auth"))]
    fn client_auth() -> ClientAuth {
        ClientAuth::for_current_service()
    }

    /// 控制台模式：需要管理员终端（配置目录归 Administrators 所有），只在测试虚拟机里使用。
    fn run_console() -> anyhow::Result<()> {
        let root = prepare_config_root()?;
        let services = services(&root)?;
        let rt = tokio::runtime::Runtime::new().context("start tokio runtime")?;
        rt.block_on(async {
            let (tx, rx) = watch::channel(false);
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("ctrl+c received, stopping");
                }
                let _ = tx.send(true);
            });
            serve(server_config(), services, rx).await
        })?;
        Ok(())
    }

    fn service_main(status: ServiceStatusHandle, controls: Receiver<ServiceControl>) {
        let exit_code = match run_as_service(&status, controls) {
            Ok(()) => 0,
            Err(e) => {
                // 日志还没初始化时这条会被丢弃，退出码仍会报给服务控制管理器。
                tracing::error!(error = %format!("{e:#}"), "service stopped with an error");
                1
            }
        };
        let _ = status.report(ServiceState::Stopped, exit_code);
    }

    fn run_as_service(
        status: &ServiceStatusHandle,
        controls: Receiver<ServiceControl>,
    ) -> anyhow::Result<()> {
        let root = prepare_config_root()?;
        init_logging(LogTarget::File(open_log_file(&root)?))?;
        let services = services(&root)?;
        let rt = tokio::runtime::Runtime::new().context("start tokio runtime")?;
        let (tx, rx) = watch::channel(false);
        // 控制请求来自分派器线程上的同步 channel，转交给异步侧。
        std::thread::spawn(move || {
            if let Ok(control) = controls.recv() {
                tracing::info!(?control, "service control received");
            }
            let _ = tx.send(true);
        });
        status.report(ServiceState::Running, 0)?;
        let result = rt.block_on(serve(server_config(), services, rx));
        let _ = status.report(ServiceState::StopPending, 0);
        result.context("control pipe server failed")
    }
}
