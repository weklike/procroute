// SPDX-License-Identifier: GPL-3.0-or-later
//! `procroute-svc`：ProcRoute 的 Windows 服务（T-057、T-058）。
//!
//! 唯一的特权进程，也是唯一的组装点（C-ARCH-01、C-ARCH-02）。配置与日志放在
//! `%ProgramData%\ProcRoute\`，启动时设置只有 SYSTEM 与 Administrators 可访问的 DACL（C-SEC-05），
//! 随后从令牌中移除用不到的特权（C-SEC-06）。sing-box 从服务所在的安装目录启动（T-056）。
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
mod events;
#[cfg(windows)]
mod handlers;
#[cfg(windows)]
mod ipc_server;
#[cfg(windows)]
mod kernel;
#[cfg(windows)]
mod log_stream;
#[cfg(windows)]
mod node_store;
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
    use procroute_core_mgr::kernel_lock::KERNEL_FILE_NAME;
    use procroute_platform_win::acl::{CONTROL_PIPE_NAME, SYSTEM_SID};
    use procroute_platform_win::dir_acl::{
        ADMINISTRATORS_SID, CONFIG_DIR_SDDL, config_root, secure_directory,
    };
    use procroute_platform_win::privileges::retain_privileges;
    use procroute_platform_win::service::{
        ServiceControl, ServiceState, ServiceStatusHandle, run_service_dispatcher,
    };
    use tokio::sync::{broadcast, watch};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    use crate::client_auth::ClientAuth;
    use crate::events::{STREAM_CAPACITY, StreamEvent};
    use crate::handlers::Services;
    use crate::ipc_server::{ServerConfig, serve};
    use crate::kernel::SupervisedKernel;
    use crate::log_stream::BroadcastLayer;
    use crate::node_store::NodeStore;
    use crate::store::ProfileStore;

    /// 服务名，与安装器注册时一致。
    const SERVICE_NAME: &str = "ProcRoute";

    /// 界面的可执行文件名，与服务放在同一安装目录。
    const UI_FILE_NAME: &str = "procroute-ui.exe";

    /// 启动后保留的令牌特权，其余全部移除（C-SEC-06）：
    /// - `SeTcbPrivilege`：`WTSQueryUserToken` 取交互用户，用于控制管道的 DACL（C-SEC-01）；
    /// - `SeLoadDriverPrivilege`：sing-box 安装 wintun、以后打开 WinDivert 时加载驱动；
    /// - `SeChangeNotifyPrivilege`：跳过遍历检查，所有令牌默认都有；
    /// - `SeCreateGlobalPrivilege`：控制台模式（不在会话 0）下创建全局命名对象。
    const RETAINED_PRIVILEGES: [&str; 4] = [
        "SeTcbPrivilege",
        "SeLoadDriverPrivilege",
        "SeChangeNotifyPrivilege",
        "SeCreateGlobalPrivilege",
    ];

    pub fn run() -> anyhow::Result<()> {
        if std::env::args().skip(1).any(|a| a == "--console") {
            let stream = broadcast::channel(STREAM_CAPACITY).0;
            init_logging(LogTarget::Stderr, stream.clone())?;
            return run_console(stream);
        }
        run_service_dispatcher(SERVICE_NAME, service_main).context(
            "not started by the service control manager (use --console for a foreground run)",
        )
    }

    enum LogTarget {
        Stderr,
        File(File),
    }

    /// 日志写到控制台或文件，同时转发给订阅了 `log.subscribe` 的界面。
    fn init_logging(
        target: LogTarget,
        stream: broadcast::Sender<StreamEvent>,
    ) -> anyhow::Result<()> {
        let filter = tracing_subscriber::EnvFilter::try_from_env("PROCROUTE_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let output = match target {
            LogTarget::Stderr => tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .boxed(),
            LogTarget::File(f) => tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(Mutex::new(f))
                .boxed(),
        };
        tracing_subscriber::registry()
            .with(filter)
            .with(output)
            .with(BroadcastLayer::new(stream))
            .try_init()
            .map_err(|e| anyhow::anyhow!("cannot install the log subscriber: {e}"))
    }

    /// 移除白名单以外的令牌特权。失败只记录、不阻止启动：令牌保持原样只是少一层加固。
    fn drop_privileges() {
        match retain_privileges(&RETAINED_PRIVILEGES) {
            Ok(removed) => tracing::info!(removed = removed.len(), "token privileges narrowed"),
            Err(e) => tracing::error!(error = %e, "cannot narrow token privileges"),
        }
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

    fn services(
        root: &Path,
        stream: broadcast::Sender<StreamEvent>,
    ) -> anyhow::Result<Arc<Services>> {
        let profiles = ProfileStore::open(root.join("profiles")).context("open profile store")?;
        let nodes = NodeStore::open(root.join("nodes.json")).context("open node store")?;
        let exe = std::env::current_exe().context("locate the service executable")?;
        let install_dir = exe
            .parent()
            .context("the service executable has no parent directory")?;
        let launcher = SupervisedKernel::new(install_dir, root.join("run"))
            .context("read the embedded sing-box lock")?;
        tracing::debug!(kernel = %install_dir.join(KERNEL_FILE_NAME).display(), "kernel location");
        let self_exe_paths = vec![
            exe.to_string_lossy().into_owned(),
            install_dir
                .join(UI_FILE_NAME)
                .to_string_lossy()
                .into_owned(),
        ];
        Ok(Arc::new(Services::new(
            profiles,
            nodes,
            stream,
            Arc::new(launcher),
            self_exe_paths,
        )))
    }

    /// 运行管道服务端直到收到停止信号，然后停止会话。
    async fn serve_until(
        services: Arc<Services>,
        shutdown: watch::Receiver<bool>,
    ) -> std::io::Result<()> {
        let result = serve(server_config(), services.clone(), shutdown).await;
        services.shutdown().await;
        result
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
    fn run_console(stream: broadcast::Sender<StreamEvent>) -> anyhow::Result<()> {
        let root = prepare_config_root()?;
        drop_privileges();
        let services = services(&root, stream)?;
        let rt = tokio::runtime::Runtime::new().context("start tokio runtime")?;
        rt.block_on(async {
            let (tx, rx) = watch::channel(false);
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("ctrl+c received, stopping");
                }
                let _ = tx.send(true);
            });
            serve_until(services, rx).await
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
        let stream = broadcast::channel(STREAM_CAPACITY).0;
        init_logging(LogTarget::File(open_log_file(&root)?), stream.clone())?;
        drop_privileges();
        let services = services(&root, stream)?;
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
        let result = rt.block_on(serve_until(services, rx));
        let _ = status.report(ServiceState::StopPending, 0);
        result.context("control pipe server failed")
    }
}
