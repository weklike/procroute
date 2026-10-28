// SPDX-License-Identifier: GPL-3.0-or-later
//! `procroute-svc`：ProcRoute 的 Windows 服务（T-057）。
//!
//! 唯一的特权进程，也是唯一的组装点（C-ARCH-01、C-ARCH-02）。启动方式：
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
mod ipc_server;

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
    use std::sync::Arc;
    use std::sync::mpsc::Receiver;

    use anyhow::Context;
    use procroute_platform_win::acl::CONTROL_PIPE_NAME;
    use procroute_platform_win::service::{
        ServiceControl, ServiceState, ServiceStatusHandle, run_service_dispatcher,
    };
    use procroute_proto::Empty;
    use procroute_proto::error::{ErrorCode, IpcError};
    use procroute_proto::session::{ComponentState, ComponentStatus, SessionStatus};
    use serde_json::Value;
    use tokio::sync::watch;

    use crate::client_auth::ClientAuth;
    use crate::ipc_server::{Call, Handler, ServerConfig, parse_params, serve};

    /// 服务名，与安装器注册时一致。
    const SERVICE_NAME: &str = "ProcRoute";

    pub fn run() -> anyhow::Result<()> {
        init_logging();
        if std::env::args().skip(1).any(|a| a == "--console") {
            return run_console();
        }
        run_service_dispatcher(SERVICE_NAME, service_main).context(
            "not started by the service control manager (use --console for a foreground run)",
        )
    }

    fn init_logging() {
        // 服务模式下 stderr 没有去处；落盘日志随配置目录（%ProgramData%\ProcRoute\，C-SEC-05）一起在 T-058 接入。
        let filter = tracing_subscriber::EnvFilter::try_from_env("PROCROUTE_LOG")
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
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

    fn run_console() -> anyhow::Result<()> {
        let rt = tokio::runtime::Runtime::new().context("start tokio runtime")?;
        rt.block_on(async {
            let (tx, rx) = watch::channel(false);
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    tracing::info!("ctrl+c received, stopping");
                }
                let _ = tx.send(true);
            });
            serve(server_config(), Arc::new(Bootstrap), rx).await
        })?;
        Ok(())
    }

    fn service_main(status: ServiceStatusHandle, controls: Receiver<ServiceControl>) {
        let exit_code = match run_as_service(&status, controls) {
            Ok(()) => 0,
            Err(e) => {
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
        let result = rt.block_on(serve(server_config(), Arc::new(Bootstrap), rx));
        let _ = status.report(ServiceState::StopPending, 0);
        result.context("control pipe server failed")
    }

    /// 在 T-058 接上各领域的处理函数之前，只如实回答 `session.status`：服务在运行，
    /// 驱动与内核都未启动。其他方法一律返回错误，不假装成功。
    struct Bootstrap;

    impl Handler for Bootstrap {
        async fn handle(&self, call: Call<'_>) -> Result<Value, IpcError> {
            match call.method.name {
                "session.status" => {
                    let Empty {} = parse_params(call.params)?;
                    let status = SessionStatus {
                        components: ComponentStatus {
                            service: ComponentState::Active,
                            ..ComponentStatus::default()
                        },
                        ..SessionStatus::default()
                    };
                    serde_json::to_value(status)
                        .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
                }
                other => {
                    tracing::debug!(
                        method = other,
                        pid = call.caller.pid,
                        "method not wired yet"
                    );
                    Err(IpcError::new(
                        ErrorCode::Internal,
                        "method is not available in this build yet",
                    ))
                }
            }
        }
    }
}
