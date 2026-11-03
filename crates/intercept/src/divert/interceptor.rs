// SPDX-License-Identifier: GPL-3.0-or-later
//! WinDivert 后端：组装 SOCKET 层归属（[`SocketMonitor`]）与 NETWORK 层改道（[`NetworkWorker`]），
//! 以 [`Interceptor`] 交给 svc（C-DRV-06）。
//!
//! 目前只改道 TCP。UDP 与 53 端口的劫持随 T-091 接入；在那之前目标进程的 UDP 按 fail_policy 丢弃或放行
//! （见 [`super::network`]）。
//!
//! 启动顺序：先起 NETWORK 层，再起 SOCKET 层。两者之间发起的连接没有 SOCKET 事件，它们的第一个 SYN
//! 经暂存与连接表反查兜底归属（C-NET-04），不会漏掉。停止时先关 SOCKET 层，再关 NETWORK 层；
//! 关闭句柄即撤销过滤器，服务退出时系统关闭全部句柄（C-NET-06）。

use std::path::PathBuf;
use std::sync::Arc;

use super::ffi::WinDivert;
use super::network::{Engine, RedirectMap, Relays};
use super::socket::{Attributor, FlowTable, ProcessResolver, SocketMonitor};
use super::worker::NetworkWorker;
use crate::backend::{Counters, InterceptError, InterceptStats, Interceptor, StartContext};
use crate::exclude::ExclusionSet;

/// 后端的固定配置（会话期间不变）。
pub struct DivertConfig {
    /// 放着锁定版本 `WinDivert.dll` 与 `WinDivert64.sys` 的目录（安装目录）。
    pub dir: PathBuf,
    /// 回环中继的监听地址。
    pub relays: Relays,
    /// 把改道登记进中继的 NAT 表。
    pub map: Arc<dyn RedirectMap>,
    pub resolver: Arc<dyn ProcessResolver>,
    /// 收包线程数。
    pub receivers: usize,
}

impl std::fmt::Debug for DivertConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DivertConfig")
            .field("dir", &self.dir)
            .field("relays", &self.relays)
            .field("receivers", &self.receivers)
            .finish_non_exhaustive()
    }
}

struct Running {
    attributor: Arc<Attributor>,
    engine: Arc<Engine>,
    table: Arc<FlowTable>,
    socket: Option<SocketMonitor>,
    network: Option<NetworkWorker>,
}

impl Running {
    fn shut_down(mut self) {
        if let Some(s) = self.socket.take() {
            s.stop();
        }
        if let Some(n) = self.network.take() {
            n.stop();
        }
        self.engine.clear();
        self.table.clear();
    }
}

/// WinDivert 后端。
pub struct DivertInterceptor {
    config: DivertConfig,
    counters: Arc<Counters>,
    running: Option<Running>,
}

impl std::fmt::Debug for DivertInterceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DivertInterceptor")
            .field("config", &self.config)
            .field("active", &self.running.is_some())
            .finish_non_exhaustive()
    }
}

impl DivertInterceptor {
    pub fn new(config: DivertConfig) -> Self {
        Self {
            config,
            counters: Arc::default(),
            running: None,
        }
    }

    /// 收包或收事件的线程是否出错退出（此后目标流不再被正确处理，上层按 fail_policy 处理）。
    pub fn failure(&self) -> Option<String> {
        let r = self.running.as_ref()?;
        if let Some(e) = r.socket.as_ref().and_then(SocketMonitor::failure) {
            return Some(format!("SOCKET layer: {e}"));
        }
        if let Some(e) = r.network.as_ref().and_then(NetworkWorker::failure) {
            return Some(format!("NETWORK layer: {e}"));
        }
        None
    }

    /// 正在改道的连接数。
    pub fn active_connections(&self) -> usize {
        self.running.as_ref().map_or(0, |r| r.engine.active())
    }
}

impl Interceptor for DivertInterceptor {
    fn name(&self) -> &'static str {
        "divert"
    }

    fn start(&mut self, ctx: StartContext) -> Result<(), InterceptError> {
        if self.running.is_some() {
            return Err(InterceptError::AlreadyRunning);
        }
        let api = WinDivert::load(&self.config.dir)
            .map_err(|e| InterceptError::DriverUnavailable(e.to_string()))?;
        let table = Arc::new(FlowTable::default());
        let attributor = Arc::new(Attributor::new(
            ctx.settings,
            ctx.exclusions,
            ctx.policy,
            Arc::clone(&self.config.resolver),
            Arc::clone(&table),
            Arc::clone(&self.counters),
        ));
        let engine = Arc::new(Engine::new(
            Arc::clone(&table),
            self.config.relays,
            Arc::clone(&self.config.map),
            ctx.settings.fail_policy,
            Arc::clone(&self.counters),
            ctx.events,
        ));
        let mut running = Running {
            attributor: Arc::clone(&attributor),
            engine: Arc::clone(&engine),
            table,
            socket: None,
            network: None,
        };
        let started =
            NetworkWorker::start(&api, engine, Arc::clone(&attributor), self.config.receivers)
                .and_then(|network| {
                    running.network = Some(network);
                    SocketMonitor::start(&api, attributor)
                });
        match started {
            Ok(socket) => {
                running.socket = Some(socket);
                self.running = Some(running);
                Ok(())
            }
            Err(e) => {
                running.shut_down();
                Err(InterceptError::DriverUnavailable(e.to_string()))
            }
        }
    }

    fn stop(&mut self) -> Result<(), InterceptError> {
        let running = self.running.take().ok_or(InterceptError::NotRunning)?;
        running.shut_down();
        Ok(())
    }

    fn is_active(&self) -> bool {
        self.running.is_some()
    }

    fn update_exclusions(&mut self, exclusions: ExclusionSet) -> Result<(), InterceptError> {
        let r = self.running.as_ref().ok_or(InterceptError::NotRunning)?;
        r.attributor.set_exclusions(exclusions);
        Ok(())
    }

    fn stats(&self) -> InterceptStats {
        self.counters.snapshot()
    }
}

impl Drop for DivertInterceptor {
    fn drop(&mut self) {
        // 与 Interceptor 的约定一致：销毁即撤销全部过滤器（C-NET-06）
        if let Some(r) = self.running.take() {
            r.shut_down();
        }
    }
}
