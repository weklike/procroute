// SPDX-License-Identifier: GPL-3.0-or-later
//! 进程追踪的运行部分：一个专用线程持有 [`ProcessTree`]，把目标集合的变化交给回调。
//!
//! - 优先用 ETW 实时进程事件（`procroute_platform_win::etw`，延迟约 100 ms），并每
//!   [`RESYNC_INTERVAL`] 用快照校正一次（事件可能丢失，队列满时立即校正）；
//! - ETW 不可用（没有管理员权限）或会话被外部停掉时，改为每 [`Options::poll_interval`] 拍一次快照；
//! - [`Watcher::start`] 返回前已在调用线程上完成第一次快照：调用方据此装好保护后再启动内核。
//!
//! 回调在追踪线程上执行，不应长时间阻塞。

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procroute_platform_win::etw::{ProcessEvent, ProcessEventTrace};
use procroute_rules::engine::RuleEngine;

use crate::snapshot;
use crate::tree::{Change, ProcessInfo, ProcessKey, ProcessTree};

/// ETW 会话名。服务异常退出后残留的同名会话会在下次启动时被替换。
pub const ETW_SESSION_NAME: &str = "ProcRoute-ProcWatch";
/// 有 ETW 时用快照校正的间隔。
pub const RESYNC_INTERVAL: Duration = Duration::from_secs(30);
/// 没有 ETW 时拍快照的默认间隔。
pub const POLL_INTERVAL: Duration = Duration::from_millis(500);
/// 事件队列长度。队列满时丢弃事件并安排一次快照校正，不阻塞 ETW 的回调线程。
const QUEUE: usize = 4096;
/// 检查 ETW 会话是否还在的间隔。
const LIVENESS_CHECK: Duration = Duration::from_secs(1);

/// 进程事件的来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    Etw,
    Polling,
}

/// 启动参数。
#[derive(Debug, Clone)]
pub struct Options {
    /// 尝试 ETW；失败时退回快照。
    pub use_etw: bool,
    pub session_name: String,
    /// 没有 ETW 时的快照间隔。
    pub poll_interval: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            use_etw: true,
            session_name: ETW_SESSION_NAME.to_owned(),
            poll_interval: POLL_INTERVAL,
        }
    }
}

enum Msg {
    Event(ProcessEvent),
    SetEngine(RuleEngine),
    Stop,
}

/// 运行中的进程追踪。丢弃即停止（含 ETW 会话）。
#[derive(Debug)]
pub struct Watcher {
    tx: SyncSender<Msg>,
    thread: Option<JoinHandle<()>>,
    source: Source,
}

impl Watcher {
    /// 启动追踪。返回前已拍完第一次快照，初始的目标进程已经交给 `on_change`。
    pub fn start(
        engine: RuleEngine,
        options: Options,
        mut on_change: impl FnMut(&[Change]) + Send + 'static,
    ) -> io::Result<Self> {
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let lost = Arc::new(AtomicBool::new(false));
        // 先开事件会话再拍快照：两者之间启动的进程不会漏掉，重复的登记会被忽略
        let trace = if options.use_etw {
            start_trace(&options.session_name, tx.clone(), lost.clone())
        } else {
            None
        };
        let source = if trace.is_some() {
            Source::Etw
        } else {
            Source::Polling
        };
        let mut tree = ProcessTree::new(engine);
        let mut out = Vec::new();
        resync(&mut tree, &mut out);
        if !out.is_empty() {
            on_change(&out);
        }
        let worker = Worker {
            rx,
            tree,
            trace,
            lost,
            poll_interval: options.poll_interval,
        };
        let thread = std::thread::Builder::new()
            .name("procwatch".to_owned())
            .spawn(move || worker.run(on_change))?;
        tracing::info!(?source, "process tracking started");
        Ok(Self {
            tx,
            thread: Some(thread),
            source,
        })
    }

    /// 启动时选定的事件来源。
    pub fn source(&self) -> Source {
        self.source
    }

    /// 换方案：重新判定全部进程，变化照常交给回调。
    pub fn set_engine(&self, engine: RuleEngine) {
        let _ = self.tx.send(Msg::SetEngine(engine));
    }

    /// 停止追踪并等线程结束。
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = self.tx.send(Msg::Stop);
            let _ = thread.join();
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct Worker {
    rx: Receiver<Msg>,
    tree: ProcessTree,
    trace: Option<ProcessEventTrace>,
    lost: Arc<AtomicBool>,
    poll_interval: Duration,
}

impl Worker {
    fn interval(&self) -> Duration {
        if self.trace.is_some() {
            RESYNC_INTERVAL
        } else {
            self.poll_interval
        }
    }

    fn run(mut self, mut on_change: impl FnMut(&[Change])) {
        let mut out = Vec::new();
        let mut next_sync = Instant::now() + self.interval();
        loop {
            let wait = next_sync
                .saturating_duration_since(Instant::now())
                .min(LIVENESS_CHECK);
            match self.rx.recv_timeout(wait) {
                Ok(Msg::Event(ProcessEvent::Started {
                    pid,
                    parent_pid,
                    created_at,
                    ..
                })) => {
                    let key = ProcessKey { pid, created_at };
                    let info = ProcessInfo {
                        key,
                        parent_pid,
                        name: String::new(),
                        path: snapshot::image_path(key),
                    };
                    self.tree.started(info, &mut out);
                }
                Ok(Msg::Event(ProcessEvent::Stopped { pid, created_at })) => {
                    self.tree.stopped(ProcessKey { pid, created_at }, &mut out);
                }
                Ok(Msg::SetEngine(engine)) => {
                    self.tree.set_engine(engine, &mut out);
                }
                Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    if self.trace.as_ref().is_some_and(|t| !t.is_running()) {
                        tracing::warn!("ETW process session ended, falling back to snapshots");
                        self.trace = None;
                        next_sync = Instant::now();
                    }
                    if Instant::now() >= next_sync {
                        resync(&mut self.tree, &mut out);
                        next_sync = Instant::now() + self.interval();
                    }
                }
            }
            if self.lost.swap(false, Ordering::Relaxed) {
                tracing::debug!("process event queue overflowed, resyncing");
                resync(&mut self.tree, &mut out);
            }
            if !out.is_empty() {
                on_change(&out);
                out.clear();
            }
        }
        // 先停 ETW 会话：之后不会再有事件进队列
        if let Some(trace) = self.trace.take() {
            trace.stop();
        }
    }
}

fn start_trace(
    name: &str,
    tx: SyncSender<Msg>,
    lost: Arc<AtomicBool>,
) -> Option<ProcessEventTrace> {
    let sink = move |e: ProcessEvent| {
        if let Err(TrySendError::Full(_)) = tx.try_send(Msg::Event(e)) {
            lost.store(true, Ordering::Relaxed);
        }
    };
    match ProcessEventTrace::start(name, sink) {
        Ok(trace) => Some(trace),
        Err(e) => {
            tracing::warn!(error = %e, "ETW process events unavailable, using snapshots");
            None
        }
    }
}

fn resync(tree: &mut ProcessTree, out: &mut Vec<Change>) {
    match snapshot::take(|k| tree.contains(k)) {
        Ok(processes) => tree.reconcile(processes, out),
        Err(e) => tracing::warn!(error = %e, "process snapshot failed"),
    }
}

#[cfg(test)]
mod tests;
