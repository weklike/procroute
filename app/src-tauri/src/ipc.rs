// SPDX-License-Identifier: GPL-3.0-or-later
//! 到服务控制管道的客户端（`\\.\pipe\ProcRoute.Control`）。
//!
//! 一条长连接、一行一条 JSON-RPC 2.0 消息，与 `procroute-svc` 的 `ipc_server` 对应：
//!
//! - 连接建立后先发 `ipc.hello` 比对协议版本（C-ARCH-07），不一致的错误原样交给界面；
//! - 请求按 `id` 与响应配对；没有 `id` 的消息是服务推送的通知（`session.status`、`conn.subscribe`、
//!   `log.subscribe`），转给 [`Sink`]，由外壳发成前端事件；
//! - 连接断开后，后台每隔 [`RECONNECT_INTERVAL`] 重连一次；重连成功后重放界面调用过的
//!   `*.subscribe`，界面不必关心连接换过；
//! - 请求在发出前按 `procroute_proto` 的方法表与 1 MiB 上限检查一遍（C-SEC-03），服务端仍会再查。
//!
//! 界面里只有这里接触管道；前端经 `ipc_call` 命令进来，组件不直接调用（C-CODE-09）。

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use procroute_proto::IPC_PROTOCOL_VERSION;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::methods::{self, EVENT_CHANNELS};
use procroute_proto::rpc::{
    HelloParams, MAX_MESSAGE_BYTES, RpcErrorObject, RpcNotification, RpcRequest,
};
use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::sync::{Notify, oneshot};

/// 服务的控制管道名（C-SEC-01）。
pub const PIPE_NAME: &str = r"\\.\pipe\ProcRoute.Control";

/// 断开后两次重连之间的间隔。
pub const RECONNECT_INTERVAL: Duration = Duration::from_secs(2);

/// 单个请求的最长等待：启动会话要等内核就绪，留足余量。
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// 管道实例都在忙时的重试。
const BUSY_RETRY: Duration = Duration::from_millis(50);
const BUSY_ATTEMPTS: u32 = 40;

/// 服务发来的单条消息上限。请求受 1 MiB 限制；响应（例如几千个节点的列表）可以更大，但不能无限大。
const MAX_INCOMING_BYTES: u64 = 8 * 1024 * 1024;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;

/// 由界面调用、需要在重连后重放的订阅方法。
const SUBSCRIBE_METHODS: [&str; 2] = ["conn.subscribe", "log.subscribe"];

/// 交给外壳转发的消息。
#[derive(Debug, Clone, PartialEq)]
pub enum Outbound {
    /// 服务推送的通知；`channel` 是 `procroute_proto::methods::EVENT_CHANNELS` 之一。
    Notification { channel: String, payload: Value },
    /// 与服务的连接建立（`true`）或断开（`false`）。
    Connection(bool),
}

/// 消息的去处。在读线程上调用，应当很快返回。
pub type Sink = Arc<dyn Fn(Outbound) + Send + Sync>;

/// 调用失败。序列化后交给前端：服务的结构化错误原样传递，其余是字符串，前端统一显示为
/// `ipc.transport`（见 `app/src/api/client.ts`）。
#[derive(Debug, Clone, PartialEq, Serialize, thiserror::Error)]
#[serde(untagged)]
pub enum CallError {
    #[error("{0}")]
    Service(IpcError),
    #[error("{0}")]
    Transport(String),
}

impl CallError {
    fn transport(what: &str, e: impl std::fmt::Display) -> Self {
        Self::Transport(format!("{what}: {e}"))
    }
}

type Reply = Result<Value, CallError>;

/// 控制管道客户端。克隆 `Arc` 后可在多个任务里并发调用。
pub struct Client {
    pipe_name: String,
    sink: Sink,
    /// 当前连接；建立连接的过程也持有这把锁，避免并发重复连接。
    conn: tokio::sync::Mutex<Option<Arc<Connection>>>,
    /// 订阅方法 → 最近一次成功订阅的参数。
    subscriptions: Mutex<BTreeMap<String, Value>>,
    next_id: AtomicU64,
    /// 连接断开时通知后台重连任务。
    disconnected: Arc<Notify>,
}

struct Connection {
    writer: tokio::sync::Mutex<WriteHalf<NamedPipeClient>>,
    /// 等待响应的请求与连接状态，同一把锁保护：断开后不会再有请求挂进来；
    /// 「连上」「断开」两条消息也在这把锁下发出，不会颠倒顺序。
    pending: Mutex<Pending>,
}

#[derive(Default)]
struct Pending {
    closed: bool,
    /// 握手成功、已经发过「连上」。只有这样的连接断开时才发「断开」。
    announced: bool,
    waiters: HashMap<u64, oneshot::Sender<Reply>>,
}

impl Client {
    pub fn new(pipe_name: impl Into<String>, sink: Sink) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            sink,
            conn: tokio::sync::Mutex::new(None),
            subscriptions: Mutex::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            disconnected: Arc::new(Notify::new()),
        }
    }

    /// 调用一个 IPC 方法。没有连接时先建立连接；服务不在时立刻返回传输错误。
    pub async fn call(&self, method: &str, params: Value) -> Reply {
        let info = methods::method(method)
            .filter(|m| m.name != "ipc.hello")
            .ok_or_else(|| {
                CallError::Service(IpcError::new(ErrorCode::IpcUnknownMethod, "unknown method"))
            })?;
        let conn = self.connection().await?;
        let result = self.request(&conn, info.name, params.clone()).await;
        if result.is_ok() && SUBSCRIBE_METHODS.contains(&info.name) {
            lock(&self.subscriptions).insert(info.name.to_owned(), params);
        }
        result
    }

    /// 后台保持连接：断开后每隔 [`RECONNECT_INTERVAL`] 重连一次。永不返回。
    pub async fn keep_connected(self: Arc<Self>) {
        loop {
            if self.connection().await.is_ok() {
                self.disconnected.notified().await;
            }
            tokio::time::sleep(RECONNECT_INTERVAL).await;
        }
    }

    /// 当前连接；断开了就重新建立。
    async fn connection(&self) -> Result<Arc<Connection>, CallError> {
        let mut current = self.conn.lock().await;
        if let Some(conn) = current.as_ref()
            && !lock(&conn.pending).closed
        {
            return Ok(conn.clone());
        }
        *current = None;
        let conn = self.connect().await?;
        {
            let mut pending = lock(&conn.pending);
            if pending.closed {
                return Err(CallError::Transport("connection closed".to_owned()));
            }
            pending.announced = true;
            (self.sink)(Outbound::Connection(true));
        }
        *current = Some(conn.clone());
        Ok(conn)
    }

    /// 打开管道、启动读任务、握手，再重放订阅。
    async fn connect(&self) -> Result<Arc<Connection>, CallError> {
        let pipe = open_pipe(&self.pipe_name).await?;
        let (reader, writer) = tokio::io::split(pipe);
        let conn = Arc::new(Connection {
            writer: tokio::sync::Mutex::new(writer),
            pending: Mutex::new(Pending::default()),
        });
        let reader_task = tokio::spawn(read_loop(
            reader,
            conn.clone(),
            self.sink.clone(),
            self.disconnected.clone(),
        ));
        let hello = HelloParams {
            protocol_version: IPC_PROTOCOL_VERSION,
            client_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let greeted = match serde_json::to_value(hello) {
            Ok(hello) => self.request(&conn, "ipc.hello", hello).await,
            Err(e) => Err(CallError::transport("encode", e)),
        };
        if let Err(e) = greeted {
            // 握手失败的连接从未对外宣布过：丢弃即可，读任务也不会为它发「断开」
            reader_task.abort();
            conn.fail_all(&e, None);
            return Err(e);
        }
        let replay: Vec<(String, Value)> = lock(&self.subscriptions)
            .iter()
            .map(|(m, p)| (m.clone(), p.clone()))
            .collect();
        for (method, params) in replay {
            // 重放失败只影响事件推送，不影响这次调用本身
            let _ = self.request(&conn, &method, params).await;
        }
        Ok(conn)
    }

    async fn request(&self, conn: &Connection, method: &str, params: Value) -> Reply {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let mut line = serde_json::to_vec(&RpcRequest::new(id, method, params))
            .map_err(|e| CallError::transport("encode", e))?;
        if line.len() > MAX_MESSAGE_BYTES {
            return Err(CallError::Service(IpcError::new(
                ErrorCode::IpcPayloadTooLarge,
                format!("request exceeds {MAX_MESSAGE_BYTES} bytes"),
            )));
        }
        line.push(b'\n');
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = lock(&conn.pending);
            if pending.closed {
                return Err(CallError::Transport("connection closed".to_owned()));
            }
            pending.waiters.insert(id, tx);
        }
        let written = {
            let mut writer = conn.writer.lock().await;
            match writer.write_all(&line).await {
                Ok(()) => writer.flush().await,
                Err(e) => Err(e),
            }
        };
        if let Err(e) = written {
            lock(&conn.pending).waiters.remove(&id);
            return Err(CallError::transport("write", e));
        }
        match tokio::time::timeout(CALL_TIMEOUT, rx).await {
            Ok(Ok(reply)) => reply,
            Ok(Err(_)) => Err(CallError::Transport("connection closed".to_owned())),
            Err(_) => {
                lock(&conn.pending).waiters.remove(&id);
                Err(CallError::Transport(
                    "the service did not answer in time".to_owned(),
                ))
            }
        }
    }
}

impl Connection {
    /// 标记断开，以 `reason` 结束所有等待中的请求；连接宣布过「连上」时经 `sink` 发「断开」。
    /// 返回连接是否宣布过。
    fn fail_all(&self, reason: &CallError, sink: Option<&Sink>) -> bool {
        let (waiters, announced) = {
            let mut pending = lock(&self.pending);
            pending.closed = true;
            if pending.announced
                && let Some(sink) = sink
            {
                sink(Outbound::Connection(false));
            }
            (std::mem::take(&mut pending.waiters), pending.announced)
        };
        for (_, tx) in waiters {
            let _ = tx.send(Err(reason.clone()));
        }
        announced
    }
}

/// 打开管道。服务没在运行时立刻失败；所有实例都在忙时短暂重试。
async fn open_pipe(name: &str) -> Result<NamedPipeClient, CallError> {
    for _ in 0..BUSY_ATTEMPTS {
        match ClientOptions::new().open(name) {
            Ok(pipe) => return Ok(pipe),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                tokio::time::sleep(BUSY_RETRY).await;
            }
            Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                return Err(CallError::Transport(
                    "the ProcRoute service is not running".to_owned(),
                ));
            }
            Err(e) => return Err(CallError::transport("open the control pipe", e)),
        }
    }
    Err(CallError::Transport(
        "the control pipe stayed busy".to_owned(),
    ))
}

/// 读任务：分发响应与通知，直到连接断开。
async fn read_loop(
    reader: ReadHalf<NamedPipeClient>,
    conn: Arc<Connection>,
    sink: Sink,
    disconnected: Arc<Notify>,
) {
    let mut reader = BufReader::new(reader);
    let mut buf = Vec::new();
    let reason = loop {
        buf.clear();
        match read_line(&mut reader, &mut buf).await {
            Ok(true) => {
                if let Some(fatal) = dispatch(&buf, &conn, &sink) {
                    break fatal;
                }
            }
            Ok(false) => {
                break CallError::Transport("the service closed the connection".to_owned());
            }
            Err(e) => break CallError::transport("read", e),
        }
    };
    if conn.fail_all(&reason, Some(&sink)) {
        disconnected.notify_one();
    }
}

/// 读一行（不含行尾）。连接结束返回 `false`；超过 [`MAX_INCOMING_BYTES`] 视为错误。
async fn read_line(
    reader: &mut BufReader<ReadHalf<NamedPipeClient>>,
    buf: &mut Vec<u8>,
) -> io::Result<bool> {
    let n = (&mut *reader)
        .take(MAX_INCOMING_BYTES + 1)
        .read_until(b'\n', buf)
        .await?;
    if n == 0 {
        return Ok(false);
    }
    if buf.last() != Some(&b'\n') {
        if n as u64 > MAX_INCOMING_BYTES {
            return Err(io::Error::other("message from the service is too large"));
        }
    } else {
        buf.pop();
    }
    Ok(true)
}

/// 处理一条消息。服务以 id 0 回报的错误（未授权、消息超限等）之后会断开连接，
/// 返回它作为全部等待中请求的失败原因。
fn dispatch(line: &[u8], conn: &Connection, sink: &Sink) -> Option<CallError> {
    let Ok(message) = serde_json::from_slice::<Value>(line) else {
        return None;
    };
    let Some(id) = message.get("id").and_then(Value::as_u64) else {
        if let Ok(n) = serde_json::from_value::<RpcNotification>(message)
            && EVENT_CHANNELS.contains(&n.method.as_str())
        {
            sink(Outbound::Notification {
                channel: n.method,
                payload: n.params,
            });
        }
        return None;
    };
    let reply = match message.get("error") {
        Some(error) => match serde_json::from_value::<RpcErrorObject>(error.clone()) {
            Ok(e) => Err(CallError::Service(e.data)),
            Err(_) => Err(CallError::Transport(
                "malformed error from the service".to_owned(),
            )),
        },
        None => Ok(message.get("result").cloned().unwrap_or(Value::Null)),
    };
    if id == 0 {
        return reply.err();
    }
    if let Some(tx) = lock(&conn.pending).waiters.remove(&id) {
        let _ = tx.send(reply);
    }
    None
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // 锁里只有可以安全继续使用的数据，持锁方 panic 也不影响一致性
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests;
