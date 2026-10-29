// SPDX-License-Identifier: GPL-3.0-or-later
//! 控制管道服务端（T-057）。
//!
//! 传输：`\\.\pipe\ProcRoute.Control` 上的字节流，**一行一条** JSON-RPC 2.0 消息（以 `\n` 结尾，
//! 允许 `\r\n`）。JSON 序列化结果本身不含换行，所以不需要额外转义。
//!
//! 每个连接的处理顺序：
//!
//! 1. 取客户端 PID → 可执行文件路径与用户 SID，按 [`ClientAuth`] 校验（C-SEC-02），不通过即回
//!    `ipc.unauthorized` 并断开；
//! 2. 第一条请求必须是 `ipc.hello`，协议版本不一致回 `ipc.version_mismatch` 并断开（C-ARCH-07）；
//! 3. 每条消息不超过 1 MiB，超限回 `ipc.payload_too_large` 并断开（C-SEC-03）；
//! 4. 方法名必须在 `procroute_proto::methods` 登记过；参数由处理函数用 [`parse_params`] 按类型
//!    严格反序列化（schema 校验）；
//! 5. 修改类方法写审计日志：方法名、调用者 SID、结果，不含任何参数（C-SEC-03、C-SEC-04）。
//!
//! 服务主动推送的事件是同一管道上的 JSON-RPC 通知（没有 `id`）：握手后，每次会话状态变化都推送
//! `session.status`；调用过 `conn.subscribe` / `log.subscribe`（由这里处理，不交给 [`Handler`]）的
//! 连接还会收到连接与日志事件，订阅持续到连接断开。读请求与推送事件在同一个任务里交替进行，所以读帧
//! 必须可以安全取消（见 [`FrameReader`]）。
//!
//! 错误信息里不回显请求内容：serde 的错误文本可能带上参数值（其中可能有凭据），一律换成
//! 只含位置与类别的描述。

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use procroute_platform_win::acl::{SecurityDescriptor, create_pipe_server, interactive_user_sid};
use procroute_platform_win::process::{pipe_client_pid, process_image_path, process_user_sid};
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::event::{LogLevel, LogSubscribeParams};
use procroute_proto::methods::{self, MethodInfo};
use procroute_proto::rpc::{
    HelloParams, HelloResult, MAX_MESSAGE_BYTES, RpcNotification, RpcRequest, RpcResponse,
    check_hello,
};
use procroute_proto::{Empty, IPC_PROTOCOL_VERSION};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::broadcast::error::RecvError;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::client_auth::ClientAuth;
use crate::events::{StreamEvent, Subscription};

/// 无法关联到具体请求时（消息无法解析、超限、未授权）响应里使用的 id。
const NO_ID: u64 = 0;

/// 创建管道实例失败后的重试间隔。
const RETRY_DELAY: Duration = Duration::from_millis(500);

/// 服务端配置。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub pipe_name: String,
    pub client_auth: ClientAuth,
}

/// 已通过校验的调用者。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub pid: u32,
    pub image: String,
    pub sid: String,
}

/// 交给处理函数的一次调用。`ipc.hello` 与事件订阅由服务端自己处理，不会到这里。
#[derive(Debug)]
pub struct Call<'a> {
    pub method: &'static MethodInfo,
    pub params: Value,
    pub caller: &'a Caller,
}

/// 各领域方法的处理函数。
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, call: Call<'_>) -> impl Future<Output = Result<Value, IpcError>> + Send;

    /// 推送给一个新连接的事件；没有事件源时为 `None`。
    fn events(&self) -> Option<Subscription> {
        None
    }
}

/// 按类型严格解析参数（schema 校验）。缺省的 `params` 视为 `{}`。
///
/// 错误信息只给出类别与位置，不回显参数内容。
pub fn parse_params<T: DeserializeOwned>(params: Value) -> Result<T, IpcError> {
    let params = if params.is_null() {
        Value::Object(serde_json::Map::new())
    } else {
        params
    };
    serde_json::from_value(params).map_err(|e| {
        IpcError::new(
            ErrorCode::IpcInvalidParams,
            format!(
                "params do not match the method schema ({:?} error)",
                e.classify()
            ),
        )
    })
}

/// 运行管道服务端，直到 `shutdown` 变为 `true`（或发送端被丢弃）。
///
/// 返回前会中止所有连接任务。只有第一个管道实例创建失败（例如名字被占用）才返回错误。
pub async fn serve<H: Handler>(
    config: ServerConfig,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let config = Arc::new(config);
    let mut server = create_instance(&config.pipe_name, true)?;
    tracing::info!(pipe = %config.pipe_name, "control pipe listening");
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            connected = server.connect() => {
                if let Err(e) = &connected {
                    tracing::warn!(error = %e, "pipe connect failed");
                }
                let Some(next) = next_instance(&config.pipe_name, &mut shutdown).await else {
                    break;
                };
                let conn = std::mem::replace(&mut server, next);
                if connected.is_ok() {
                    connections.spawn(handle_connection(conn, config.clone(), handler.clone()));
                }
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    connections.shutdown().await;
    tracing::info!("control pipe stopped");
    Ok(())
}

/// 每个新实例都按当时的交互用户生成安全描述符（用户可能注销或切换）。
fn create_instance(name: &str, first: bool) -> io::Result<NamedPipeServer> {
    let user = interactive_user_sid()?;
    let sd = SecurityDescriptor::control_pipe(user.as_deref())?;
    create_pipe_server(name, &sd, first)
}

/// 创建下一个实例，失败则每隔 [`RETRY_DELAY`] 重试；收到停止信号时返回 `None`。
async fn next_instance(
    name: &str,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<NamedPipeServer> {
    loop {
        match create_instance(name, false) {
            Ok(s) => return Some(s),
            Err(e) => tracing::error!(error = %e, "cannot create pipe instance, retrying"),
        }
        tokio::select! {
            _ = tokio::time::sleep(RETRY_DELAY) => {}
            _ = shutdown.changed() => return None,
        }
    }
}

fn identify(pipe: &NamedPipeServer) -> io::Result<Caller> {
    let pid = pipe_client_pid(pipe)?;
    Ok(Caller {
        pid,
        image: process_image_path(pid)?,
        sid: process_user_sid(pid)?,
    })
}

async fn handle_connection<H: Handler>(
    pipe: NamedPipeServer,
    config: Arc<ServerConfig>,
    handler: Arc<H>,
) {
    let caller = match identify(&pipe) {
        Ok(c) => c,
        Err(e) => {
            // 无法确认身份就不服务（fail-closed）。
            tracing::warn!(error = %e, "cannot identify pipe client; disconnecting");
            return;
        }
    };
    let (reader, mut writer) = tokio::io::split(pipe);
    if let Err(e) = config.client_auth.verify(&caller.image) {
        tracing::warn!(pid = caller.pid, image = %caller.image, reason = %e.message, "pipe client rejected");
        let _ = write_message(&mut writer, &RpcResponse::err(NO_ID, e)).await;
        return;
    }
    tracing::debug!(pid = caller.pid, "pipe client connected");
    let mut frames = FrameReader::new(BufReader::new(reader));
    let mut events = handler.events();
    let mut session = Session {
        greeted: false,
        caller: &caller,
        subscriptions: Subscriptions::default(),
    };
    loop {
        let next = tokio::select! {
            frame = frames.next() => Incoming::Frame(frame),
            event = next_notification(&mut events, &session.subscriptions), if session.greeted => {
                Incoming::Event(event)
            }
        };
        let (written, close) = match next {
            Incoming::Frame(Ok(Some(frame))) => {
                let (response, close) = session.process(&frame, handler.as_ref()).await;
                (write_message(&mut writer, &response).await, close)
            }
            Incoming::Frame(Ok(None)) => break,
            Incoming::Frame(Err(FrameError::TooLarge)) => {
                let err = IpcError::new(
                    ErrorCode::IpcPayloadTooLarge,
                    format!("message exceeds {MAX_MESSAGE_BYTES} bytes"),
                );
                let response = RpcResponse::err(NO_ID, err);
                (write_message(&mut writer, &response).await, true)
            }
            Incoming::Frame(Err(FrameError::Io(e))) => {
                tracing::debug!(error = %e, "pipe read failed");
                break;
            }
            Incoming::Event(Some(notification)) => {
                (write_message(&mut writer, &notification).await, false)
            }
            Incoming::Event(None) => {
                // 事件源已关闭（服务正在退出）：只是不再推送，请求照常处理
                events = None;
                (Ok(()), false)
            }
        };
        if written.is_err() || close {
            break;
        }
    }
    tracing::debug!(pid = caller.pid, "pipe client disconnected");
}

enum Incoming {
    Frame(Result<Option<Vec<u8>>, FrameError>),
    Event(Option<RpcNotification>),
}

/// 一个连接订阅了哪些高频事件。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Subscriptions {
    conn: bool,
    /// 订阅了日志时的最低级别。
    log: Option<LogLevel>,
}

/// 等下一条要推给本连接的通知。没有事件源时一直等待；事件源关闭时返回 `None`。
///
/// 可以安全取消：`watch::Receiver::changed` 与 `broadcast::Receiver::recv` 都可以安全取消，
/// 收到值后立即返回，中间没有别的等待点。
async fn next_notification(
    events: &mut Option<Subscription>,
    subscriptions: &Subscriptions,
) -> Option<RpcNotification> {
    let Some(events) = events else {
        return std::future::pending().await;
    };
    loop {
        tokio::select! {
            changed = events.session.changed() => {
                changed.ok()?;
                let status = events.session.borrow_and_update().clone();
                return notification("session.status", &status);
            }
            event = events.stream.recv() => match event {
                Ok(StreamEvent::Log(e)) if subscriptions.log.is_some_and(|min| e.level >= min) => {
                    return notification("log.subscribe", &e);
                }
                Ok(StreamEvent::Conn(e)) if subscriptions.conn => {
                    return notification("conn.subscribe", &e);
                }
                // 未订阅的事件，或本连接处理太慢而被丢弃的事件：跳过。这里不能写日志，
                // 否则转发日志本身又会产生新的日志。
                Ok(_) | Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return None,
            },
        }
    }
}

fn notification(channel: &str, payload: &impl Serialize) -> Option<RpcNotification> {
    serde_json::to_value(payload)
        .ok()
        .map(|v| RpcNotification::new(channel, v))
}

/// 一个连接上的握手与订阅状态。
struct Session<'a> {
    greeted: bool,
    caller: &'a Caller,
    subscriptions: Subscriptions,
}

impl Session<'_> {
    /// 处理一条消息，返回响应以及是否随后断开连接。
    async fn process<H: Handler>(&mut self, frame: &[u8], handler: &H) -> (RpcResponse, bool) {
        let req = match RpcRequest::parse(frame) {
            Ok(r) => r,
            Err(e) => return (RpcResponse::err(NO_ID, scrub_parse_error(e)), false),
        };
        let id = req.id;
        let Some(method) = methods::method(&req.method) else {
            let err = IpcError::new(ErrorCode::IpcUnknownMethod, "unknown method");
            return (RpcResponse::err(id, err), !self.greeted);
        };
        if method.name == "ipc.hello" {
            return match hello(req.params) {
                Ok(result) => {
                    self.greeted = true;
                    (RpcResponse::ok(id, result), false)
                }
                Err(e) => (RpcResponse::err(id, e), true),
            };
        }
        if !self.greeted {
            let err = IpcError::new(
                ErrorCode::IpcInvalidRequest,
                "ipc.hello must be the first request",
            );
            return (RpcResponse::err(id, err), true);
        }
        let result = match method.name {
            "conn.subscribe" | "log.subscribe" => self.subscribe(method.name, req.params),
            _ => {
                handler
                    .handle(Call {
                        method,
                        params: req.params,
                        caller: self.caller,
                    })
                    .await
            }
        };
        if method.mutating {
            AuditRecord::new(method, self.caller, &result).log();
        }
        let response = match result {
            Ok(v) => RpcResponse::ok(id, v),
            Err(e) => RpcResponse::err(id, e),
        };
        (response, false)
    }

    /// 登记本连接的事件订阅；重复订阅以最后一次为准。
    fn subscribe(&mut self, method: &str, params: Value) -> Result<Value, IpcError> {
        if method == "log.subscribe" {
            let LogSubscribeParams { min_level } = parse_params(params)?;
            self.subscriptions.log = Some(min_level);
        } else {
            let Empty {} = parse_params(params)?;
            self.subscriptions.conn = true;
        }
        serde_json::to_value(Empty {})
            .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
    }
}

fn hello(params: Value) -> Result<Value, IpcError> {
    let params: HelloParams = parse_params(params)?;
    check_hello(&params)?;
    serde_json::to_value(HelloResult {
        protocol_version: IPC_PROTOCOL_VERSION,
        service_version: env!("CARGO_PKG_VERSION").to_owned(),
    })
    .map_err(|e| IpcError::new(ErrorCode::Internal, e.to_string()))
}

/// 请求解析错误的文本来自 serde，可能包含请求内容；保留错误码，换掉文本。
fn scrub_parse_error(e: IpcError) -> IpcError {
    match e.code {
        ErrorCode::IpcInvalidRequest => {
            IpcError::new(ErrorCode::IpcInvalidRequest, "malformed JSON-RPC request")
        }
        _ => e,
    }
}

/// 一条审计记录（C-SEC-03）。只有方法名、调用者与结果，从结构上就不可能带上参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub method: &'static str,
    pub caller_sid: String,
    pub caller_pid: u32,
    /// `ok` 或错误码字符串。
    pub outcome: &'static str,
}

impl AuditRecord {
    fn new(method: &MethodInfo, caller: &Caller, result: &Result<Value, IpcError>) -> Self {
        Self {
            method: method.name,
            caller_sid: caller.sid.clone(),
            caller_pid: caller.pid,
            outcome: match result {
                Ok(_) => "ok",
                Err(e) => e.code.as_str(),
            },
        }
    }

    fn log(&self) {
        tracing::info!(
            target: "audit",
            method = self.method,
            caller_sid = %self.caller_sid,
            caller_pid = self.caller_pid,
            outcome = self.outcome,
            "ipc call"
        );
    }
}

#[derive(Debug)]
enum FrameError {
    TooLarge,
    Io(io::Error),
}

/// 按行切分请求，可以安全取消（用在 `tokio::select!` 里）。
///
/// 只在 `fill_buf` 处等待（它可以安全取消：被取消时没有读走任何数据），拿到数据后不再等待就
/// `consume`；未成行的部分留在 `pending` 里，下次接着拼。消息上限只计消息本身，不含行尾：
/// 恰好 1 MiB 的消息加 `\r\n` 可以通过，更长的消息在凑满一行之前就判定为超限，不会无限占用内存。
struct FrameReader<R> {
    reader: R,
    pending: Vec<u8>,
}

impl<R: AsyncBufRead + Unpin> FrameReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            pending: Vec::new(),
        }
    }

    /// 下一条消息（不含行尾）。连接正常结束返回 `None`；没有换行就到达 EOF 的内容当作最后一条消息。
    async fn next(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        loop {
            let available = self.reader.fill_buf().await.map_err(FrameError::Io)?;
            if available.is_empty() {
                if self.pending.is_empty() {
                    return Ok(None);
                }
                return self.take_frame().map(Some);
            }
            if let Some(pos) = available.iter().position(|&b| b == b'\n') {
                self.pending.extend_from_slice(&available[..pos]);
                self.reader.consume(pos + 1);
                return self.take_frame().map(Some);
            }
            let n = available.len();
            self.pending.extend_from_slice(available);
            self.reader.consume(n);
            // 末尾那个可能还在等 `\n` 的 `\r` 不计入上限
            if self.pending.len() > MAX_MESSAGE_BYTES + 1 {
                return Err(FrameError::TooLarge);
            }
        }
    }

    fn take_frame(&mut self) -> Result<Vec<u8>, FrameError> {
        let mut frame = std::mem::take(&mut self.pending);
        if frame.last() == Some(&b'\r') {
            frame.pop();
        }
        if frame.len() > MAX_MESSAGE_BYTES {
            return Err(FrameError::TooLarge);
        }
        Ok(frame)
    }
}

/// 写一行 JSON（响应或通知）。
async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &impl Serialize,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests;
