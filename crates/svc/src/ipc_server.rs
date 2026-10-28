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
//! 错误信息里不回显请求内容：serde 的错误文本可能带上参数值（其中可能有凭据），一律换成
//! 只含位置与类别的描述。

use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use procroute_platform_win::acl::{SecurityDescriptor, create_pipe_server, interactive_user_sid};
use procroute_platform_win::process::{pipe_client_pid, process_image_path, process_user_sid};
use procroute_proto::IPC_PROTOCOL_VERSION;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::methods::{self, MethodInfo};
use procroute_proto::rpc::{
    HelloParams, HelloResult, MAX_MESSAGE_BYTES, RpcRequest, RpcResponse, check_hello,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::windows::named_pipe::NamedPipeServer;
use tokio::sync::watch;
use tokio::task::JoinSet;

use crate::client_auth::ClientAuth;

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

/// 交给处理函数的一次调用。`ipc.hello` 由服务端自己处理，不会到这里。
#[derive(Debug)]
pub struct Call<'a> {
    pub method: &'static MethodInfo,
    pub params: Value,
    pub caller: &'a Caller,
}

/// 各领域方法的处理函数。
pub trait Handler: Send + Sync + 'static {
    fn handle(&self, call: Call<'_>) -> impl Future<Output = Result<Value, IpcError>> + Send;
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
        let _ = write_response(&mut writer, &RpcResponse::err(NO_ID, e)).await;
        return;
    }
    tracing::debug!(pid = caller.pid, "pipe client connected");
    let mut reader = BufReader::new(reader);
    let mut session = Session {
        greeted: false,
        caller: &caller,
    };
    let mut frame = Vec::new();
    loop {
        let (response, close) = match read_frame(&mut reader, &mut frame).await {
            Ok(false) => break,
            Ok(true) => session.process(&frame, handler.as_ref()).await,
            Err(FrameError::TooLarge) => (
                RpcResponse::err(
                    NO_ID,
                    IpcError::new(
                        ErrorCode::IpcPayloadTooLarge,
                        format!("message exceeds {MAX_MESSAGE_BYTES} bytes"),
                    ),
                ),
                true,
            ),
            Err(FrameError::Io(e)) => {
                tracing::debug!(error = %e, "pipe read failed");
                break;
            }
        };
        if write_response(&mut writer, &response).await.is_err() || close {
            break;
        }
    }
    tracing::debug!(pid = caller.pid, "pipe client disconnected");
}

/// 一个连接上的握手状态。
struct Session<'a> {
    greeted: bool,
    caller: &'a Caller,
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
        let result = handler
            .handle(Call {
                method,
                params: req.params,
                caller: self.caller,
            })
            .await;
        if method.mutating {
            AuditRecord::new(method, self.caller, &result).log();
        }
        let response = match result {
            Ok(v) => RpcResponse::ok(id, v),
            Err(e) => RpcResponse::err(id, e),
        };
        (response, false)
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

/// 读一行到 `buf`（不含行尾）。连接正常结束返回 `false`。
///
/// 最多读 `MAX_MESSAGE_BYTES + 2` 字节：恰好 1 MiB 的消息加 `\r\n` 刚好读完；
/// 更长的消息在读满之前就会被判定为超限，不会无限占用内存。上限只计消息本身，不含行尾。
async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
) -> Result<bool, FrameError> {
    buf.clear();
    let limit = (MAX_MESSAGE_BYTES + 2) as u64;
    let n = (&mut *reader)
        .take(limit)
        .read_until(b'\n', buf)
        .await
        .map_err(FrameError::Io)?;
    if n == 0 {
        return Ok(false);
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }
    // 没有换行就到达 EOF 时当作最后一条消息处理；两种情况都按去掉行尾后的长度判断。
    if buf.len() > MAX_MESSAGE_BYTES {
        return Err(FrameError::TooLarge);
    }
    Ok(true)
}

async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(response).map_err(io::Error::other)?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests;
