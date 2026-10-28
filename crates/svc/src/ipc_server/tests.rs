// SPDX-License-Identifier: GPL-3.0-or-later
//! 控制管道服务端的测试：真实命名管道、进程内收发，不注册服务（C-TEST-04）。

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use procroute_proto::Empty;
use procroute_proto::session::SessionStartParams;
use serde_json::json;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};
use tokio::task::JoinHandle;

use super::*;

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PIPE_BUSY: i32 = 231;

/// 回显方法名与调用者 PID；`profile.delete` 返回业务错误。
struct Echo;

impl Handler for Echo {
    async fn handle(&self, call: Call<'_>) -> Result<Value, IpcError> {
        if call.method.name == "profile.delete" {
            return Err(IpcError::new(ErrorCode::ProfileNotFound, "no such profile"));
        }
        Ok(json!({ "method": call.method.name, "pid": call.caller.pid }))
    }
}

struct Harness {
    name: String,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<io::Result<()>>,
}

fn unique_pipe_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        r"\\.\pipe\ProcRoute.Test.svc.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn start(client_auth: ClientAuth) -> Harness {
    let name = unique_pipe_name();
    let (shutdown, rx) = watch::channel(false);
    let config = ServerConfig {
        pipe_name: name.clone(),
        client_auth,
    };
    let task = tokio::spawn(serve(config, Arc::new(Echo), rx));
    Harness {
        name,
        shutdown,
        task,
    }
}

struct Client {
    reader: BufReader<ReadHalf<NamedPipeClient>>,
    writer: WriteHalf<NamedPipeClient>,
}

impl Client {
    async fn connect(name: &str) -> Self {
        for _ in 0..200 {
            match ClientOptions::new().open(name) {
                Ok(pipe) => {
                    let (r, w) = tokio::io::split(pipe);
                    return Self {
                        reader: BufReader::new(r),
                        writer: w,
                    };
                }
                Err(e)
                    if matches!(
                        e.raw_os_error(),
                        Some(ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY)
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(e) => panic!("connect failed: {e}"),
            }
        }
        panic!("pipe {name} never became available");
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).await.expect("write");
        self.writer.flush().await.expect("flush");
    }

    /// 读一条响应；连接被服务端关闭时返回 `None`。
    async fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(5), self.reader.read_line(&mut line))
            .await
            .expect("response within 5s")
            .unwrap_or(0);
        (n > 0).then(|| serde_json::from_str(&line).expect("response is JSON"))
    }

    async fn call(&mut self, id: u64, method: &str, params: Value) -> Value {
        let req = serde_json::to_vec(&RpcRequest::new(id, method, params)).expect("encode");
        self.send_raw(&[req.as_slice(), b"\n"].concat()).await;
        self.recv().await.expect("a response")
    }

    async fn hello(&mut self) {
        let resp = self
            .call(
                1,
                "ipc.hello",
                json!({ "protocol_version": IPC_PROTOCOL_VERSION, "client_version": "test" }),
            )
            .await;
        assert_eq!(
            resp["result"]["protocol_version"], IPC_PROTOCOL_VERSION,
            "{resp}"
        );
    }
}

fn error_code(resp: &Value) -> &str {
    resp["error"]["data"]["code"].as_str().unwrap_or("<none>")
}

#[tokio::test]
async fn valid_requests_after_hello_are_answered() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    c.hello().await;
    let resp = c.call(2, "session.status", json!({})).await;
    assert_eq!(resp["id"], 2);
    assert_eq!(resp["result"]["method"], "session.status");
    assert_eq!(
        resp["result"]["pid"],
        std::process::id(),
        "caller is identified"
    );
    // 业务错误原样带回错误码，连接保持。
    let resp = c.call(3, "profile.delete", json!({ "id": "p1" })).await;
    assert_eq!(error_code(&resp), "profile.not_found");
    let resp = c.call(4, "session.status", Value::Null).await;
    assert_eq!(resp["result"]["method"], "session.status");
}

#[tokio::test]
async fn protocol_version_mismatch_is_rejected_and_disconnected() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    let resp = c
        .call(
            1,
            "ipc.hello",
            json!({ "protocol_version": IPC_PROTOCOL_VERSION + 1, "client_version": "9" }),
        )
        .await;
    assert_eq!(error_code(&resp), "ipc.version_mismatch");
    assert!(c.recv().await.is_none(), "connection must be closed");
}

#[tokio::test]
async fn requests_before_hello_are_rejected_and_disconnected() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    let resp = c.call(1, "session.status", json!({})).await;
    assert_eq!(error_code(&resp), "ipc.invalid_request");
    assert!(c.recv().await.is_none(), "connection must be closed");
}

#[tokio::test]
async fn oversized_messages_are_rejected_and_disconnected() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    c.hello().await;
    let mut big = vec![b'a'; MAX_MESSAGE_BYTES + 16];
    big.push(b'\n');
    c.send_raw(&big).await;
    let resp = c.recv().await.expect("an error response");
    assert_eq!(error_code(&resp), "ipc.payload_too_large");
    assert!(c.recv().await.is_none(), "connection must be closed");
}

#[tokio::test]
async fn a_message_of_exactly_the_limit_is_accepted() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    c.hello().await;
    let head = r#"{"jsonrpc":"2.0","id":7,"method":"session.status","params":{"pad":""#;
    let tail = r#""}}"#;
    let pad = "x".repeat(MAX_MESSAGE_BYTES - head.len() - tail.len());
    let msg = format!("{head}{pad}{tail}");
    assert_eq!(msg.len(), MAX_MESSAGE_BYTES);
    c.send_raw(format!("{msg}\r\n").as_bytes()).await;
    let resp = c.recv().await.expect("a response");
    assert_eq!(resp["id"], 7, "{}", error_code(&resp));
    assert_eq!(resp["result"]["method"], "session.status");
}

#[tokio::test]
async fn frame_limit_counts_the_message_without_its_line_ending() {
    async fn read(input: Vec<u8>) -> Result<usize, &'static str> {
        let mut buf = Vec::new();
        match read_frame(&mut input.as_slice(), &mut buf).await {
            Ok(true) => Ok(buf.len()),
            Ok(false) => Err("eof"),
            Err(FrameError::TooLarge) => Err("too large"),
            Err(FrameError::Io(_)) => Err("io"),
        }
    }
    let msg = |len: usize, end: &[u8]| [vec![b'x'; len], end.to_vec()].concat();
    assert_eq!(
        read(msg(MAX_MESSAGE_BYTES, b"\n")).await,
        Ok(MAX_MESSAGE_BYTES)
    );
    assert_eq!(
        read(msg(MAX_MESSAGE_BYTES, b"\r\n")).await,
        Ok(MAX_MESSAGE_BYTES)
    );
    assert_eq!(
        read(msg(MAX_MESSAGE_BYTES, b"")).await,
        Ok(MAX_MESSAGE_BYTES)
    );
    assert_eq!(
        read(msg(MAX_MESSAGE_BYTES + 1, b"\n")).await,
        Err("too large")
    );
    assert_eq!(
        read(msg(MAX_MESSAGE_BYTES + 1, b"\r\n")).await,
        Err("too large")
    );
    assert_eq!(
        read(msg(MAX_MESSAGE_BYTES + 1, b"")).await,
        Err("too large")
    );
    assert_eq!(read(Vec::new()).await, Err("eof"));
}

#[tokio::test]
async fn unknown_methods_and_malformed_json_keep_the_connection() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    c.hello().await;
    let resp = c.call(2, "no.such", json!({})).await;
    assert_eq!(error_code(&resp), "ipc.unknown_method");
    c.send_raw(b"{not json\n").await;
    let resp = c.recv().await.expect("an error response");
    assert_eq!(error_code(&resp), "ipc.invalid_request");
    let resp = c.call(3, "session.status", json!({})).await;
    assert_eq!(resp["result"]["method"], "session.status");
}

#[tokio::test]
async fn error_messages_never_echo_request_content() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    c.hello().await;
    // id 类型错误：serde 的原始错误文本会带上这个字符串。
    c.send_raw(br#"{"jsonrpc":"2.0","id":"hunter2-secret","method":"session.status"}"#)
        .await;
    c.send_raw(b"\n").await;
    let resp = c.recv().await.expect("an error response");
    assert_eq!(error_code(&resp), "ipc.invalid_request");
    assert!(!resp.to_string().contains("hunter2"), "{resp}");
}

#[test]
fn parse_params_is_strict_and_does_not_echo_values() {
    let Empty {} = parse_params(Value::Null).expect("missing params mean {}");
    let ok: SessionStartParams = parse_params(json!({ "profile_id": "p1" })).expect("valid");
    assert_eq!(ok.profile_id, "p1");
    let err = parse_params::<SessionStartParams>(json!({ "profile_id": "p1", "x": 1 }))
        .expect_err("unknown fields are rejected");
    assert_eq!(err.code, ErrorCode::IpcInvalidParams);
    let err = parse_params::<HelloParams>(
        json!({ "protocol_version": "hunter2", "client_version": "x" }),
    )
    .expect_err("wrong type");
    assert_eq!(err.code, ErrorCode::IpcInvalidParams);
    assert!(!err.message.contains("hunter2"), "{}", err.message);
}

#[tokio::test]
async fn unauthorized_clients_are_rejected_before_any_request() {
    // 正式策略、安装目录不包含测试二进制：必须拒绝。
    let h = start(ClientAuth::Enforce {
        install_dir: r"c:\program files\procroute".into(),
        signer: Ok("C=CN, O=ProcRoute, CN=ProcRoute".into()),
    });
    let mut c = Client::connect(&h.name).await;
    let resp = c.recv().await.expect("an error response");
    assert_eq!(error_code(&resp), "ipc.unauthorized");
    assert!(c.recv().await.is_none(), "connection must be closed");
}

#[tokio::test]
async fn several_clients_are_served_concurrently() {
    let h = start(ClientAuth::Disabled);
    let mut a = Client::connect(&h.name).await;
    let mut b = Client::connect(&h.name).await;
    a.hello().await;
    b.hello().await;
    let ra = a.call(2, "session.status", json!({})).await;
    let rb = b.call(2, "node.list", json!({})).await;
    assert_eq!(ra["result"]["method"], "session.status");
    assert_eq!(rb["result"]["method"], "node.list");
}

#[tokio::test]
async fn shutdown_stops_the_server_and_removes_the_pipe() {
    let h = start(ClientAuth::Disabled);
    let mut c = Client::connect(&h.name).await;
    c.hello().await;
    h.shutdown.send(true).expect("signal");
    tokio::time::timeout(Duration::from_secs(3), h.task)
        .await
        .expect("stops within 3s")
        .expect("task")
        .expect("serve returns Ok");
    assert!(c.recv().await.is_none(), "open connections are closed");
    let err = ClientOptions::new()
        .open(&h.name)
        .expect_err("pipe is gone");
    assert_eq!(err.raw_os_error(), Some(ERROR_FILE_NOT_FOUND), "{err}");
}

#[tokio::test]
async fn first_instance_fails_when_the_name_is_taken() {
    let h = start(ClientAuth::Disabled);
    let _c = Client::connect(&h.name).await;
    let (_tx, rx) = watch::channel(false);
    let config = ServerConfig {
        pipe_name: h.name.clone(),
        client_auth: ClientAuth::Disabled,
    };
    assert!(serve(config, Arc::new(Echo), rx).await.is_err());
}

#[test]
fn audit_records_carry_method_caller_and_outcome_only() {
    let caller = Caller {
        pid: 42,
        image: r"C:\Program Files\ProcRoute\procroute-ui.exe".into(),
        sid: "S-1-5-21-1-2-3-1001".into(),
    };
    let method = methods::method("profile.delete").expect("registered");
    let rec = AuditRecord::new(
        method,
        &caller,
        &Err(IpcError::new(ErrorCode::ProfileNotFound, "x")),
    );
    assert_eq!(
        rec,
        AuditRecord {
            method: "profile.delete",
            caller_sid: "S-1-5-21-1-2-3-1001".into(),
            caller_pid: 42,
            outcome: "profile.not_found",
        }
    );
    let ok = AuditRecord::new(method, &caller, &Ok(json!({ "password": "hunter2" })));
    assert_eq!(ok.outcome, "ok");
    assert!(!format!("{ok:?}").contains("hunter2"));
}
