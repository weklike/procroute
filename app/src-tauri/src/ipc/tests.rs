// SPDX-License-Identifier: GPL-3.0-or-later
//! 控制管道客户端的测试：进程内的假服务端（真实命名管道，不注册服务，C-TEST-04）。

use std::sync::atomic::AtomicU32;

use procroute_proto::error::FieldIssueCode;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};

use super::*;

const WAIT: Duration = Duration::from_secs(5);

fn unique_pipe_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(
        r"\\.\pipe\ProcRoute.Test.ui.{}.{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    )
}

/// 客户端与收集推送消息的通道。
fn client(name: &str) -> (Arc<Client>, UnboundedReceiver<Outbound>) {
    let (tx, rx) = unbounded_channel();
    let sink: Sink = Arc::new(move |out| {
        let _ = tx.send(out);
    });
    (Arc::new(Client::new(name, sink)), rx)
}

fn instance(name: &str, first: bool) -> NamedPipeServer {
    ServerOptions::new()
        .first_pipe_instance(first)
        .create(name)
        .expect("create pipe instance")
}

/// 假服务端的一个连接。
struct Peer {
    reader: BufReader<ReadHalf<NamedPipeServer>>,
    writer: WriteHalf<NamedPipeServer>,
}

impl Peer {
    async fn accept(server: NamedPipeServer) -> Self {
        server.connect().await.expect("client connects");
        let (r, w) = tokio::io::split(server);
        Self {
            reader: BufReader::new(r),
            writer: w,
        }
    }

    async fn recv(&mut self) -> Value {
        let mut line = String::new();
        let n = tokio::time::timeout(WAIT, self.reader.read_line(&mut line))
            .await
            .expect("request within 5s")
            .expect("read");
        assert!(n > 0, "client closed the connection");
        serde_json::from_str(&line).expect("request is JSON")
    }

    async fn send(&mut self, message: Value) {
        let mut line = serde_json::to_vec(&message).expect("encode");
        line.push(b'\n');
        self.writer.write_all(&line).await.expect("write");
        self.writer.flush().await.expect("flush");
    }

    async fn ok(&mut self, req: &Value, result: Value) {
        self.send(json!({ "jsonrpc": "2.0", "id": req["id"], "result": result }))
            .await;
    }

    async fn error(&mut self, id: &Value, code: &str) {
        self.send(json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": { "code": -32000, "message": code, "data": { "code": code, "message": "x" } },
        }))
        .await;
    }

    /// 读一条请求，断言方法名后返回。
    async fn expect(&mut self, method: &str) -> Value {
        let req = self.recv().await;
        assert_eq!(req["method"], method, "{req}");
        req
    }

    async fn greet(&mut self) {
        let req = self.expect("ipc.hello").await;
        assert_eq!(req["params"]["protocol_version"], IPC_PROTOCOL_VERSION);
        self.ok(
            &req,
            json!({ "protocol_version": IPC_PROTOCOL_VERSION, "service_version": "test" }),
        )
        .await;
    }
}

async fn next(rx: &mut UnboundedReceiver<Outbound>) -> Outbound {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("an outbound message within 5s")
        .expect("sink open")
}

fn service_code(r: Reply) -> ErrorCode {
    match r {
        Err(CallError::Service(e)) => e.code,
        other => panic!("expected a service error, got {other:?}"),
    }
}

#[tokio::test]
async fn calls_greet_first_and_return_results() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, mut rx) = client(&name);
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        peer.greet().await;
        let req = peer.expect("session.status").await;
        assert_eq!(req["params"], json!({}));
        peer.ok(&req, json!({ "state": "stopped" })).await;
        peer
    });
    let result = client.call("session.status", json!({})).await;
    assert_eq!(result, Ok(json!({ "state": "stopped" })));
    assert_eq!(next(&mut rx).await, Outbound::Connection(true));
    peer.await.expect("peer");
}

#[tokio::test]
async fn service_errors_keep_their_code_and_fields() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, _rx) = client(&name);
    tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        peer.greet().await;
        let req = peer.expect("profile.save").await;
        peer.send(json!({
            "jsonrpc": "2.0",
            "id": req["id"],
            "error": { "code": -32000, "message": "profile.invalid_schema", "data": {
                "code": "profile.invalid_schema", "message": "1 issue",
                "fields": [ { "path": "name", "code": "empty", "message": "empty" } ],
            } },
        }))
        .await;
        peer.recv().await
    });
    let err = client
        .call("profile.save", json!({ "id": "p1" }))
        .await
        .expect_err("rejected");
    let CallError::Service(e) = err else {
        panic!("expected a service error, got {err:?}");
    };
    assert_eq!(e.code, ErrorCode::ProfileInvalidSchema);
    let fields = e.fields.expect("field issues");
    assert_eq!(fields[0].path, "name");
    assert_eq!(fields[0].code, FieldIssueCode::Empty);
}

#[tokio::test]
async fn notifications_are_forwarded_and_unknown_channels_dropped() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, mut rx) = client(&name);
    tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        peer.greet().await;
        let req = peer.expect("log.subscribe").await;
        peer.ok(&req, json!({})).await;
        peer.send(json!({ "jsonrpc": "2.0", "method": "no.such", "params": {} }))
            .await;
        peer.send(
            json!({ "jsonrpc": "2.0", "method": "log.subscribe", "params": { "message": "hi" } }),
        )
        .await;
        peer.recv().await
    });
    client
        .call("log.subscribe", json!({ "min_level": "info" }))
        .await
        .expect("subscribed");
    assert_eq!(next(&mut rx).await, Outbound::Connection(true));
    assert_eq!(
        next(&mut rx).await,
        Outbound::Notification {
            channel: "log.subscribe".into(),
            payload: json!({ "message": "hi" }),
        }
    );
}

#[tokio::test]
async fn a_missing_service_is_a_transport_error() {
    let (client, mut rx) = client(&unique_pipe_name());
    let err = client
        .call("session.status", json!({}))
        .await
        .expect_err("no service");
    assert!(matches!(err, CallError::Transport(_)), "{err:?}");
    assert!(rx.try_recv().is_err(), "nothing is announced");
}

#[tokio::test]
async fn unknown_methods_and_hello_are_rejected_locally() {
    // 管道名不存在：如果客户端尝试连接，得到的会是传输错误
    let (client, _rx) = client(&unique_pipe_name());
    for method in ["no.such", "ipc.hello"] {
        assert_eq!(
            service_code(client.call(method, json!({})).await),
            ErrorCode::IpcUnknownMethod,
            "{method}"
        );
    }
}

#[tokio::test]
async fn oversized_requests_are_rejected_before_sending() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, _rx) = client(&name);
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        peer.greet().await;
        // 超限的请求没有发出来，下一条就是之后的正常请求
        let req = peer.expect("session.status").await;
        peer.ok(&req, json!({})).await;
    });
    let huge = "x".repeat(MAX_MESSAGE_BYTES);
    assert_eq!(
        service_code(
            client
                .call(
                    "node.import",
                    json!({ "kind": "share_links", "text": huge })
                )
                .await
        ),
        ErrorCode::IpcPayloadTooLarge
    );
    client
        .call("session.status", json!({}))
        .await
        .expect("still usable");
    peer.await.expect("peer");
}

#[tokio::test]
async fn subscriptions_are_replayed_after_a_reconnect() {
    let name = unique_pipe_name();
    let first = instance(&name, true);
    let (client, mut rx) = client(&name);
    let peer = tokio::spawn(async move {
        let mut peer = Peer::accept(first).await;
        // 第一个连接建立后才创建第二个实例，保证客户端第一次连上的是 `first`
        let second = instance(&name, false);
        peer.greet().await;
        let req = peer.expect("log.subscribe").await;
        peer.ok(&req, json!({})).await;
        // 断开第一个连接
        drop(peer);
        let mut peer = Peer::accept(second).await;
        peer.greet().await;
        let replay = peer.expect("log.subscribe").await;
        assert_eq!(replay["params"], json!({ "min_level": "warn" }));
        peer.ok(&replay, json!({})).await;
        let req = peer.expect("session.status").await;
        peer.ok(&req, json!({ "state": "running" })).await;
        peer
    });
    client
        .call("log.subscribe", json!({ "min_level": "warn" }))
        .await
        .expect("subscribed");
    assert_eq!(next(&mut rx).await, Outbound::Connection(true));
    assert_eq!(next(&mut rx).await, Outbound::Connection(false));
    let result = client.call("session.status", json!({})).await;
    assert_eq!(result, Ok(json!({ "state": "running" })));
    assert_eq!(next(&mut rx).await, Outbound::Connection(true));
    peer.await.expect("peer");
}

#[tokio::test]
async fn version_mismatch_is_reported_and_never_announced() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, mut rx) = client(&name);
    tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        let req = peer.expect("ipc.hello").await;
        peer.error(&req["id"], "ipc.version_mismatch").await;
    });
    assert_eq!(
        service_code(client.call("session.status", json!({})).await),
        ErrorCode::IpcVersionMismatch
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        rx.try_recv().is_err(),
        "a failed handshake is not a connection"
    );
}

#[tokio::test]
async fn rejection_without_a_request_id_fails_the_call_with_its_code() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, _rx) = client(&name);
    tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        // 服务端校验客户端失败时以 id 0 回报后断开（见 svc 的 ipc_server）
        peer.error(&json!(0), "ipc.unauthorized").await;
    });
    assert_eq!(
        service_code(client.call("session.status", json!({})).await),
        ErrorCode::IpcUnauthorized
    );
}

#[tokio::test]
async fn pending_calls_fail_when_the_connection_drops() {
    let name = unique_pipe_name();
    let server = instance(&name, true);
    let (client, _rx) = client(&name);
    tokio::spawn(async move {
        let mut peer = Peer::accept(server).await;
        peer.greet().await;
        peer.expect("session.start").await;
        // 不回答就断开
    });
    let err = client
        .call("session.start", json!({ "profile_id": "p1" }))
        .await
        .expect_err("dropped");
    assert!(matches!(err, CallError::Transport(_)), "{err:?}");
}

#[test]
fn errors_serialize_for_the_front_end() {
    let service = CallError::Service(IpcError::new(ErrorCode::ProfileNotFound, "no such id"));
    assert_eq!(
        serde_json::to_value(&service).expect("json"),
        json!({ "code": "profile.not_found", "message": "no such id" })
    );
    let transport = CallError::Transport("the ProcRoute service is not running".into());
    assert_eq!(
        serde_json::to_value(&transport).expect("json"),
        json!("the ProcRoute service is not running")
    );
}
