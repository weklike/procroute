// SPDX-License-Identifier: GPL-3.0-or-later
//! 处理函数的测试。存储目录放在临时目录；端到端的审计测试走真实命名管道（不注册服务）。

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use procroute_proto::IPC_PROTOCOL_VERSION;
use procroute_proto::methods;
use procroute_proto::profile::Profile;
use procroute_proto::session::{ComponentState, SessionState};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::watch;

use super::*;
use crate::client_auth::ClientAuth;
use crate::ipc_server::{Caller, ServerConfig, serve};
use crate::node_store::NodeStore;
use crate::store::tests::sample;

struct Fixture {
    services: Services,
    dir: PathBuf,
    caller: Caller,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(tag: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!("procroute-handlers-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    Fixture {
        services: services(&dir),
        dir,
        caller: Caller {
            pid: 1234,
            image: r"C:\Program Files\ProcRoute\procroute-ui.exe".into(),
            sid: "S-1-5-21-1-2-3-1001".into(),
        },
    }
}

/// 方案目录与节点文件分开放，和正式布局一致（`profiles\` 与 `nodes.json`）。
fn services(dir: &std::path::Path) -> Services {
    Services::new(
        ProfileStore::open(dir).expect("store"),
        NodeStore::open(dir.join("node-store").join("nodes.json")).expect("node store"),
    )
}

impl Fixture {
    async fn call(&self, method: &str, params: Value) -> Result<Value, IpcError> {
        let method = methods::method(method).expect("registered method");
        self.services
            .handle(Call {
                method,
                params,
                caller: &self.caller,
            })
            .await
    }
}

fn code(r: Result<Value, IpcError>) -> ErrorCode {
    r.expect_err("must fail").code
}

#[tokio::test]
async fn profile_save_get_list_delete_round_trip() {
    let f = fixture("crud");
    let p = sample("01JBX7Q3K2M8T5W9Y4C6N0R1PZ", "游戏加速");
    let saved = f
        .call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    assert_eq!(saved, json!({ "id": p.id }));

    let got = f
        .call("profile.get", json!({ "id": p.id }))
        .await
        .expect("get");
    assert_eq!(serde_json::from_value::<Profile>(got).expect("profile"), p);

    let list = f.call("profile.list", json!({})).await.expect("list");
    assert_eq!(list["profiles"][0]["id"], p.id.as_str());
    assert_eq!(list["profiles"][0]["group_count"], 1);
    assert_eq!(list["profiles"][0]["active"], false);

    f.call("profile.delete", json!({ "id": p.id }))
        .await
        .expect("delete");
    assert_eq!(
        code(f.call("profile.get", json!({ "id": p.id })).await),
        ErrorCode::ProfileNotFound
    );
    assert_eq!(
        code(f.call("profile.delete", json!({ "id": p.id })).await),
        ErrorCode::ProfileNotFound
    );
}

#[tokio::test]
async fn invalid_profiles_are_rejected_with_field_issues() {
    let f = fixture("invalid");
    let mut p = sample("p1", "x");
    p.groups[0].matchers.clear();
    p.groups.push(p.groups[0].clone());
    let err = f
        .call("profile.save", to_json(&p).expect("json"))
        .await
        .expect_err("invalid");
    assert_eq!(err.code, ErrorCode::ProfileInvalidSchema);
    let paths: Vec<_> = err
        .fields
        .iter()
        .flatten()
        .map(|i| i.path.as_str())
        .collect();
    assert!(paths.contains(&"groups[0].match"), "{paths:?}");
    assert!(
        paths.iter().any(|p| p.starts_with("groups[1]")),
        "{paths:?}"
    );

    let mut v = to_json(sample("p2", "x")).expect("json");
    v["surprise"] = json!(1);
    assert_eq!(
        code(f.call("profile.save", v).await),
        ErrorCode::ProfileInvalidSchema
    );
    assert_eq!(
        code(
            f.call("profile.save", json!({ "name": "no version" }))
                .await
        ),
        ErrorCode::ProfileInvalidSchema
    );
    // 什么都没有写进存储。
    let list = f.call("profile.list", Value::Null).await.expect("list");
    assert_eq!(list["profiles"], json!([]));
}

#[tokio::test]
async fn ids_from_the_wire_cannot_traverse_paths() {
    let f = fixture("traverse");
    for bad in [r"..\..\Windows\win", "../x", "a.b"] {
        assert_eq!(
            code(f.call("profile.get", json!({ "id": bad })).await),
            ErrorCode::IpcInvalidParams,
            "{bad}"
        );
        assert_eq!(
            code(f.call("profile.delete", json!({ "id": bad })).await),
            ErrorCode::IpcInvalidParams,
            "{bad}"
        );
    }
}

#[tokio::test]
async fn session_reports_truthfully_and_never_pretends_to_start() {
    let f = fixture("session");
    let status = f.call("session.status", json!({})).await.expect("status");
    assert_eq!(status["state"], "stopped");
    assert_eq!(status["components"]["service"], "active");
    assert_eq!(status["components"]["driver"], "inactive");
    assert_eq!(status["components"]["kernel"], "inactive");

    assert_eq!(
        code(f.call("session.stop", json!({})).await),
        ErrorCode::SessionNotRunning
    );
    assert_eq!(
        code(
            f.call("session.start", json!({ "profile_id": "missing" }))
                .await
        ),
        ErrorCode::ProfileNotFound
    );
    let p = sample("p1", "x");
    f.call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": "p1" })).await),
        ErrorCode::KernelUnavailable
    );
    let after = f.services.session_snapshot();
    assert_eq!(after.state, SessionState::Stopped);
    assert_eq!(after.components.kernel, ComponentState::Inactive);
}

#[tokio::test]
async fn params_are_schema_checked() {
    let f = fixture("schema");
    assert_eq!(
        code(f.call("session.status", json!({ "x": 1 })).await),
        ErrorCode::IpcInvalidParams
    );
    assert_eq!(
        code(f.call("profile.get", json!({ "id": 5 })).await),
        ErrorCode::IpcInvalidParams
    );
}

#[tokio::test]
async fn unwired_methods_fail_explicitly() {
    let f = fixture("unwired");
    for m in ["process.list", "driver.status"] {
        assert_eq!(code(f.call(m, json!({})).await), ErrorCode::Internal, "{m}");
    }
    assert_eq!(
        code(f.call("node.test", json!({ "ids": [] })).await),
        ErrorCode::KernelUnavailable
    );
    assert_eq!(
        code(
            f.call(
                "node.import",
                json!({ "kind": "subscription", "name": "s", "url": "https://sub.example.com/s" })
            )
            .await
        ),
        ErrorCode::NodeImportFailed
    );
}

const TROJAN: &str = "trojan://hunter2-node-secret@tj.example.com:443?sni=tj.example.com#香港 01";

#[tokio::test]
async fn node_import_and_list_round_trip() {
    let f = fixture("nodes");
    let text = format!("{TROJAN}\nssr://abc\n\nhy2://pw@[2001:db8::1]:443#v6");
    let r = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": text }),
        )
        .await
        .expect("import");
    assert_eq!(
        r,
        json!({ "added": 2, "skipped": 1, "issues": [ { "line": 2, "reason": "unsupported_protocol" } ] })
    );

    let list = f.call("node.list", json!({})).await.expect("list");
    let nodes = list["nodes"].as_array().expect("nodes");
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0]["name"], "香港 01");
    assert_eq!(nodes[0]["protocol"], "trojan");
    assert_eq!(nodes[0]["server"], "tj.example.com:443");
    assert_eq!(nodes[0]["credential"], "set");
    assert_eq!(nodes[1]["protocol"], "hysteria2");
    assert_eq!(nodes[1]["server"], "[2001:db8::1]:443");
    let outbounds = list["outbounds"].as_array().expect("outbounds");
    assert_eq!(outbounds[0]["tag"], nodes[0]["id"]);
    assert_eq!(outbounds[0]["kind"], "single");
    assert_eq!(outbounds[0]["members"], json!([nodes[0]["id"]]));
    assert_eq!(list["subscriptions"], json!([]));
    // C-SEC-04：凭据既不在响应里，也不以明文落盘
    assert!(!list.to_string().contains("hunter2"), "{list}");
    let on_disk =
        std::fs::read_to_string(f.dir.join("node-store").join("nodes.json")).expect("read");
    assert!(!on_disk.contains("hunter2"));
    assert!(on_disk.contains("tj.example.com"));

    // 再次导入同一条链接：按重复跳过，不产生新节点
    let again = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": TROJAN }),
        )
        .await
        .expect("import");
    assert_eq!(
        again,
        json!({ "added": 0, "skipped": 1, "issues": [ { "line": 1, "reason": "duplicate" } ] })
    );
    let list = f.call("node.list", json!({})).await.expect("list");
    assert_eq!(list["nodes"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn node_import_reports_whole_input_problems() {
    let f = fixture("nodes-bad");
    let r = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": "proxies:\n  - name: a" }),
        )
        .await
        .expect("import");
    assert_eq!(
        r,
        json!({ "added": 0, "skipped": 0, "issues": [ { "line": 0, "reason": "clash_yaml_unsupported" } ] })
    );
    assert_eq!(
        code(
            f.call("node.import", json!({ "kind": "share_links" }))
                .await
        ),
        ErrorCode::IpcInvalidParams
    );
}

/// 把 tracing 输出收集到内存里。
#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut *self.0.lock().expect("capture lock"), buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Capture {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("capture lock")).into_owned()
    }
}

/// 端到端：真实管道 + 真实处理函数，审计日志有记录且不含任何请求内容。
#[tokio::test]
async fn mutating_calls_are_audited_without_their_params() {
    let capture = Capture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    // 默认的 #[tokio::test] 是单线程运行时，服务端任务都在本线程上，线程局部的订阅者能收到全部日志。
    let _guard = tracing::subscriber::set_default(subscriber);

    let f = fixture("audit");
    let name = format!(r"\\.\pipe\ProcRoute.Test.audit.{}", std::process::id());
    let (tx, rx) = watch::channel(false);
    let services = services(&f.dir);
    let config = ServerConfig {
        pipe_name: name.clone(),
        client_auth: ClientAuth::Disabled,
    };
    let server = tokio::spawn(serve(config, Arc::new(services), rx));

    let pipe = loop {
        match ClientOptions::new().open(&name) {
            Ok(p) => break p,
            Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
        }
    };
    let (r, mut w) = tokio::io::split(pipe);
    let mut r = BufReader::new(r);
    let marker = "hunter2-marker-should-never-be-logged";
    let mut p = sample("p1", marker);
    p.groups[0].outbound = marker.into();
    let requests = [
        json!({ "jsonrpc": "2.0", "id": 1, "method": "ipc.hello",
                "params": { "protocol_version": IPC_PROTOCOL_VERSION, "client_version": marker } }),
        json!({ "jsonrpc": "2.0", "id": 2, "method": "profile.save", "params": p }),
        json!({ "jsonrpc": "2.0", "id": 3, "method": "profile.delete", "params": { "id": "missing" } }),
        json!({ "jsonrpc": "2.0", "id": 4, "method": "node.import",
                "params": { "kind": "share_links", "text": format!("trojan://{marker}@h.example.com:443#{marker}") } }),
    ];
    for req in requests {
        let mut line = serde_json::to_vec(&req).expect("encode");
        line.push(b'\n');
        w.write_all(&line).await.expect("write");
        let mut resp = String::new();
        r.read_line(&mut resp).await.expect("read");
        assert!(resp.contains(&format!("\"id\":{}", req["id"])), "{resp}");
    }
    tx.send(true).expect("stop");
    server.await.expect("join").expect("serve");

    let logs = capture.text();
    let audit: Vec<_> = logs.lines().filter(|l| l.contains(" audit: ")).collect();
    assert_eq!(audit.len(), 3, "one record per mutating call:\n{logs}");
    assert!(
        audit[0].contains("method=\"profile.save\"") && audit[0].contains("outcome=\"ok\""),
        "{logs}"
    );
    assert!(audit[1].contains("outcome=\"profile.not_found\""), "{logs}");
    assert!(
        audit[2].contains("method=\"node.import\"") && audit[2].contains("outcome=\"ok\""),
        "{logs}"
    );
    assert!(
        audit.iter().all(|l| l.contains("caller_sid=S-1-5-")),
        "{logs}"
    );
    assert!(
        !logs.contains(marker),
        "request content leaked into logs:\n{logs}"
    );
}
