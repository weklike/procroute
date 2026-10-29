// SPDX-License-Identifier: GPL-3.0-or-later
//! 处理函数的测试。存储目录放在临时目录；端到端的审计测试走真实命名管道（不注册服务）。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use procroute_core_mgr::supervisor::{KernelState, LaunchError, StopReason};
use procroute_platform_win::secret::Secret;
use procroute_proto::IPC_PROTOCOL_VERSION;
use procroute_proto::methods;
use procroute_proto::profile::{FailPolicy, Mode, Profile};
use procroute_proto::session::{ComponentState, SessionState};
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::watch;

use super::*;
use crate::client_auth::ClientAuth;
use crate::ipc_server::{Caller, ServerConfig, serve};
use crate::kernel::{RunningKernel, StateCallback};
use crate::node_store::NodeStore;
use crate::store::tests::sample;

/// 假内核：记录收到的配置与控制 API 地址，留下状态回调供测试模拟守护的上报。
#[derive(Default)]
struct FakeLauncher {
    fail: bool,
    launches: Mutex<Vec<(String, SocketAddr)>>,
    callbacks: Mutex<Vec<StateCallback>>,
    stopped: Arc<AtomicUsize>,
}

impl FakeLauncher {
    fn failing() -> Self {
        Self {
            fail: true,
            ..Self::default()
        }
    }

    /// 以第 `i` 次启动的身份上报一个内核状态。
    fn report(&self, i: usize, state: KernelState) {
        (self.callbacks.lock().expect("callbacks")[i])(state);
    }

    fn launch_count(&self) -> usize {
        self.launches.lock().expect("launches").len()
    }
}

impl KernelLauncher for FakeLauncher {
    fn launch(
        &self,
        config: Secret<String>,
        api: SocketAddr,
        on_state: StateCallback,
    ) -> Result<Box<dyn RunningKernel>, LaunchError> {
        if self.fail {
            return Err(LaunchError::ExitedDuringStartup(Some(1)));
        }
        self.launches
            .lock()
            .expect("launches")
            .push((config.expose().clone(), api));
        on_state(KernelState::Running { pid: 42 });
        self.callbacks.lock().expect("callbacks").push(on_state);
        Ok(Box::new(FakeKernel {
            stopped: self.stopped.clone(),
        }))
    }
}

struct FakeKernel {
    stopped: Arc<AtomicUsize>,
}

impl RunningKernel for FakeKernel {
    fn stop(self: Box<Self>) {
        self.stopped.fetch_add(1, Ordering::SeqCst);
    }
}

struct Fixture {
    services: Services,
    launcher: Arc<FakeLauncher>,
    dir: PathBuf,
    caller: Caller,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture(tag: &str) -> Fixture {
    fixture_with(tag, FakeLauncher::default())
}

fn fixture_with(tag: &str, launcher: FakeLauncher) -> Fixture {
    let dir = std::env::temp_dir().join(format!("procroute-handlers-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let launcher = Arc::new(launcher);
    Fixture {
        services: services_with(&dir, launcher.clone()),
        launcher,
        dir,
        caller: Caller {
            // 用测试进程自己：`process.list` 要按调用者的会话过滤
            pid: std::process::id(),
            image: r"C:\Program Files\ProcRoute\procroute-ui.exe".into(),
            sid: "S-1-5-21-1-2-3-1001".into(),
        },
    }
}

/// 方案目录与节点文件分开放，和正式布局一致（`profiles\` 与 `nodes.json`）。
fn services(dir: &std::path::Path) -> Services {
    services_with(dir, Arc::new(FakeLauncher::default()))
}

fn services_with(dir: &std::path::Path, launcher: Arc<FakeLauncher>) -> Services {
    Services::new(
        ProfileStore::open(dir).expect("store"),
        NodeStore::open(dir.join("node-store").join("nodes.json")).expect("node store"),
        tokio::sync::broadcast::channel(16).0,
        launcher,
        vec![
            r"C:\Program Files\ProcRoute\procroute-svc.exe".into(),
            r"C:\Program Files\ProcRoute\procroute-ui.exe".into(),
        ],
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
async fn session_reports_truthfully_and_refuses_what_it_cannot_do_safely() {
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
    // 精确进程模式：拦截驱动尚未接入
    let p = sample("p1", "x");
    assert_eq!(p.mode, Mode::Precise);
    f.call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": "p1" })).await),
        ErrorCode::DriverNotLoaded
    );
    // TUN + 阻断：内核退出时无法阻断目标进程（C-NET-03）
    let mut tun_block = sample("p2", "y");
    tun_block.mode = Mode::Tun;
    tun_block.fail_policy = FailPolicy::Block;
    f.call("profile.save", to_json(&tun_block).expect("json"))
        .await
        .expect("save");
    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": "p2" })).await),
        ErrorCode::SessionFailClosedUnsupported
    );
    assert_eq!(f.launcher.launch_count(), 0, "nothing was launched");
    let after = f.services.session_snapshot();
    assert_eq!(after.state, SessionState::Stopped);
    assert_eq!(after.components.kernel, ComponentState::Inactive);
}

/// 导入一个节点，保存一个引用它的 TUN + 放行方案，返回方案 id。
async fn tun_allow_profile(f: &Fixture) -> String {
    f.call(
        "node.import",
        json!({ "kind": "share_links", "text": TROJAN }),
    )
    .await
    .expect("import");
    let list = f.call("node.list", json!({})).await.expect("list");
    let node_id = list["nodes"][0]["id"].as_str().expect("node id").to_owned();
    let mut p = sample("tun1", "TUN 方案");
    p.mode = Mode::Tun;
    p.fail_policy = FailPolicy::Allow;
    p.groups[0].outbound = node_id;
    f.call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    p.id
}

#[tokio::test]
async fn tun_session_starts_with_a_generated_config_and_stops() {
    let f = fixture("tun");
    let id = tun_allow_profile(&f).await;
    let status = f
        .call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    assert_eq!(status["state"], "running");
    assert_eq!(status["profile_id"], id.as_str());
    assert_eq!(status["mode"], "tun");
    assert_eq!(status["components"]["kernel"], "active");

    let (config, api) = f.launcher.launches.lock().expect("launches")[0].clone();
    let config: Value = serde_json::from_str(&config).expect("config is JSON");
    assert_eq!(config["inbounds"][0]["type"], "tun");
    assert_eq!(
        config["experimental"]["clash_api"]["external_controller"],
        api.to_string()
    );
    assert!(
        api.ip().is_loopback(),
        "control API binds loopback (C-NET-08)"
    );
    let secret = config["experimental"]["clash_api"]["secret"]
        .as_str()
        .expect("secret");
    assert!(secret.len() >= 32, "random per-start secret");
    assert!(
        config.to_string().contains("hunter2-node-secret"),
        "node credentials reach the kernel"
    );

    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": id })).await),
        ErrorCode::SessionAlreadyRunning
    );
    assert_eq!(
        code(f.call("profile.delete", json!({ "id": id })).await),
        ErrorCode::ProfileInUse
    );
    let list = f.call("profile.list", json!({})).await.expect("list");
    assert_eq!(list["profiles"][0]["active"], true);

    let stopped = f.call("session.stop", json!({})).await.expect("stop");
    assert_eq!(stopped["state"], "stopped");
    assert_eq!(stopped["components"]["kernel"], "inactive");
    assert_eq!(stopped["profile_id"], Value::Null);
    assert_eq!(f.launcher.stopped.load(Ordering::SeqCst), 1);
    assert_eq!(
        code(f.call("session.stop", json!({})).await),
        ErrorCode::SessionNotRunning
    );
}

#[tokio::test]
async fn kernel_reports_drive_the_session_and_stale_ones_are_ignored() {
    let f = fixture("kernel-events");
    let id = tun_allow_profile(&f).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    f.launcher.report(0, KernelState::Restarting { attempt: 1 });
    assert_eq!(
        f.services.session_snapshot().components.kernel,
        ComponentState::Restarting
    );
    f.launcher.report(0, KernelState::Running { pid: 43 });
    assert_eq!(
        f.services.session_snapshot().components.kernel,
        ComponentState::Active
    );
    // 放行策略下超出重启上限：会话结束，内核显示失败
    f.launcher
        .report(0, KernelState::Stopped(StopReason::CrashLoop));
    let s = f.services.session_snapshot();
    assert_eq!(s.state, SessionState::Stopped);
    assert_eq!(s.components.kernel, ComponentState::Failed);

    // 重新启动时先收尾上一个守护
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("restart the session");
    assert_eq!(f.launcher.stopped.load(Ordering::SeqCst), 1);
    // 旧会话的回调不再改写状态
    f.launcher
        .report(0, KernelState::Stopped(StopReason::CrashLoop));
    assert_eq!(f.services.session_snapshot().state, SessionState::Running);
    f.call("session.stop", json!({})).await.expect("stop");
    f.launcher.report(1, KernelState::Restarting { attempt: 1 });
    assert_eq!(f.services.session_snapshot(), session::initial_status());
}

#[tokio::test]
async fn failed_launch_is_reported_and_leaves_the_session_stopped() {
    let f = fixture_with("launch-fails", FakeLauncher::failing());
    let id = tun_allow_profile(&f).await;
    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": id })).await),
        ErrorCode::KernelUnavailable
    );
    let s = f.services.session_snapshot();
    assert_eq!(s.state, SessionState::Stopped);
    assert_eq!(s.components.kernel, ComponentState::Failed);
    assert_eq!(s.profile_id, None);
}

#[tokio::test]
async fn profiles_referencing_missing_outbounds_do_not_start() {
    let f = fixture("missing-outbound");
    let mut p = sample("tun2", "x");
    p.mode = Mode::Tun;
    p.fail_policy = FailPolicy::Allow;
    p.groups[0].outbound = "no-such-node".into();
    f.call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    assert_eq!(
        code(
            f.call("session.start", json!({ "profile_id": "tun2" }))
                .await
        ),
        ErrorCode::NodeNotFound
    );
    assert_eq!(f.launcher.launch_count(), 0);
    assert_eq!(f.services.session_snapshot().state, SessionState::Stopped);
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
async fn process_list_shows_this_session_and_marks_matches() {
    let f = fixture("processes");
    let me = std::process::id();
    let exe = std::env::current_exe().expect("current exe");
    let file = exe
        .file_name()
        .expect("file name")
        .to_string_lossy()
        .into_owned();

    let find = |list: &Value| {
        list["processes"]
            .as_array()
            .expect("processes")
            .iter()
            .find(|p| p["pid"] == me)
            .cloned()
            .expect("the test process is listed")
    };
    let list = f.call("process.list", json!({})).await.expect("list");
    let entry = find(&list);
    assert!(
        entry["name"]
            .as_str()
            .expect("name")
            .eq_ignore_ascii_case(&file)
    );
    assert!(
        entry["path"]
            .as_str()
            .expect("path")
            .eq_ignore_ascii_case(&exe.to_string_lossy())
    );
    assert_eq!(
        entry["matched_group"],
        Value::Null,
        "no session, no matches"
    );

    // 运行一个按名称命中测试进程的 TUN 会话
    f.call(
        "node.import",
        json!({ "kind": "share_links", "text": TROJAN }),
    )
    .await
    .expect("import");
    let nodes = f.call("node.list", json!({})).await.expect("nodes");
    let mut p = sample("self", "self");
    p.mode = Mode::Tun;
    p.fail_policy = FailPolicy::Allow;
    p.groups[0].outbound = nodes["nodes"][0]["id"].as_str().expect("id").to_owned();
    p.groups[0].matchers[0].value = file.clone();
    f.call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    f.call("session.start", json!({ "profile_id": "self" }))
        .await
        .expect("start");
    let list = f.call("process.list", json!({})).await.expect("list");
    assert_eq!(find(&list)["matched_group"], "game");
    // 命中的排在最前
    assert_ne!(list["processes"][0]["matched_group"], Value::Null);
    f.call("session.stop", json!({})).await.expect("stop");
}

#[tokio::test]
async fn unwired_methods_fail_explicitly() {
    let f = fixture("unwired");
    for m in ["driver.status"] {
        assert_eq!(code(f.call(m, json!({})).await), ErrorCode::Internal, "{m}");
    }
    assert_eq!(
        code(f.call("node.test", json!({ "ids": [] })).await),
        ErrorCode::KernelUnavailable
    );
}

const TROJAN: &str = "trojan://hunter2-node-secret@tj.example.com:443?sni=tj.example.com#香港 01";

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

mod nodes;
