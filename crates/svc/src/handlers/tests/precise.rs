// SPDX-License-Identifier: GPL-3.0-or-later
//! 精确进程模式的会话（T-078）：内核与拦截后端都是假的（开发机上不加载驱动，C-TEST-04），
//! 进程追踪、目标集合、中继是真的。

use std::sync::atomic::Ordering;

use procroute_intercept::divert::socket::{ProcessResolver, SystemProcesses};
use procroute_proto::event::Network;
use procroute_proto::profile::MatchType;

use super::*;

/// 目标进程：系统自带的 `PING.EXE`，跑一会儿再退出。服务自身（测试进程）在排除表里，不能拿来当目标。
fn ping_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\PING.EXE")
}

/// 导入一个节点，保存一个按 [`ping_exe`] 完整路径命中、引用该节点的精确模式方案，返回方案 id。
async fn precise_profile(f: &Fixture, policy: FailPolicy) -> String {
    profile_with(f, policy, |_| {}).await
}

/// 同上，存盘前再改一改方案。
async fn profile_with(
    f: &Fixture,
    policy: FailPolicy,
    change: impl FnOnce(&mut Profile),
) -> String {
    f.call(
        "node.import",
        json!({ "kind": "share_links", "text": TROJAN }),
    )
    .await
    .expect("import");
    let list = f.call("node.list", json!({})).await.expect("list");
    let node_id = list["nodes"][0]["id"].as_str().expect("node id").to_owned();
    let mut p = sample("precise1", "精确方案");
    p.mode = Mode::Precise;
    p.fail_policy = policy;
    p.groups[0].outbound = node_id;
    p.groups[0].matchers[0].kind = MatchType::Path;
    p.groups[0].matchers[0].value = ping_exe();
    change(&mut p);
    f.call("profile.save", to_json(&p).expect("json"))
        .await
        .expect("save");
    p.id
}

fn me() -> ProcessKey {
    SystemProcesses
        .resolve(std::process::id())
        .expect("resolve this process")
}

fn flow(process: ProcessKey) -> NewFlow {
    NewFlow {
        key: FlowKey {
            network: Network::Tcp,
            local: "192.168.1.5:50001".parse().expect("addr"),
            remote: "203.0.113.24:443".parse().expect("addr"),
        },
        process: Some(process),
    }
}

#[tokio::test]
async fn precise_session_starts_kernel_relay_and_backend_and_stops_them() {
    let f = fixture("precise");
    let id = precise_profile(&f, FailPolicy::Block).await;
    let status = f
        .call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    assert_eq!(status["state"], "running");
    assert_eq!(status["mode"], "precise");
    assert_eq!(status["components"]["driver"], "active");
    assert_eq!(status["components"]["kernel"], "active");

    // sing-box 只有本地 SOCKS 入口：绑定回环、每次启动随机密码，用户名是组标签（C-NET-08）
    let (config, _) = f.launcher.launches.lock().expect("launches")[0].clone();
    let config: Value = serde_json::from_str(&config).expect("config is JSON");
    let inbound = &config["inbounds"][0];
    assert_eq!(inbound["type"], "socks");
    assert_eq!(inbound["listen"], "127.0.0.1");
    assert_eq!(inbound["users"][0]["username"], "game");
    let password = inbound["users"][0]["password"].as_str().expect("password");
    assert!(password.len() >= 32, "random per-start password");

    // 中继在回环上
    let relays = f.backends.created.lock().expect("created")[0].0;
    assert!(relays.v4.ip().is_loopback(), "{relays:?}");
    assert!(relays.v6.is_none_or(|v6| v6.ip().is_loopback()));

    // 后端按目标集合判定：启动后才出现的目标进程（追踪还没报到）当场判定为 0 号组
    let h = f.backends.handle(0);
    assert_eq!(h.installed_filters(), 1);
    let mut ping = std::process::Command::new(ping_exe())
        .args(["-n", "30", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start ping");
    let target = SystemProcesses.resolve(ping.id()).expect("resolve ping");
    let verdict = h.new_flow(flow(target)).expect("flow");
    let _ = ping.kill();
    let _ = ping.wait();
    assert_eq!(verdict, Verdict::Redirect { group: 0 });
    // 服务自身永远排除（C-NET-05）
    assert_eq!(
        h.new_flow(flow(me())).expect("flow"),
        Verdict::Bypass(BypassReason::Excluded)
    );
    let ghost = ProcessKey {
        pid: 0x7fff_fff0,
        created_at: 1,
    };
    assert_eq!(
        h.new_flow(flow(ghost)).expect("flow"),
        Verdict::Bypass(BypassReason::NotTarget)
    );

    let stopped = f.call("session.stop", json!({})).await.expect("stop");
    assert_eq!(stopped["state"], "stopped");
    assert_eq!(stopped["components"]["driver"], "inactive");
    assert_eq!(h.installed_filters(), 0, "filters are withdrawn (C-NET-06)");
    assert_eq!(f.launcher.stopped.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn precise_session_refuses_to_run_without_the_driver() {
    let f = fixture_with_backends(
        "precise-no-driver",
        FakeBackends {
            fail: true,
            ..FakeBackends::default()
        },
    );
    let id = precise_profile(&f, FailPolicy::Block).await;
    let err = f
        .call("session.start", json!({ "profile_id": id }))
        .await
        .expect_err("no driver");
    assert_eq!(err.code, ErrorCode::DriverNotLoaded);
    assert!(err.message.contains("access denied"), "{}", err.message);
    // 已经启动的内核再停掉，不留半个会话
    assert_eq!(f.launcher.launch_count(), 1);
    assert_eq!(f.launcher.stopped.load(Ordering::SeqCst), 1);
    assert_eq!(f.services.session_snapshot(), session::initial_status());
}

#[tokio::test]
async fn precise_block_keeps_intercepting_when_the_kernel_gives_up() {
    // C-NET-03：内核不在时目标进程的新连接被中继重置，不能撤下拦截让它们直连
    let f = fixture("precise-block");
    let id = precise_profile(&f, FailPolicy::Block).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    f.launcher
        .report(0, KernelState::Stopped(StopReason::CrashLoop));
    let s = f.services.session_snapshot();
    assert_eq!(s.state, SessionState::Blocked);
    assert_eq!(s.components.kernel, ComponentState::Failed);
    let h = f.backends.handle(0);
    assert_eq!(h.installed_filters(), 1, "still intercepting");
    f.call("session.stop", json!({})).await.expect("stop");
    assert_eq!(h.installed_filters(), 0);
}

#[tokio::test]
async fn precise_allow_withdraws_interception_when_the_kernel_gives_up() {
    // 用户显式选择放行：会话结束，拦截随之撤下，目标进程回到直连
    let f = fixture("precise-allow");
    let id = precise_profile(&f, FailPolicy::Allow).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    let h = f.backends.handle(0);
    f.launcher
        .report(0, KernelState::Stopped(StopReason::CrashLoop));
    let s = f.services.session_snapshot();
    assert_eq!(s.state, SessionState::Stopped);
    assert_eq!(s.components.kernel, ComponentState::Failed);
    assert_eq!(s.components.driver, ComponentState::Inactive);
    assert_eq!(h.installed_filters(), 0, "interception withdrawn");
    // 再次启动时收尾上一个会话
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("restart");
    assert_eq!(f.backends.handle(1).installed_filters(), 1);
    f.call("session.stop", json!({})).await.expect("stop");
}

#[tokio::test]
async fn block_sessions_block_the_targets_other_protocols_until_they_stop() {
    // C-NET-07：拦截层管不到的协议按 fail_policy。完整路径规则的目标一开始就挡住
    let f = fixture("protocols-block");
    let id = precise_profile(&f, FailPolicy::Block).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    assert_eq!(*f.protocols.opened.lock().expect("opened"), [false]);
    assert_eq!(*f.protocols.targets.lock().expect("targets"), [ping_exe()]);
    assert_eq!(f.protocols.closed.load(Ordering::SeqCst), 0);
    f.call("session.stop", json!({})).await.expect("stop");
    assert_eq!(f.protocols.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn targets_found_by_tracking_are_blocked_too() {
    // 名称规则要等进程追踪报到
    let f = fixture("protocols-tracked");
    let id = profile_with(&f, FailPolicy::Block, |p| {
        p.groups[0].matchers[0].kind = MatchType::Name;
        p.groups[0].matchers[0].value = "ping.exe".into();
    })
    .await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    let mut ping = std::process::Command::new(ping_exe())
        .args(["-n", "30", "127.0.0.1"])
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("start ping");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let seen = loop {
        let targets = f.protocols.targets.lock().expect("targets").clone();
        if !targets.is_empty() || std::time::Instant::now() >= deadline {
            break targets;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    };
    let _ = ping.kill();
    let _ = ping.wait();
    f.call("session.stop", json!({})).await.expect("stop");
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert!(seen[0].to_lowercase().ends_with("ping.exe"), "{seen:?}");
}

#[tokio::test]
async fn allow_sessions_install_no_filters_unless_ping_is_blocked() {
    // `allow` 是用户选择的放行，不碰任何过滤器；开关打开时只挡 ping，不挡目标进程的其他协议
    let f = fixture("protocols-allow");
    let id = precise_profile(&f, FailPolicy::Allow).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    f.call("session.stop", json!({})).await.expect("stop");
    assert!(f.protocols.opened.lock().expect("opened").is_empty());

    let id = profile_with(&f, FailPolicy::Allow, |p| p.icmp.block_all_ping = true).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    assert_eq!(*f.protocols.opened.lock().expect("opened"), [true]);
    assert!(f.protocols.targets.lock().expect("targets").is_empty());
    f.call("session.stop", json!({})).await.expect("stop");
}

#[tokio::test]
async fn sessions_refuse_to_start_without_the_filters_they_need() {
    let f = fixture_with_protocols(
        "protocols-unavailable",
        FakeProtocols {
            fail: true,
            ..FakeProtocols::default()
        },
    );
    let id = profile_with(&f, FailPolicy::Allow, |p| p.icmp.block_all_ping = true).await;
    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": id })).await),
        ErrorCode::SessionFailClosedUnsupported
    );
    assert_eq!(f.launcher.launch_count(), 0, "nothing was launched");
    assert_eq!(f.services.session_snapshot().state, SessionState::Stopped);
    // 不需要过滤器的方案不受影响
    let id = precise_profile(&f, FailPolicy::Allow).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    f.call("session.stop", json!({})).await.expect("stop");
}

#[tokio::test]
async fn a_failed_start_closes_the_filters_again() {
    let f = fixture_with_backends(
        "protocols-failed-start",
        FakeBackends {
            fail: true,
            ..FakeBackends::default()
        },
    );
    let id = precise_profile(&f, FailPolicy::Block).await;
    assert_eq!(
        code(f.call("session.start", json!({ "profile_id": id })).await),
        ErrorCode::DriverNotLoaded
    );
    assert_eq!(f.protocols.opened.lock().expect("opened").len(), 1);
    assert_eq!(f.protocols.closed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn filters_follow_the_session_when_the_kernel_gives_up() {
    let gave_up = KernelState::Stopped(StopReason::CrashLoop);
    // `allow`：会话结束，ping 不能还被挡着
    let f = fixture("protocols-give-up-allow");
    let id = profile_with(&f, FailPolicy::Allow, |p| p.icmp.block_all_ping = true).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    f.launcher.report(0, gave_up.clone());
    assert_eq!(f.services.session_snapshot().state, SessionState::Stopped);
    assert_eq!(f.protocols.closed.load(Ordering::SeqCst), 1);

    // `block`：会话还在（blocked），过滤器也还在，直到用户停止
    let f = fixture("protocols-give-up-block");
    let id = profile_with(&f, FailPolicy::Block, |p| p.icmp.block_all_ping = true).await;
    f.call("session.start", json!({ "profile_id": id }))
        .await
        .expect("start");
    f.launcher.report(0, gave_up);
    assert_eq!(f.services.session_snapshot().state, SessionState::Blocked);
    assert_eq!(f.protocols.closed.load(Ordering::SeqCst), 0);
    f.call("session.stop", json!({})).await.expect("stop");
    assert_eq!(f.protocols.closed.load(Ordering::SeqCst), 1);
}
