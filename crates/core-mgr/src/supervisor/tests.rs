// SPDX-License-Identifier: GPL-3.0-or-later
//! 用锁定版本的 sing-box 测试守护（需要先运行 `cargo xtask fetch-deps`）。
//!
//! 测试用的配置只有直连出站与绑定回环的控制 API：不建 TUN、不改路由，可以在开发机上运行（C-TEST-04）。

use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver};

use procroute_platform_win::hash;

use super::*;
use crate::kernel_lock::locked_kernel;
use crate::runtime::free_loopback_port;

const EVENT_TIMEOUT: Duration = Duration::from_secs(15);
const SECRET: &str = "0123456789abcdefABCDEF0123456789";

/// `third_party/sing-box/bin/sing-box.exe`，与编译进来的锁一致才返回。
fn locked_sing_box() -> PathBuf {
    let exe =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../third_party/sing-box/bin/sing-box.exe");
    let actual = hash::sha256_file(&exe)
        .map(|d| hash::to_hex(&d))
        .unwrap_or_else(|e| {
            panic!("找不到锁定版本的 sing-box（{e}），先运行 `cargo xtask fetch-deps`")
        });
    assert_eq!(
        actual,
        locked_kernel().unwrap().sha256,
        "sing-box.exe 与锁文件不一致，重新运行 `cargo xtask fetch-deps`"
    );
    exe
}

fn work_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "procroute-supervisor-{name}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn api_addr() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, free_loopback_port().unwrap()))
}

fn launch(name: &str, api: SocketAddr, config: String) -> KernelLaunch {
    KernelLaunch {
        exe: locked_sing_box(),
        expected_sha256: locked_kernel().unwrap().sha256,
        config: Secret::new(config),
        working_dir: work_dir(name),
        ready_probe: Some(api),
    }
}

/// 只有直连出站与控制 API 的最小配置。
fn idle_config(api: SocketAddr) -> String {
    serde_json::json!({
        "log": { "level": "warn" },
        "outbounds": [ { "type": "direct", "tag": "direct" } ],
        "experimental": { "clash_api": { "external_controller": api.to_string(), "secret": SECRET } },
    })
    .to_string()
}

fn fast_policy() -> RestartPolicy {
    RestartPolicy {
        delay: Duration::from_millis(50),
        ..RestartPolicy::default()
    }
}

fn start(launch: KernelLaunch, policy: RestartPolicy) -> (Supervisor, Receiver<KernelState>) {
    let (tx, rx) = mpsc::channel();
    let sup = Supervisor::start(launch, policy, move |s| {
        let _ = tx.send(s);
    })
    .expect("kernel starts");
    (sup, rx)
}

fn next(rx: &Receiver<KernelState>) -> KernelState {
    rx.recv_timeout(EVENT_TIMEOUT).expect("kernel state event")
}

fn running_pid(rx: &Receiver<KernelState>) -> u32 {
    match next(rx) {
        KernelState::Running { pid } => pid,
        other => panic!("expected Running, got {other:?}"),
    }
}

fn kill(pid: u32) {
    let status = Command::new("taskkill")
        .args(["/F", "/PID", &pid.to_string()])
        .output()
        .unwrap()
        .status;
    assert!(status.success(), "taskkill {pid} failed");
}

fn api_reachable(api: SocketAddr) -> bool {
    TcpStream::connect_timeout(&api, Duration::from_millis(200)).is_ok()
}

/// 等到控制 API 关闭（内核已退出）。
fn wait_api_closed(api: SocketAddr) {
    let deadline = Instant::now() + EVENT_TIMEOUT;
    while api_reachable(api) {
        assert!(Instant::now() < deadline, "kernel still listening on {api}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn killed_kernel_is_restarted_and_stop_ends_it() {
    let api = api_addr();
    let (sup, rx) = start(launch("restart", api, idle_config(api)), fast_policy());
    let first = running_pid(&rx);
    assert!(api_reachable(api));

    kill(first);
    assert_eq!(next(&rx), KernelState::Restarting { attempt: 1 });
    let second = running_pid(&rx);
    assert_ne!(first, second);

    sup.stop();
    assert_eq!(next(&rx), KernelState::Stopped(StopReason::Requested));
    wait_api_closed(api);
    assert!(rx.try_recv().is_err(), "no events after Stopped");
}

#[test]
fn fourth_crash_within_a_minute_stops_supervision() {
    let api = api_addr();
    let (_sup, rx) = start(launch("crash-loop", api, idle_config(api)), fast_policy());
    let mut pid = running_pid(&rx);
    for attempt in 1..=3 {
        kill(pid);
        assert_eq!(next(&rx), KernelState::Restarting { attempt });
        pid = running_pid(&rx);
    }
    kill(pid);
    assert_eq!(next(&rx), KernelState::Stopped(StopReason::CrashLoop));
    wait_api_closed(api);
}

#[test]
fn dropping_the_supervisor_kills_the_kernel() {
    let api = api_addr();
    let (sup, rx) = start(launch("drop", api, idle_config(api)), fast_policy());
    running_pid(&rx);
    drop(sup);
    assert_eq!(next(&rx), KernelState::Stopped(StopReason::Requested));
    wait_api_closed(api);
}

#[test]
fn control_api_lists_connections() {
    let api = api_addr();
    let (sup, rx) = start(launch("api", api, idle_config(api)), fast_policy());
    running_pid(&rx);
    let conns = crate::clash_api::fetch_connections(
        api,
        &Secret::new(SECRET.to_owned()),
        Duration::from_secs(5),
    )
    .expect("the locked kernel answers /connections");
    assert!(conns.is_empty(), "nothing is routed through an idle kernel");
    // 密钥不对时拒绝
    let wrong = crate::clash_api::fetch_connections(
        api,
        &Secret::new("x".repeat(32)),
        Duration::from_secs(5),
    );
    assert!(
        matches!(wrong, Err(crate::clash_api::ApiError::Status(401))),
        "{wrong:?}"
    );
    sup.stop();
}

#[test]
fn hash_mismatch_refuses_to_start() {
    let api = api_addr();
    let mut l = launch("hash", api, idle_config(api));
    l.expected_sha256 = "0".repeat(64);
    let err = Supervisor::start(l, fast_policy(), |_| {}).unwrap_err();
    assert_eq!(err, LaunchError::HashMismatch);
    assert!(!api_reachable(api));
}

#[test]
fn invalid_config_fails_during_startup() {
    let api = api_addr();
    let l = launch(
        "bad-config",
        api,
        r#"{"inbounds":[{"type":"nope"}]}"#.to_owned(),
    );
    let err = Supervisor::start(l, fast_policy(), |_| {}).unwrap_err();
    assert!(
        matches!(err, LaunchError::ExitedDuringStartup(Some(code)) if code != 0),
        "{err:?}"
    );
}

#[test]
fn startup_times_out_when_the_api_never_opens() {
    // 配置有效但不开控制 API：探测永远连不上
    let api = api_addr();
    let config = serde_json::json!({ "outbounds": [ { "type": "direct", "tag": "direct" } ] });
    let l = launch("timeout", api, config.to_string());
    let policy = RestartPolicy {
        startup_timeout: Duration::from_millis(500),
        ..fast_policy()
    };
    let err = Supervisor::start(l, policy, |_| {}).unwrap_err();
    assert_eq!(err, LaunchError::StartupTimeout);
}

#[test]
fn kernel_binary_cannot_be_modified_while_being_verified() {
    // 校验期间用的共享方式：其他人打开同一文件写入会失败
    let exe = locked_sing_box();
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&exe)
        .unwrap();
    let write = std::fs::OpenOptions::new().write(true).open(&exe);
    assert!(write.is_err(), "writer must be locked out");
    drop(guard);
}
