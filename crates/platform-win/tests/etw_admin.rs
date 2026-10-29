// SPDX-License-Identifier: GPL-3.0-or-later
//! 真实的 ETW 进程事件会话。需要管理员终端（控制实时会话要求管理员或 LocalSystem）：
//!
//! ```text
//! cargo nextest run -p procroute-platform-win --features admin-tests
//! ```
//!
//! 只开一个私有的实时会话、拉起一个 `sort.exe` 子进程，不加载驱动、不改网络与系统设置。
#![cfg(all(windows, feature = "admin-tests"))]

use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use procroute_platform_win::etw::{ProcessEvent, ProcessEventTrace};
use procroute_platform_win::process::process_creation_time;

const NAME: &str = "ProcRoute-Test-ProcessEvents";

fn wait_for(
    rx: &mpsc::Receiver<ProcessEvent>,
    mut pred: impl FnMut(&ProcessEvent) -> bool,
) -> ProcessEvent {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let e = rx.recv_timeout(left).expect("event not seen within 3 s");
        if pred(&e) {
            return e;
        }
    }
}

#[test]
fn child_start_and_stop_arrive_with_its_identity() {
    let (tx, rx) = mpsc::channel();
    let trace = ProcessEventTrace::start(NAME, move |e| {
        let _ = tx.send(e);
    })
    .expect("start the session (run as administrator)");
    assert!(trace.is_running());

    // sort.exe 一直等标准输入结束，期间可以查它的创建时间
    let mut child = Command::new("sort.exe")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn sort.exe");
    let pid = child.id();
    let created = process_creation_time(pid).expect("creation time");
    let started = Instant::now();
    let event = wait_for(
        &rx,
        |e| matches!(e, ProcessEvent::Started { pid: p, .. } if *p == pid),
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "start event within 1 s"
    );
    assert_eq!(
        event,
        ProcessEvent::Started {
            pid,
            parent_pid: std::process::id(),
            created_at: created,
            session_id: procroute_platform_win::process::process_session_id(pid)
                .unwrap_or_default(),
        }
    );

    drop(child.stdin.take());
    child.wait().expect("sort.exe exits");
    let stopped = wait_for(
        &rx,
        |e| matches!(e, ProcessEvent::Stopped { pid: p, .. } if *p == pid),
    );
    assert_eq!(
        stopped,
        ProcessEvent::Stopped {
            pid,
            created_at: created
        }
    );
    trace.stop();
}

#[test]
fn a_leftover_session_with_the_same_name_is_replaced() {
    let name = format!("{NAME}-leftover");
    let first = ProcessEventTrace::start(&name, |_| {}).expect("first");
    // 模拟服务异常退出：不停止会话就再开一个同名的
    std::mem::forget(first);
    let second = ProcessEventTrace::start(&name, |_| {}).expect("replaces the leftover");
    assert!(second.is_running());
    second.stop();
}
