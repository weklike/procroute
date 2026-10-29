// SPDX-License-Identifier: GPL-3.0-or-later
//! 不需要管理员权限的部分：快照轮询。真实 ETW 见 `tests/watcher_admin.rs`。
//!
//! 用 `sort.exe` 当子进程：它一直读标准输入直到关闭，退出时机由测试控制。

use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};

use procroute_proto::profile::{
    DnsSettings, FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION, Profile,
    UdpSettings,
};

use super::*;

fn engine(name: &str, include_children: bool) -> RuleEngine {
    RuleEngine::compile(&Profile {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: "p".into(),
        name: "p".into(),
        mode: Mode::Precise,
        fail_policy: FailPolicy::Block,
        dns: DnsSettings::default(),
        udp: UdpSettings::default(),
        groups: vec![Group {
            tag: "g".into(),
            outbound: "o".into(),
            include_children,
            matchers: vec![MatchRule {
                kind: MatchType::Name,
                value: name.into(),
                recursive: false,
            }],
        }],
        exclude: Vec::new(),
    })
    .expect("engine")
}

fn polling() -> Options {
    Options {
        use_etw: false,
        poll_interval: Duration::from_millis(100),
        ..Options::default()
    }
}

fn watch(engine: RuleEngine, options: Options) -> (Watcher, Receiver<Change>) {
    let (tx, rx) = mpsc::channel();
    let w = Watcher::start(engine, options, move |changes| {
        for c in changes {
            let _ = tx.send(c.clone());
        }
    })
    .expect("start");
    (w, rx)
}

fn spawn(program: &str, args: &[&str]) -> Child {
    Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn")
}

/// 等第一个满足条件的变化，最多 1 秒（T-079 的验收要求）。
fn within_a_second(rx: &Receiver<Change>, mut pred: impl FnMut(&Change) -> bool) -> Change {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let c = rx.recv_timeout(left).expect("change within 1 s");
        if pred(&c) {
            return c;
        }
    }
}

fn targeted_pid(c: &Change, pid: u32) -> bool {
    matches!(c, Change::Targeted { key, .. } if key.pid == pid)
}

fn released_pid(c: &Change, pid: u32) -> bool {
    matches!(c, Change::Released { key } if key.pid == pid)
}

#[test]
fn a_matching_child_enters_and_leaves_the_target_set() {
    let (w, rx) = watch(engine("sort.exe", false), polling());
    assert_eq!(w.source(), Source::Polling);
    let mut child = spawn("sort.exe", &[]);
    let pid = child.id();
    let c = within_a_second(&rx, |c| targeted_pid(c, pid));
    let Change::Targeted {
        key,
        group,
        inherited,
        path,
        ..
    } = c
    else {
        unreachable!("filtered above");
    };
    assert_eq!(group, 0);
    assert!(!inherited);
    assert_eq!(
        key.created_at,
        procroute_platform_win::process::process_creation_time(pid).expect("creation time")
    );
    assert!(
        path.as_deref()
            .is_some_and(|p| p.to_lowercase().ends_with(r"\sort.exe")),
        "{path:?}"
    );

    drop(child.stdin.take());
    child.wait().expect("exit");
    within_a_second(&rx, |c| released_pid(c, pid));
    w.stop();
}

#[test]
fn children_of_a_target_inherit_its_group() {
    let (w, rx) = watch(engine("cmd.exe", true), polling());
    // cmd 等 sort 结束；sort 继承 cmd 的标准输入
    let mut child = spawn("cmd.exe", &["/d", "/c", "sort.exe"]);
    let cmd = child.id();
    within_a_second(&rx, |c| targeted_pid(c, cmd));
    let sort = within_a_second(&rx, |c| {
        matches!(c, Change::Targeted { inherited: true, path: Some(p), .. }
            if p.to_lowercase().ends_with(r"\sort.exe"))
    });
    drop(child.stdin.take());
    child.wait().expect("exit");
    let Change::Targeted { key, .. } = sort else {
        unreachable!("filtered above");
    };
    within_a_second(&rx, |c| released_pid(c, key.pid));
    w.stop();
}

#[test]
fn switching_the_profile_retargets_running_processes() {
    let (w, rx) = watch(engine("nothing-matches.exe", false), polling());
    let mut child = spawn("sort.exe", &[]);
    let pid = child.id();
    // 等它被登记（下一轮快照），确认没有进组
    std::thread::sleep(Duration::from_millis(300));
    assert!(rx.try_iter().all(|c| !targeted_pid(&c, pid)));
    w.set_engine(engine("sort.exe", false));
    within_a_second(&rx, |c| targeted_pid(c, pid));
    drop(child.stdin.take());
    child.wait().expect("exit");
    w.stop();
}

#[test]
fn already_running_targets_are_reported_before_start_returns() {
    let mut child = spawn("sort.exe", &[]);
    let pid = child.id();
    let (w, rx) = watch(engine("sort.exe", false), polling());
    // 第一次快照在 start 里同步完成
    assert!(rx.try_iter().any(|c| targeted_pid(&c, pid)));
    drop(child.stdin.take());
    child.wait().expect("exit");
    w.stop();
}

#[test]
fn tracking_works_whether_or_not_etw_is_available() {
    // 普通终端里 ETW 会话开不起来，退回快照；管理员终端里走 ETW。两种情况都要在 1 秒内看到
    let (w, rx) = watch(
        engine("sort.exe", false),
        Options {
            session_name: format!("ProcRoute-Test-Watcher-{}", std::process::id()),
            ..Options::default()
        },
    );
    let mut child = spawn("sort.exe", &[]);
    let pid = child.id();
    within_a_second(&rx, |c| targeted_pid(c, pid));
    drop(child.stdin.take());
    child.wait().expect("exit");
    within_a_second(&rx, |c| released_pid(c, pid));
    w.stop();
}
