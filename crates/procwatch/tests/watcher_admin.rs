// SPDX-License-Identifier: GPL-3.0-or-later
//! 用真实 ETW 事件追踪进程。需要管理员终端：
//!
//! ```text
//! cargo nextest run -p procroute-procwatch --features admin-tests
//! ```
//!
//! 只开一个私有的实时会话、拉起 `cmd.exe` 与 `sort.exe`，不加载驱动、不改网络与系统设置。
#![cfg(all(windows, feature = "admin-tests"))]

use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use procroute_procwatch::Change;
use procroute_procwatch::watcher::{Options, Source, Watcher};
use procroute_proto::profile::{
    DnsSettings, FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION, Profile,
    UdpSettings,
};
use procroute_rules::engine::RuleEngine;

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

#[test]
fn etw_events_drive_inheritance_within_a_second() {
    let engine = RuleEngine::compile(&Profile {
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
            include_children: true,
            matchers: vec![MatchRule {
                kind: MatchType::Name,
                value: "cmd.exe".into(),
                recursive: false,
            }],
        }],
        exclude: Vec::new(),
    })
    .expect("engine");
    let (tx, rx) = mpsc::channel();
    let w = Watcher::start(
        engine,
        Options {
            session_name: "ProcRoute-Test-ProcWatch".into(),
            // 轮询间隔拉长：这里看到的变化只能来自 ETW 事件
            poll_interval: Duration::from_secs(60),
            ..Options::default()
        },
        move |changes| {
            for c in changes {
                let _ = tx.send(c.clone());
            }
        },
    )
    .expect("start");
    assert_eq!(w.source(), Source::Etw, "run as administrator");

    let mut child = Command::new("cmd.exe")
        .args(["/d", "/c", "sort.exe"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn");
    let cmd = child.id();
    within_a_second(
        &rx,
        |c| matches!(c, Change::Targeted { key, inherited: false, .. } if key.pid == cmd),
    );
    let sort = within_a_second(&rx, |c| {
        matches!(c, Change::Targeted { inherited: true, path: Some(p), .. }
            if p.to_lowercase().ends_with(r"\sort.exe"))
    });
    drop(child.stdin.take());
    child.wait().expect("exit");
    let Change::Targeted { key: sort, .. } = sort else {
        unreachable!("filtered above");
    };
    within_a_second(
        &rx,
        |c| matches!(c, Change::Released { key } if *key == sort),
    );
    within_a_second(
        &rx,
        |c| matches!(c, Change::Released { key } if key.pid == cmd),
    );
    w.stop();
}
