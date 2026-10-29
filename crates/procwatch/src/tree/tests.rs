// SPDX-License-Identifier: GPL-3.0-or-later
use procroute_proto::profile::{
    DnsSettings, FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION, Profile,
    UdpSettings,
};

use super::*;

fn rule(kind: MatchType, value: &str) -> MatchRule {
    MatchRule {
        kind,
        value: value.into(),
        recursive: false,
    }
}

/// 组 0 `launcher`：launcher.exe，子进程继承；组 1 `tool`：tool.exe，不继承。排除 updater.exe。
fn engine() -> RuleEngine {
    engine_for(vec![
        Group {
            tag: "launcher".into(),
            outbound: "hk".into(),
            include_children: true,
            matchers: vec![rule(MatchType::Name, "launcher.exe")],
        },
        Group {
            tag: "tool".into(),
            outbound: "hk".into(),
            include_children: false,
            matchers: vec![rule(MatchType::Path, r"C:\Tools\tool.exe")],
        },
    ])
}

fn engine_for(groups: Vec<Group>) -> RuleEngine {
    RuleEngine::compile(&Profile {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: "p".into(),
        name: "p".into(),
        mode: Mode::Precise,
        fail_policy: FailPolicy::Block,
        dns: DnsSettings::default(),
        udp: UdpSettings::default(),
        groups,
        exclude: vec![rule(MatchType::Name, "updater.exe")],
    })
    .expect("engine")
}

fn key(pid: u32, created_at: u64) -> ProcessKey {
    ProcessKey { pid, created_at }
}

fn proc(pid: u32, created_at: u64, parent_pid: u32, path: &str) -> ProcessInfo {
    ProcessInfo {
        key: key(pid, created_at),
        parent_pid,
        name: String::new(),
        path: Some(path.into()),
    }
}

fn start(tree: &mut ProcessTree, p: ProcessInfo) -> Vec<Change> {
    let mut out = Vec::new();
    tree.started(p, &mut out);
    out
}

fn targeted_keys(changes: &[Change]) -> Vec<(ProcessKey, usize, bool)> {
    changes
        .iter()
        .filter_map(|c| match c {
            Change::Targeted {
                key,
                group,
                inherited,
                ..
            } => Some((*key, *group, *inherited)),
            Change::Released { .. } => None,
        })
        .collect()
}

#[test]
fn matching_processes_enter_the_target_set() {
    let mut t = ProcessTree::new(engine());
    let c = start(&mut t, proc(100, 10, 4, r"C:\Games\Launcher.exe"));
    assert_eq!(
        c,
        [Change::Targeted {
            key: key(100, 10),
            group: 0,
            inherited: false,
            name: String::new(),
            path: Some(r"C:\Games\Launcher.exe".into()),
        }]
    );
    assert!(start(&mut t, proc(200, 11, 4, r"C:\Windows\notepad.exe")).is_empty());
    assert_eq!(t.decision(&key(100, 10)), Decision::Group(0));
    assert_eq!(t.decision(&key(200, 11)), Decision::Direct);
    assert_eq!(t.targets().collect::<Vec<_>>(), [(key(100, 10), 0)]);
    assert_eq!(t.len(), 2);
}

#[test]
fn children_inherit_only_when_the_group_allows_it() {
    let mut t = ProcessTree::new(engine());
    start(&mut t, proc(100, 10, 4, r"C:\Games\launcher.exe"));
    start(&mut t, proc(300, 10, 4, r"C:\Tools\tool.exe"));
    // launcher 的子进程与孙进程继承组 0
    let c = start(&mut t, proc(101, 20, 100, r"C:\Games\game.exe"));
    assert_eq!(targeted_keys(&c), [(key(101, 20), 0, true)]);
    let c = start(&mut t, proc(102, 30, 101, r"C:\Games\crash.exe"));
    assert_eq!(targeted_keys(&c), [(key(102, 30), 0, true)]);
    // 排除规则优先于继承
    assert!(start(&mut t, proc(103, 31, 100, r"C:\Games\updater.exe")).is_empty());
    // tool 不开继承
    assert!(start(&mut t, proc(301, 40, 300, r"C:\Tools\helper.exe")).is_empty());
    // 自身命中的子进程按自身判定，不算继承
    let c = start(&mut t, proc(302, 41, 100, r"C:\Tools\tool.exe"));
    assert_eq!(targeted_keys(&c), [(key(302, 41), 1, false)]);
}

#[test]
fn a_reused_parent_pid_is_not_inherited_from() {
    let mut t = ProcessTree::new(engine());
    // 记录里的父 PID 属于一个更晚创建的目标进程：真正的父进程早已退出（C-DRV-04）
    start(&mut t, proc(100, 50, 4, r"C:\Games\launcher.exe"));
    assert!(start(&mut t, proc(500, 40, 100, r"C:\x\other.exe")).is_empty());
}

#[test]
fn stop_events_must_match_the_creation_time() {
    let mut t = ProcessTree::new(engine());
    start(&mut t, proc(100, 10, 4, r"C:\Games\launcher.exe"));
    let mut out = Vec::new();
    t.stopped(key(100, 9), &mut out);
    assert!(
        out.is_empty() && t.contains(&key(100, 10)),
        "stale stop ignored"
    );
    t.stopped(key(100, 10), &mut out);
    assert_eq!(out, [Change::Released { key: key(100, 10) }]);
    assert!(t.is_empty());
    // 非目标进程退出不产生变化
    start(&mut t, proc(200, 11, 4, r"C:\Windows\notepad.exe"));
    out.clear();
    t.stopped(key(200, 11), &mut out);
    assert!(out.is_empty() && t.is_empty());
}

#[test]
fn pid_reuse_replaces_the_old_process() {
    let mut t = ProcessTree::new(engine());
    start(&mut t, proc(100, 10, 4, r"C:\Games\launcher.exe"));
    // 退出事件丢了，同一个 PID 来了个新进程
    let c = start(&mut t, proc(100, 99, 4, r"C:\Windows\notepad.exe"));
    assert_eq!(c, [Change::Released { key: key(100, 10) }]);
    assert_eq!(t.decision(&key(100, 99)), Decision::Direct);
    assert!(!t.contains(&key(100, 10)));
    // 重复与过时的启动都不改变状态
    assert!(start(&mut t, proc(100, 99, 4, r"C:\Games\launcher.exe")).is_empty());
    assert!(start(&mut t, proc(100, 50, 4, r"C:\Games\launcher.exe")).is_empty());
    assert_eq!(t.decision(&key(100, 99)), Decision::Direct);
}

#[test]
fn reconcile_registers_parents_first_and_drops_vanished_processes() {
    let mut t = ProcessTree::new(engine());
    start(&mut t, proc(900, 1, 4, r"C:\Games\launcher.exe"));
    // 快照里子进程排在父进程前面，且 900 已经不在
    let mut out = Vec::new();
    t.reconcile(
        vec![
            proc(101, 20, 100, r"C:\Games\game.exe"),
            proc(100, 10, 4, r"C:\Games\launcher.exe"),
        ],
        &mut out,
    );
    assert_eq!(out[0], Change::Released { key: key(900, 1) });
    assert_eq!(
        targeted_keys(&out),
        [(key(100, 10), 0, false), (key(101, 20), 0, true)]
    );
    // 再次校正同样的快照：没有变化
    out.clear();
    t.reconcile(
        vec![
            proc(100, 10, 4, r"C:\Games\launcher.exe"),
            proc(101, 20, 100, r"C:\Games\game.exe"),
        ],
        &mut out,
    );
    assert!(out.is_empty());
}

#[test]
fn switching_profiles_reports_only_what_changed() {
    let mut t = ProcessTree::new(engine());
    start(&mut t, proc(100, 10, 4, r"C:\Games\launcher.exe"));
    start(&mut t, proc(101, 20, 100, r"C:\Games\game.exe"));
    start(&mut t, proc(200, 30, 4, r"C:\Windows\notepad.exe"));

    // 新方案：launcher 不再继承，notepad 进组
    let mut out = Vec::new();
    t.set_engine(
        engine_for(vec![
            Group {
                tag: "launcher".into(),
                outbound: "hk".into(),
                include_children: false,
                matchers: vec![rule(MatchType::Name, "launcher.exe")],
            },
            Group {
                tag: "editor".into(),
                outbound: "hk".into(),
                include_children: false,
                matchers: vec![rule(MatchType::Dir, r"C:\Windows")],
            },
        ]),
        &mut out,
    );
    assert_eq!(out.len(), 2, "{out:?}");
    assert!(out.contains(&Change::Released { key: key(101, 20) }));
    assert_eq!(targeted_keys(&out), [(key(200, 30), 1, false)]);
    assert_eq!(t.decision(&key(100, 10)), Decision::Group(0));
}

#[test]
fn processes_without_a_path_match_by_name_and_inheritance() {
    let mut t = ProcessTree::new(engine());
    let unknown = |pid, created_at, parent_pid, name: &str| ProcessInfo {
        key: key(pid, created_at),
        parent_pid,
        name: name.into(),
        path: None,
    };
    let c = start(&mut t, unknown(100, 10, 4, "Launcher.exe"));
    assert_eq!(targeted_keys(&c), [(key(100, 10), 0, false)]);
    // 路径规则需要路径；查不到路径的子进程仍可继承
    assert!(start(&mut t, unknown(300, 11, 4, "tool.exe")).is_empty());
    let c = start(&mut t, unknown(101, 12, 100, ""));
    assert_eq!(targeted_keys(&c), [(key(101, 12), 0, true)]);
}
