// SPDX-License-Identifier: GPL-3.0-or-later
//! 负载解码与偏移表的测试。真正启动会话需要管理员权限，见 `tests/etw_admin.rs`。

use std::process::Command;

use super::*;

fn start_v2(pid: u32, created: u64, parent: u32, session: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(pid.to_le_bytes());
    b.extend(created.to_le_bytes());
    b.extend(parent.to_le_bytes());
    b.extend(session.to_le_bytes());
    b.extend(0u32.to_le_bytes()); // Flags
    b.extend([b'a', 0, 0, 0]); // ImageName "a"
    b
}

fn start_v4(pid: u32, created: u64, parent: u32, session: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend(pid.to_le_bytes());
    b.extend(7u64.to_le_bytes()); // ProcessSequenceNumber
    b.extend(created.to_le_bytes());
    b.extend(parent.to_le_bytes());
    b.extend(6u64.to_le_bytes()); // ParentProcessSequenceNumber
    b.extend(session.to_le_bytes());
    b.extend([0u8; 12]); // Flags, ProcessTokenElevationType, ProcessTokenIsElevated
    b
}

#[test]
fn start_events_decode_in_old_and_new_layouts() {
    let expected = ProcessEvent::Started {
        pid: 4120,
        parent_pid: 880,
        created_at: 0x01db_0000_1234_5678,
        session_id: 1,
    };
    for version in 0..=2 {
        assert_eq!(
            decode(1, version, &start_v2(4120, 0x01db_0000_1234_5678, 880, 1)),
            Some(expected)
        );
    }
    for version in [3, 4, 9] {
        assert_eq!(
            decode(1, version, &start_v4(4120, 0x01db_0000_1234_5678, 880, 1)),
            Some(expected),
            "v{version}"
        );
    }
}

#[test]
fn stop_events_decode_in_old_and_new_layouts() {
    let mut v1 = Vec::new();
    v1.extend(4120u32.to_le_bytes());
    v1.extend(99u64.to_le_bytes());
    v1.extend(100u64.to_le_bytes()); // ExitTime
    let mut v2 = Vec::new();
    v2.extend(4120u32.to_le_bytes());
    v2.extend(7u64.to_le_bytes());
    v2.extend(99u64.to_le_bytes());
    let stopped = Some(ProcessEvent::Stopped {
        pid: 4120,
        created_at: 99,
    });
    assert_eq!(decode(2, 0, &v1), stopped);
    assert_eq!(decode(2, 1, &v1), stopped);
    assert_eq!(decode(2, 2, &v2), stopped);
}

#[test]
fn short_payloads_and_other_events_are_ignored() {
    let full = start_v4(1, 2, 3, 4);
    assert_eq!(decode(1, 4, &full[..35]), None);
    assert_eq!(decode(1, 4, &[]), None);
    assert_eq!(decode(2, 2, &[0; 19]), None);
    // 线程启动等其他事件
    assert_eq!(decode(3, 0, &full), None);
}

/// 模板里定长类型的字节数；遇到变长类型返回 `None`。
fn fixed_size(in_type: &str) -> Option<usize> {
    match in_type {
        "win:UInt32" | "win:Int32" | "win:HexInt32" => Some(4),
        "win:UInt64" | "win:Int64" | "win:HexInt64" | "win:FILETIME" => Some(8),
        _ => None,
    }
}

/// 清单里的一个事件模板：(事件 id, 版本, [(字段名, 类型)])。
type Template = (u16, u8, Vec<(String, String)>);

/// 本机清单里的事件模板。只读提供者元数据，不需要管理员权限。
fn installed_templates() -> Vec<Template> {
    let script = "(Get-WinEvent -ListProvider Microsoft-Windows-Kernel-Process).Events | \
                  Where-Object { $_.Id -in 1,2 } | \
                  ForEach-Object { \"=== $($_.Id) $($_.Version)\"; $_.Template }";
    let out = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .expect("powershell");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let mut events = Vec::new();
    for block in text.split("=== ").skip(1) {
        let (head, body) = block.split_once('\n').expect("header line");
        let mut parts = head.split_whitespace();
        let id = parts.next().and_then(|v| v.parse().ok()).expect("id");
        let version = parts.next().and_then(|v| v.parse().ok()).expect("version");
        let fields = body
            .split("<data ")
            .skip(1)
            .map(|d| {
                let attr = |name: &str| {
                    d.split_once(&format!("{name}=\""))
                        .and_then(|(_, rest)| rest.split_once('"'))
                        .map(|(v, _)| v.to_owned())
                        .expect("attribute")
                };
                (attr("name"), attr("inType"))
            })
            .collect();
        events.push((id, version, fields));
    }
    events
}

#[test]
fn layout_matches_the_installed_manifest() {
    let events = installed_templates();
    assert!(
        events.iter().any(|(id, _, _)| *id == EVENT_START)
            && events.iter().any(|(id, _, _)| *id == EVENT_STOP),
        "manifest lists both events: {events:?}"
    );
    for (id, version, fields) in events {
        // 从模板算出各字段的偏移，直到第一个变长字段
        let mut offsets = std::collections::HashMap::new();
        let mut at = 0;
        for (name, in_type) in &fields {
            let Some(size) = fixed_size(in_type) else {
                break;
            };
            offsets.insert(name.as_str(), (at, size));
            at += size;
        }
        let l = layout(id, version).expect("known event");
        let end = |(o, s): (usize, usize)| o + s;
        assert_eq!(offsets.get("ProcessID"), Some(&(0, 4)), "{id} v{version}");
        assert_eq!(
            offsets.get("CreateTime"),
            Some(&(l.create_time, 8)),
            "{id} v{version}"
        );
        let mut last = end((l.create_time, 8));
        if id == EVENT_START {
            let parent = l.parent_pid.expect("parent offset");
            let session = l.session_id.expect("session offset");
            assert_eq!(
                offsets.get("ParentProcessID"),
                Some(&(parent, 4)),
                "{id} v{version}"
            );
            assert_eq!(
                offsets.get("SessionID"),
                Some(&(session, 4)),
                "{id} v{version}"
            );
            last = last.max(end((parent, 4))).max(end((session, 4)));
        }
        assert_eq!(l.min_len, last, "{id} v{version}");
    }
}

#[test]
fn provider_guid_matches_the_manifest() {
    let g = GUID::from_u128(0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e716);
    assert!(is_provider(&g));
    assert!(!is_provider(&GUID::from_u128(
        0x22fb2cd6_0e7b_422b_a0c7_2fad1fd0e717
    )));
}

#[test]
fn session_names_are_checked() {
    assert_eq!(
        ProcessEventTrace::start("", |_| {})
            .expect_err("empty")
            .kind(),
        io::ErrorKind::InvalidInput
    );
    let long = "x".repeat(MAX_NAME + 1);
    assert_eq!(
        ProcessEventTrace::start(&long, |_| {})
            .expect_err("too long")
            .kind(),
        io::ErrorKind::InvalidInput
    );
}
