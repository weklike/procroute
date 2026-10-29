// SPDX-License-Identifier: GPL-3.0-or-later
//! 连接事件：判定归属、快照差异，以及对着假控制 API 的轮询。

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Mutex;

use procroute_proto::event::Network;
use procroute_proto::profile::{
    DnsSettings, FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION, UdpSettings,
};
use procroute_proto::session::SessionStatus;

use super::*;
use crate::events::StreamEvent;

fn rule(kind: MatchType, value: &str) -> MatchRule {
    MatchRule {
        kind,
        value: value.into(),
        recursive: false,
    }
}

fn profile() -> Profile {
    Profile {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: "p1".into(),
        name: "x".into(),
        mode: Mode::Tun,
        fail_policy: FailPolicy::Allow,
        dns: DnsSettings::default(),
        udp: UdpSettings::default(),
        groups: vec![
            Group {
                tag: "game".into(),
                outbound: "n1".into(),
                include_children: true,
                matchers: vec![rule(MatchType::Name, "launcher.exe")],
            },
            Group {
                tag: "browser".into(),
                outbound: "hk-auto".into(),
                include_children: false,
                matchers: vec![rule(MatchType::Name, "firefox.exe")],
            },
        ],
        exclude: vec![rule(MatchType::Name, "updater.exe")],
    }
}

fn classifier() -> Classifier {
    let names = HashMap::from([
        ("n1".to_owned(), "香港 01".to_owned()),
        ("n2".to_owned(), "日本 02".to_owned()),
    ]);
    Classifier::new(&profile(), names).expect("compile")
}

fn conn(id: &str, process: &str, chains: &[&str], up: u64, down: u64) -> KernelConnection {
    KernelConnection {
        id: id.into(),
        network: Network::Tcp,
        host: String::new(),
        destination_ip: "203.0.113.24".into(),
        destination_port: 443,
        process_path: process.into(),
        chains: chains.iter().map(|s| (*s).to_owned()).collect(),
        upload: up,
        download: down,
        started_at_ms: Some(1_000),
    }
}

#[test]
fn attribution_follows_the_rules_and_names_nodes() {
    let c = classifier();
    let game = conn("a", r"D:\Games\Launcher.exe", &["n1"], 0, 0);
    assert_eq!(
        c.classify(&game),
        Some(Attribution {
            group: "game".into(),
            outbound: "香港 01".into(),
        })
    );
    // 内核没查到进程：按规则选中的出站反查进程组；显示实际使用的节点
    let unknown = conn("b", "", &["n2", "hk-auto"], 0, 0);
    assert_eq!(
        c.classify(&unknown),
        Some(Attribution {
            group: "browser".into(),
            outbound: "日本 02".into(),
        })
    );
    // 直连（非目标进程）不算
    assert_eq!(
        c.classify(&conn("c", r"C:\x\other.exe", &["direct"], 0, 0)),
        None
    );
    assert_eq!(c.classify(&conn("d", "", &[], 0, 0)), None);
}

#[test]
fn snapshots_become_opened_updated_and_closed_events() {
    let c = classifier();
    let mut t = ConnTracker::default();
    let classify = |k: &KernelConnection| c.classify(k);

    let first = t.update(
        &[
            conn("a", r"D:\Games\launcher.exe", &["n1"], 10, 20),
            conn("x", r"C:\Windows\explorer.exe", &["direct"], 1, 1),
        ],
        5_000,
        classify,
    );
    assert_eq!(first.len(), 1, "direct connections are not reported");
    assert_eq!(first[0].phase, ConnPhase::Opened);
    assert_eq!(first[0].process, "launcher.exe");
    assert_eq!(first[0].target, "203.0.113.24:443");
    assert_eq!(first[0].group, "game");
    assert_eq!(first[0].started_at_ms, 1_000);
    let id = first[0].conn_id;

    // 字节数没变：没有事件
    let same = t.update(
        &[conn("a", r"D:\Games\launcher.exe", &["n1"], 10, 20)],
        6_000,
        classify,
    );
    assert!(same.is_empty());

    let grown = t.update(
        &[conn("a", r"D:\Games\launcher.exe", &["n1"], 15, 90)],
        7_000,
        classify,
    );
    assert_eq!(grown.len(), 1);
    assert_eq!(grown[0].phase, ConnPhase::Updated);
    assert_eq!(grown[0].conn_id, id);
    assert_eq!((grown[0].upload_bytes, grown[0].download_bytes), (15, 90));

    let closed = t.update(&[], 8_000, classify);
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].phase, ConnPhase::Closed);
    assert_eq!(closed[0].conn_id, id);
    assert!(t.update(&[], 9_000, classify).is_empty());
}

#[test]
fn hosts_ipv6_and_missing_start_times_are_formatted() {
    let c = classifier();
    let mut t = ConnTracker::default();
    let mut with_host = conn("h", r"D:\Games\launcher.exe", &["n1"], 0, 0);
    with_host.host = "game.example.com".into();
    let mut v6 = conn("v6", r"D:\Games\launcher.exe", &["n1"], 0, 0);
    v6.destination_ip = "2001:db8::1".into();
    v6.started_at_ms = None;
    let events = t.update(&[with_host, v6], 42, |k| c.classify(k));
    let target = |id: &str| {
        events
            .iter()
            .find(|e| e.target.starts_with(id))
            .map(|e| (e.target.clone(), e.started_at_ms))
    };
    assert_eq!(
        target("game"),
        Some(("game.example.com:443".to_owned(), 1_000))
    );
    assert_eq!(target("[2001"), Some(("[2001:db8::1]:443".to_owned(), 42)));
}

#[test]
fn close_all_reports_every_tracked_connection() {
    let c = classifier();
    let mut t = ConnTracker::default();
    t.update(
        &[
            conn("a", r"D:\Games\launcher.exe", &["n1"], 0, 0),
            conn("b", "", &["hk-auto"], 0, 0),
        ],
        1,
        |k| c.classify(k),
    );
    let closed = t.close_all();
    assert_eq!(closed.len(), 2);
    assert!(closed.iter().all(|e| e.phase == ConnPhase::Closed));
    assert!(t.close_all().is_empty());
}

/// 依次回答若干个连接列表的假控制 API；用完后一直回答空列表。
fn fake_api(bodies: Vec<&'static str>) -> SocketAddr {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let addr = listener.local_addr().expect("addr");
    let bodies = Mutex::new(bodies.into_iter());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let mut buf = [0u8; 4096];
            let mut req = Vec::new();
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let body = bodies
                .lock()
                .expect("bodies")
                .next()
                .unwrap_or(r#"{"connections":null}"#);
            let _ = write!(s, "HTTP/1.1 200 OK\r\n\r\n{body}");
        }
    });
    addr
}

const ONE_CONNECTION: &str = r#"{"connections":[{
  "id":"k1","metadata":{"network":"tcp","destinationIP":"203.0.113.24","destinationPort":"443",
  "host":"","processPath":"D:\\Games\\launcher.exe"},
  "upload":1,"download":2,"start":"2026-10-29T00:00:00Z","chains":["n1"]}]}"#;

async fn next_conn(rx: &mut tokio::sync::broadcast::Receiver<StreamEvent>) -> ConnEvent {
    match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        Ok(Ok(StreamEvent::Conn(e))) => e,
        other => panic!("expected a connection event, got {other:?}"),
    }
}

#[tokio::test]
async fn polling_publishes_events_and_closes_on_stop() {
    let hub = Arc::new(EventHub::new(SessionStatus::default()));
    let mut events = hub.subscribe().stream;
    let api = fake_api(vec![ONE_CONNECTION, ONE_CONNECTION]);
    let watch = ConnWatch::spawn(
        hub.clone(),
        api,
        Secret::new("0123456789abcdefABCDEF0123456789".into()),
        classifier(),
        Duration::from_millis(20),
    );
    let opened = next_conn(&mut events).await;
    assert_eq!(opened.phase, ConnPhase::Opened);
    assert_eq!(opened.outbound, "香港 01");
    // 列表里不再有它：关闭
    let closed = next_conn(&mut events).await;
    assert_eq!(
        (closed.phase, closed.conn_id),
        (ConnPhase::Closed, opened.conn_id)
    );
    watch.stop().await;
}

#[tokio::test]
async fn stopping_closes_connections_still_open() {
    let hub = Arc::new(EventHub::new(SessionStatus::default()));
    let mut events = hub.subscribe().stream;
    // 一直有这条连接
    let api = fake_api(vec![ONE_CONNECTION; 1000]);
    let watch = ConnWatch::spawn(
        hub.clone(),
        api,
        Secret::new("0123456789abcdefABCDEF0123456789".into()),
        classifier(),
        Duration::from_millis(20),
    );
    let opened = next_conn(&mut events).await;
    watch.stop().await;
    let mut closed = None;
    while let Ok(StreamEvent::Conn(e)) = events.try_recv() {
        if e.phase == ConnPhase::Closed {
            closed = Some(e);
        }
    }
    assert_eq!(closed.map(|e| e.conn_id), Some(opened.conn_id));
}
