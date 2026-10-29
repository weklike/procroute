// SPDX-License-Identifier: GPL-3.0-or-later
//! `node.test` 的测试：假内核在控制 API 地址上回答测速请求（只在回环上监听，不访问外网）。

use super::*;

const PROBE_URL: &str = "https://127.0.0.1:9/generate_204";

/// 假的 `GET /proxies/{tag}/delay`：标签以 `-0` 结尾的回 42 ms，`-1` 结尾的超时，其余失败。
pub(super) fn serve_delay_api(api: SocketAddr) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(api).expect("bind control API");
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut s) = stream else { return };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let req = String::from_utf8_lossy(&req);
            let tag = req
                .strip_prefix("GET /proxies/")
                .and_then(|r| r.split('/').next())
                .unwrap_or("");
            let reply: &[u8] = if tag.ends_with("-0") {
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{\"delay\":42}"
            } else if tag.ends_with("-1") {
                b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n{}"
            } else {
                b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{}"
            };
            let _ = s.write_all(reply);
        }
    });
}

fn delay_fixture(tag: &str) -> Fixture {
    fixture_with(
        tag,
        FakeLauncher {
            serve_delay: true,
            ..FakeLauncher::default()
        },
    )
}

/// 一次导入多个节点（id 的序号即行号减一），返回 id。
async fn import_nodes(f: &Fixture, count: u16) -> Vec<String> {
    let text: Vec<String> = (0..count)
        .map(|i| {
            format!(
                "trojan://hunter2-node-secret@tj.example.com:{}?sni=tj.example.com#n{i}",
                1000 + i
            )
        })
        .collect();
    let r = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": text.join("\n") }),
        )
        .await
        .expect("import");
    assert_eq!(r["added"], count);
    let list = f.call("node.list", json!({})).await.expect("list");
    list["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .map(|n| n["id"].as_str().expect("id").to_owned())
        .collect()
}

#[tokio::test]
async fn latency_test_runs_through_a_probe_kernel() {
    let f = delay_fixture("latency");
    let ids = import_nodes(&f, 3).await;
    let r = f
        .call(
            "node.test",
            json!({ "ids": [ids[2], ids[0], ids[1], ids[0]], "url": PROBE_URL }),
        )
        .await
        .expect("test");
    // 按请求的顺序返回，重复的 id 只测一次
    assert_eq!(
        r["results"],
        json!([
            { "id": ids[2], "latency_ms": null, "timed_out": false },
            { "id": ids[0], "latency_ms": 42, "timed_out": false },
            { "id": ids[1], "latency_ms": null, "timed_out": true },
        ])
    );
    assert!(!r.to_string().contains("hunter2"));

    // 测速内核只有出站：没有 TUN、没有代理端口；测完即停
    let launches = f.launcher.launches.lock().expect("launches").clone();
    assert_eq!(launches.len(), 1);
    let config: Value = serde_json::from_str(&launches[0].0).expect("config");
    assert!(config.get("inbounds").is_none());
    let tags: Vec<&str> = config["outbounds"]
        .as_array()
        .expect("outbounds")
        .iter()
        .filter_map(|o| o["tag"].as_str())
        .collect();
    assert_eq!(tags, ["direct", &ids[2], &ids[0], &ids[1]]);
    assert_eq!(f.launcher.stopped.load(Ordering::SeqCst), 1);
    assert_eq!(f.services.session_snapshot().state, SessionState::Stopped);

    // `ids` 为空：全部节点
    let all = f
        .call("node.test", json!({ "ids": [], "url": PROBE_URL }))
        .await
        .expect("test all");
    assert_eq!(all["results"].as_array().expect("results").len(), 3);
}

#[tokio::test]
async fn latency_test_needs_a_user_configured_url() {
    let f = delay_fixture("latency-url");
    import_nodes(&f, 1).await;
    for params in [
        json!({ "ids": [] }),
        json!({ "ids": [], "url": "ftp://x.example/" }),
        json!({ "ids": [], "url": "http://x.example/generate_204" }),
        json!({ "ids": [], "url": "" }),
    ] {
        assert_eq!(
            code(f.call("node.test", params.clone()).await),
            ErrorCode::IpcInvalidParams,
            "{params}"
        );
    }
    assert_eq!(f.launcher.launch_count(), 0, "nothing was launched");
}

#[tokio::test]
async fn latency_test_rejects_unknown_and_too_many_nodes() {
    let f = delay_fixture("latency-limits");
    let ids = import_nodes(&f, 65).await;
    assert_eq!(
        code(
            f.call(
                "node.test",
                json!({ "ids": [ids[0], "n0-0"], "url": PROBE_URL })
            )
            .await
        ),
        ErrorCode::NodeNotFound
    );
    assert_eq!(
        code(
            f.call("node.test", json!({ "ids": [], "url": PROBE_URL }))
                .await
        ),
        ErrorCode::IpcInvalidParams
    );
    assert_eq!(f.launcher.launch_count(), 0);
    let r = f
        .call("node.test", json!({ "ids": &ids[..64], "url": PROBE_URL }))
        .await
        .expect("64 nodes");
    assert_eq!(r["results"].as_array().expect("results").len(), 64);
}

#[tokio::test]
async fn latency_test_without_nodes_launches_nothing() {
    let f = delay_fixture("latency-empty");
    let r = f
        .call("node.test", json!({ "ids": [], "url": PROBE_URL }))
        .await
        .expect("test");
    assert_eq!(r["results"], json!([]));
    assert_eq!(f.launcher.launch_count(), 0);
}

#[tokio::test]
async fn latency_test_reports_a_kernel_that_does_not_start() {
    let f = fixture_with("latency-no-kernel", FakeLauncher::failing());
    import_nodes(&f, 1).await;
    assert_eq!(
        code(
            f.call("node.test", json!({ "ids": [], "url": PROBE_URL }))
                .await
        ),
        ErrorCode::KernelUnavailable
    );
}
