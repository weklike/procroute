// SPDX-License-Identifier: GPL-3.0-or-later
//! `node.*` 的测试：分享链接导入、订阅拉取与刷新（订阅服务器只在回环上监听）。

use super::*;

/// 依次回答的订阅服务器（只在回环上监听，不访问外网）。返回带令牌的订阅地址。
fn subscription_server(responses: Vec<(&'static str, String)>) -> String {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind");
    let port = listener.local_addr().expect("addr").port();
    std::thread::spawn(move || {
        for (status, body) in responses {
            let Ok((mut s, _)) = listener.accept() else {
                return;
            };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => req.extend_from_slice(&buf[..n]),
                }
            }
            let head = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(body.as_bytes());
        }
    });
    format!("http://127.0.0.1:{port}/api/sub?token=hunter2-sub-token")
}

fn subscribe_params(name: &str, url: &str) -> Value {
    json!({ "kind": "subscription", "name": name, "url": url })
}

#[tokio::test]
async fn subscriptions_are_fetched_listed_and_refreshed() {
    let f = fixture("subscriptions");
    let v6 = "hy2://pw@[2001:db8::1]:443#v6";
    let url = subscription_server(vec![
        ("200 OK", format!("{TROJAN}\n{v6}\nssr://abc")),
        ("200 OK", TROJAN.to_owned()),
    ]);
    let r = f
        .call("node.import", subscribe_params("机场", &url))
        .await
        .expect("import");
    assert_eq!(r["added"], 2);
    assert_eq!(r["skipped"], 1);
    assert_eq!(r["issues"][0]["reason"], "unsupported_protocol");

    let list = f.call("node.list", json!({})).await.expect("list");
    let sub = &list["subscriptions"][0];
    assert_eq!(sub["name"], "机场");
    assert_eq!(sub["node_count"], 2);
    assert!(sub["updated_at_ms"].as_u64().is_some());
    let port = url
        .split(':')
        .nth(2)
        .and_then(|p| p.split('/').next())
        .expect("port");
    assert_eq!(sub["url_display"], format!("http://127.0.0.1:{port}"));
    assert!(
        !list.to_string().contains("hunter2"),
        "no token or credential: {list}"
    );
    let sub_id = sub["id"].as_str().expect("id").to_owned();
    let trojan_id = list["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|n| n["protocol"] == "trojan")
        .and_then(|n| n["id"].as_str())
        .expect("trojan node")
        .to_owned();
    assert!(
        list["nodes"]
            .as_array()
            .expect("nodes")
            .iter()
            .all(|n| n["subscription_id"] == sub_id.as_str())
    );

    // 再次导入同一地址：刷新。没变的节点保留 id，消失的删除
    let r = f
        .call("node.import", subscribe_params("新名字", &url))
        .await
        .expect("refresh");
    assert_eq!(r["added"], 0);
    let list = f.call("node.list", json!({})).await.expect("list");
    assert_eq!(list["subscriptions"].as_array().expect("subs").len(), 1);
    assert_eq!(list["subscriptions"][0]["name"], "新名字");
    assert_eq!(list["subscriptions"][0]["id"], sub_id.as_str());
    assert_eq!(list["subscriptions"][0]["node_count"], 1);
    assert_eq!(list["nodes"].as_array().expect("nodes").len(), 1);
    assert_eq!(list["nodes"][0]["id"], trojan_id.as_str());

    // 地址加密落盘
    let on_disk =
        std::fs::read_to_string(f.dir.join("node-store").join("nodes.json")).expect("read");
    assert!(!on_disk.contains("hunter2"), "{on_disk}");
}

#[tokio::test]
async fn subscription_failures_are_reported_without_the_url() {
    let f = fixture("subscription-errors");
    let url = subscription_server(vec![("404 Not Found", "nope".into())]);
    let err = f
        .call("node.import", subscribe_params("坏订阅", &url))
        .await
        .expect_err("404");
    assert_eq!(err.code, ErrorCode::NodeImportFailed);
    assert!(err.message.contains("404"), "{}", err.message);
    assert!(!err.message.contains("hunter2"), "{}", err.message);

    for (name, bad) in [
        ("x", "ftp://sub.example.com/s"),
        ("x", "https://sub.example.com/a b"),
        ("", "https://sub.example.com/s"),
    ] {
        assert_eq!(
            code(f.call("node.import", subscribe_params(name, bad)).await),
            ErrorCode::IpcInvalidParams,
            "{name:?} {bad}"
        );
    }
    let list = f.call("node.list", json!({})).await.expect("list");
    assert_eq!(list["subscriptions"], json!([]), "nothing was stored");
}

#[tokio::test]
async fn node_import_and_list_round_trip() {
    let f = fixture("nodes");
    let text = format!("{TROJAN}\nssr://abc\n\nhy2://pw@[2001:db8::1]:443#v6");
    let r = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": text }),
        )
        .await
        .expect("import");
    assert_eq!(
        r,
        json!({ "added": 2, "skipped": 1, "issues": [ { "line": 2, "reason": "unsupported_protocol" } ] })
    );

    let list = f.call("node.list", json!({})).await.expect("list");
    let nodes = list["nodes"].as_array().expect("nodes");
    assert_eq!(nodes.len(), 2);
    assert_eq!(nodes[0]["name"], "香港 01");
    assert_eq!(nodes[0]["protocol"], "trojan");
    assert_eq!(nodes[0]["server"], "tj.example.com:443");
    assert_eq!(nodes[0]["credential"], "set");
    assert_eq!(nodes[1]["protocol"], "hysteria2");
    assert_eq!(nodes[1]["server"], "[2001:db8::1]:443");
    let outbounds = list["outbounds"].as_array().expect("outbounds");
    assert_eq!(outbounds[0]["tag"], nodes[0]["id"]);
    assert_eq!(outbounds[0]["kind"], "single");
    assert_eq!(outbounds[0]["members"], json!([nodes[0]["id"]]));
    assert_eq!(list["subscriptions"], json!([]));
    // C-SEC-04：凭据既不在响应里，也不以明文落盘
    assert!(!list.to_string().contains("hunter2"), "{list}");
    let on_disk =
        std::fs::read_to_string(f.dir.join("node-store").join("nodes.json")).expect("read");
    assert!(!on_disk.contains("hunter2"));
    assert!(on_disk.contains("tj.example.com"));

    // 再次导入同一条链接：按重复跳过，不产生新节点
    let again = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": TROJAN }),
        )
        .await
        .expect("import");
    assert_eq!(
        again,
        json!({ "added": 0, "skipped": 1, "issues": [ { "line": 1, "reason": "duplicate" } ] })
    );
    let list = f.call("node.list", json!({})).await.expect("list");
    assert_eq!(list["nodes"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn node_import_reports_whole_input_problems() {
    let f = fixture("nodes-bad");
    let r = f
        .call(
            "node.import",
            json!({ "kind": "share_links", "text": "proxies:\n  - name: a" }),
        )
        .await
        .expect("import");
    assert_eq!(
        r,
        json!({ "added": 0, "skipped": 0, "issues": [ { "line": 0, "reason": "clash_yaml_unsupported" } ] })
    );
    assert_eq!(
        code(
            f.call("node.import", json!({ "kind": "share_links" }))
                .await
        ),
        ErrorCode::IpcInvalidParams
    );
}
