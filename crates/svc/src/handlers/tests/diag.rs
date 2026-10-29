// SPDX-License-Identifier: GPL-3.0-or-later
//! `diag.export` 的测试：经处理函数分派，返回值符合协议类型且不含凭据。脱敏细节见 `crate::diag` 的测试。

use procroute_proto::diag::{DiagFileState, DiagReport};

use super::*;
use crate::diag::DiagSources;
use crate::node_store::tests::trojan;

#[tokio::test]
async fn diag_export_returns_a_redacted_report() {
    let f = fixture("diag");
    let log = f.dir.join("svc.log");
    std::fs::write(
        &log,
        "INFO dial tj.example.com:443 password=hunter2-diag-secret\n",
    )
    .expect("log");
    f.services
        .nodes
        .update(|n| n.push(trojan("n1", "hunter2-diag-secret")))
        .expect("node");
    let services = services(&f.dir).with_diagnostics(DiagSources {
        log_file: Some(log),
        kernel_exe: Some(f.dir.join("sing-box.exe")),
    });
    let value = services
        .handle(Call {
            method: methods::method("diag.export").expect("registered"),
            params: json!({}),
            caller: &f.caller,
        })
        .await
        .expect("export");
    let text = value.to_string();
    assert!(
        !text.contains("hunter2-diag-secret") && !text.contains("tj.example.com"),
        "{text}"
    );

    let report: DiagReport = serde_json::from_value(value).expect("protocol type");
    assert_eq!(report.log.lines, vec!["INFO dial <node>:443 password=***"]);
    assert_eq!(report.nodes.expect("nodes").total, 1);
    assert_eq!(report.environment.kernel_binary, DiagFileState::Missing);
    assert!(!methods::method("diag.export").expect("registered").mutating);
}

#[tokio::test]
async fn diag_export_takes_no_params() {
    let f = fixture("diag-params");
    assert_eq!(
        code(f.call("diag.export", json!({ "x": 1 })).await),
        ErrorCode::IpcInvalidParams
    );
}
