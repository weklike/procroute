// SPDX-License-Identifier: GPL-3.0-or-later
//! `diag.export`：生成脱敏后的诊断包（T-112，C-SEC-04）。收集与脱敏见 [`crate::diag`]。

use procroute_proto::Empty;
use procroute_proto::error::IpcError;
use serde_json::Value;

use super::{Services, blocking, node, to_json};
use crate::diag;
use crate::ipc_server::{Caller, parse_params};

pub(super) async fn export(
    svc: &Services,
    params: Value,
    caller: &Caller,
) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    let session = svc.session_snapshot();
    let profiles = svc.profiles.clone();
    let nodes = svc.nodes.clone();
    let sources = svc.diag.clone();
    let report = blocking(move || {
        Ok(diag::collect(
            &profiles,
            &nodes,
            &sources,
            session,
            node::now_ms(),
        ))
    })
    .await?;
    tracing::info!(
        pid = caller.pid,
        log_lines = report.log.lines.len(),
        problems = report.problems.len(),
        "diagnostic report exported"
    );
    to_json(report)
}
