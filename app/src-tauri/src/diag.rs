// SPDX-License-Identifier: GPL-3.0-or-later
//! 诊断包导出（T-112）：向服务要 `diag.export`，连同界面版本写成「下载」文件夹里的 JSON 文件。
//!
//! 报告不经过 WebView：前端只触发命令、拿回保存路径，WebView 因此拿不到「往磁盘写任意内容」的能力。
//! 文件名由这里决定（`procroute-diag-<UTC 时间>.json`），只新建、不覆盖已有文件。报告在服务端已经
//! 脱敏（C-SEC-04），这里原样保存。

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Serialize;
use serde_json::{Value, json};
use tauri::{AppHandle, Manager, State};

use crate::ipc::{CallError, Client};

const FILE_PREFIX: &str = "procroute-diag";
/// 同一秒内多次导出时，文件名序号最多试到这里。
const MAX_NAME_ATTEMPTS: u32 = 100;

/// 导出失败。前端据 `kind` 区分「服务没给出报告」与「报告存不下来」，后者不能显示成连不上服务。
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiagExportError {
    /// 服务没能生成报告，或者连不上服务。
    Service { error: CallError },
    /// 报告已生成，但没能写进「下载」文件夹。
    Save { message: String },
}

impl DiagExportError {
    fn save(what: &str, e: impl std::fmt::Display) -> Self {
        Self::Save {
            message: format!("{what}: {e}"),
        }
    }
}

/// 生成诊断包并保存，返回文件的完整路径。
#[tauri::command]
pub async fn diag_export(
    app: AppHandle,
    client: State<'_, Arc<Client>>,
) -> Result<String, DiagExportError> {
    let report = client
        .call("diag.export", json!({}))
        .await
        .map_err(|error| DiagExportError::Service { error })?;
    let dir = app
        .path()
        .download_dir()
        .map_err(|e| DiagExportError::save("cannot locate the Downloads folder", e))?;
    let generated_ms = report["generated_at_ms"].as_u64().unwrap_or(0);
    let text =
        document(report).map_err(|e| DiagExportError::save("cannot encode the report", e))?;
    // 文件写入是阻塞 IO，不放在异步任务里（C-CODE-05）
    let saved = tauri::async_runtime::spawn_blocking(move || save(&dir, generated_ms, &text))
        .await
        .map_err(|e| DiagExportError::save("the save task failed", e))?
        .map_err(|e| DiagExportError::save("cannot save the report", e))?;
    Ok(saved.to_string_lossy().into_owned())
}

/// 文件内容：界面版本 + 服务的报告（两端可能来自不同的安装）。
fn document(report: Value) -> serde_json::Result<String> {
    let doc = json!({ "ui_version": env!("CARGO_PKG_VERSION"), "report": report });
    serde_json::to_string_pretty(&doc)
}

/// 在 `dir` 里新建文件写入 `text`；同名文件已存在时加序号，绝不覆盖。
fn save(dir: &Path, generated_ms: u64, text: &str) -> io::Result<PathBuf> {
    for attempt in 0..MAX_NAME_ATTEMPTS {
        let path = dir.join(file_name(generated_ms, attempt));
        let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        };
        let written = file.write_all(text.as_bytes()).and_then(|()| file.flush());
        drop(file);
        if let Err(e) = written {
            // 不留下半个文件
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
        return Ok(path);
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "too many reports with the same name",
    ))
}

/// `procroute-diag-20231114-221320.json`，第二个起加 `-1`、`-2`……（UTC 时间）。
fn file_name(generated_ms: u64, attempt: u32) -> String {
    let secs = generated_ms / 1000;
    let (y, m, d) = civil_from_days(secs / 86_400);
    let t = secs % 86_400;
    let (hh, mm, ss) = (t / 3600, t % 3600 / 60, t % 60);
    let suffix = if attempt == 0 {
        String::new()
    } else {
        format!("-{attempt}")
    };
    format!("{FILE_PREFIX}-{y:04}{m:02}{d:02}-{hh:02}{mm:02}{ss:02}{suffix}.json")
}

/// 1970-01-01 起的天数 → 公历年月日（Howard Hinnant 的 `civil_from_days`，只处理非负天数）。
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_carry_the_utc_time() {
        assert_eq!(file_name(0, 0), "procroute-diag-19700101-000000.json");
        // 2023-11-14T22:13:20Z
        assert_eq!(
            file_name(1_700_000_000_999, 0),
            "procroute-diag-20231114-221320.json"
        );
        // 闰日与年末
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(20_088), (2024, 12, 31));
        assert_eq!(file_name(0, 2), "procroute-diag-19700101-000000-2.json");
    }

    #[test]
    fn saving_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("procroute-ui-diag-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("dir");
        let first = save(&dir, 0, "a").expect("first");
        let second = save(&dir, 0, "b").expect("second");
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first).expect("read"), "a");
        assert_eq!(std::fs::read_to_string(&second).expect("read"), "b");
        assert!(second.ends_with("procroute-diag-19700101-000000-1.json"));
        assert!(save(&dir.join("missing"), 0, "c").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn errors_are_tagged_by_stage() {
        let save =
            serde_json::to_value(DiagExportError::save("cannot save", "disk full")).expect("json");
        assert_eq!(
            save,
            json!({ "kind": "save", "message": "cannot save: disk full" })
        );
        let service = serde_json::to_value(DiagExportError::Service {
            error: CallError::Transport("pipe closed".into()),
        })
        .expect("json");
        assert_eq!(
            service,
            json!({ "kind": "service", "error": "pipe closed" })
        );
    }

    #[test]
    fn documents_wrap_the_report_with_the_ui_version() {
        let text = document(json!({ "generated_at_ms": 1 })).expect("doc");
        let v: Value = serde_json::from_str(&text).expect("json");
        assert_eq!(v["ui_version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["report"]["generated_at_ms"], 1);
    }
}
