// SPDX-License-Identifier: GPL-3.0-or-later
//! schema 迁移（T-022，C-ARCH-06）。
//!
//! 结构变更时：
//! 1. 在 proto 里修改类型，并把 `PROFILE_SCHEMA_VERSION` 加一；
//! 2. 在 [`STEPS`] 末尾追加一个从旧版本升到新版本的函数；
//! 3. 把旧版本的样例放进 `tests/fixtures/config/v<旧版本>.json`（C-TEST-05）。
//!
//! 迁移只在 JSON 层面改写，然后再反序列化成当前版本的类型。

use procroute_proto::profile::{PROFILE_SCHEMA_VERSION, Profile};
use serde_json::Value;
use thiserror::Error;

use crate::validate::{ValidationIssue, validate};

/// 一步迁移：把版本 n 的 JSON 改写为版本 n+1。
type Step = fn(Value) -> Result<Value, String>;

/// `STEPS[i]` 把 v(i+1) 升到 v(i+2)。
const STEPS: &[Step] = &[v1_to_v2];

/// v2 新增 `dns.remote_server`：旧方案没有远程 DNS 服务器。
fn v1_to_v2(mut value: Value) -> Result<Value, String> {
    let obj = value.as_object_mut().ok_or("顶层必须是对象")?;
    match obj.get_mut("dns") {
        None => {}
        Some(Value::Object(dns)) => {
            dns.entry("remote_server").or_insert(Value::Null);
        }
        Some(_) => return Err("dns 必须是对象".into()),
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error("不是合法的 JSON：{0}")]
    Json(String),
    #[error("缺少 schema_version 或它不是正整数")]
    MissingVersion,
    #[error("schema_version {found} 比本版本支持的 {supported} 更新，请升级 ProcRoute")]
    TooNew { found: u32, supported: u32 },
    #[error("迁移到 v{to} 失败：{reason}")]
    Step { to: u32, reason: String },
    #[error("字段不符合方案格式：{0}")]
    Shape(String),
    #[error("方案校验失败（{} 处）", .0.len())]
    Invalid(Vec<ValidationIssue>),
}

/// 把任意受支持版本的方案 JSON 升级到当前版本。
pub fn migrate_value(mut value: Value) -> Result<Value, ConfigError> {
    let mut version = read_version(&value)?;
    if version > PROFILE_SCHEMA_VERSION {
        return Err(ConfigError::TooNew {
            found: version,
            supported: PROFILE_SCHEMA_VERSION,
        });
    }
    while version < PROFILE_SCHEMA_VERSION {
        let to = version + 1;
        let step = usize::try_from(version - 1)
            .ok()
            .and_then(|i| STEPS.get(i))
            .ok_or(ConfigError::Step {
                to,
                reason: "缺少迁移步骤".into(),
            })?;
        value = step(value).map_err(|reason| ConfigError::Step { to, reason })?;
        set_version(&mut value, to)?;
        version = to;
    }
    Ok(value)
}

/// 解析 → 迁移 → 反序列化 → 校验。服务读取磁盘上的方案或接收 `profile.save` 时都走这里。
pub fn load_profile(text: &str) -> Result<Profile, ConfigError> {
    let value: Value = serde_json::from_str(text).map_err(|e| ConfigError::Json(e.to_string()))?;
    let value = migrate_value(value)?;
    let profile: Profile =
        serde_json::from_value(value).map_err(|e| ConfigError::Shape(e.to_string()))?;
    validate(&profile).map_err(ConfigError::Invalid)?;
    Ok(profile)
}

fn read_version(value: &Value) -> Result<u32, ConfigError> {
    value
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or(ConfigError::MissingVersion)
}

fn set_version(value: &mut Value, version: u32) -> Result<(), ConfigError> {
    let obj = value
        .as_object_mut()
        .ok_or_else(|| ConfigError::Shape("顶层必须是对象".into()))?;
    obj.insert("schema_version".into(), Value::from(version));
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    fn fixtures_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/config")
    }

    #[test]
    fn one_step_per_version_bump() {
        assert_eq!(STEPS.len() as u32, PROFILE_SCHEMA_VERSION - 1);
    }

    #[test]
    fn every_historical_fixture_loads() {
        // C-TEST-05：每个历史版本都要有样例，并且能无损升级到当前版本
        let mut seen = Vec::new();
        for entry in fs::read_dir(fixtures_dir()).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "json") {
                let text = fs::read_to_string(&path).unwrap();
                let p = load_profile(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
                assert_eq!(p.schema_version, PROFILE_SCHEMA_VERSION);
                seen.push(path.file_stem().unwrap().to_string_lossy().into_owned());
            }
        }
        for v in 1..=PROFILE_SCHEMA_VERSION {
            assert!(seen.contains(&format!("v{v}")), "missing fixture v{v}.json");
        }
    }

    #[test]
    fn v1_fixture_keeps_its_content() {
        let text = fs::read_to_string(fixtures_dir().join("v1.json")).unwrap();
        let p = load_profile(&text).unwrap();
        assert_eq!(p.groups.len(), 2);
        assert_eq!(p.groups[0].tag, "game");
        assert!(!p.groups[1].include_children);
        assert_eq!(p.exclude[0].value, "updater.exe");
    }

    #[test]
    fn v1_profiles_gain_an_empty_remote_dns_server() {
        let text = fs::read_to_string(fixtures_dir().join("v1.json")).unwrap();
        let v1: Value = serde_json::from_str(&text).unwrap();
        let v2 = migrate_value(v1).unwrap();
        assert_eq!(v2["schema_version"], 2);
        assert_eq!(v2["dns"]["remote_server"], Value::Null);
        assert_eq!(v2["dns"]["strategy"], "sniff", "existing fields are kept");
        let p = load_profile(&text).unwrap();
        assert_eq!(p.dns.remote_server, None);
        // dns 缺失时用默认值；dns 不是对象时报错而不是丢弃
        let bare = migrate_value(serde_json::json!({ "schema_version": 1, "id": "a" })).unwrap();
        assert!(bare.get("dns").is_none());
        assert!(matches!(
            migrate_value(serde_json::json!({ "schema_version": 1, "dns": 5 })),
            Err(ConfigError::Step { to: 2, .. })
        ));
    }

    #[test]
    fn v2_fixture_keeps_its_remote_dns_server() {
        let text = fs::read_to_string(fixtures_dir().join("v2.json")).unwrap();
        let p = load_profile(&text).unwrap();
        assert_eq!(
            p.dns.remote_server.as_deref(),
            Some("tls://198.51.100.53:853")
        );
    }

    #[test]
    fn rejects_missing_or_future_versions() {
        assert_eq!(
            load_profile(r#"{"id":"a","name":"n"}"#).unwrap_err(),
            ConfigError::MissingVersion
        );
        assert_eq!(
            load_profile(r#"{"schema_version":0,"id":"a","name":"n"}"#).unwrap_err(),
            ConfigError::MissingVersion
        );
        assert_eq!(
            load_profile(r#"{"schema_version":999,"id":"a","name":"n"}"#).unwrap_err(),
            ConfigError::TooNew {
                found: 999,
                supported: PROFILE_SCHEMA_VERSION
            }
        );
    }

    #[test]
    fn invalid_profiles_are_rejected_after_migration() {
        let text = r#"{"schema_version":1,"id":"a","name":"n",
            "groups":[{"tag":"Game","outbound":"o","match":[]}]}"#;
        match load_profile(text).unwrap_err() {
            ConfigError::Invalid(issues) => assert_eq!(issues.len(), 2),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_non_json_and_wrong_shapes() {
        assert!(matches!(load_profile("nope"), Err(ConfigError::Json(_))));
        assert!(matches!(
            load_profile(r#"{"schema_version":1,"id":"a","name":"n","mode":"warp"}"#),
            Err(ConfigError::Shape(_))
        ));
    }
}
