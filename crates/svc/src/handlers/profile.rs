// SPDX-License-Identifier: GPL-3.0-or-later
//! `profile.*`：方案的增删改查。保存前走 `procroute-config` 的迁移与校验（C-SEC-03、C-ARCH-06）。

use procroute_config::migrate::migrate_value;
use procroute_config::validate::{to_ipc_error, validate};
use procroute_proto::Empty;
use procroute_proto::error::{ErrorCode, IpcError};
use procroute_proto::profile::{
    Profile, ProfileIdParams, ProfileListResult, ProfileSaveResult, ProfileSummary,
};
use procroute_proto::session::SessionState;
use serde_json::Value;

use super::{Services, blocking, store_error, to_json};
use crate::ipc_server::parse_params;

pub(super) async fn list(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let Empty {} = parse_params(params)?;
    let store = svc.profiles.clone();
    let profiles = blocking(move || store.list().map_err(store_error)).await?;
    let active = active_profile_id(svc);
    let profiles = profiles
        .into_iter()
        .map(|p| ProfileSummary {
            active: active.as_deref() == Some(p.id.as_str()),
            group_count: u32::try_from(p.groups.len()).unwrap_or(u32::MAX),
            id: p.id,
            name: p.name,
            mode: p.mode,
        })
        .collect();
    to_json(ProfileListResult { profiles })
}

pub(super) async fn get(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let ProfileIdParams { id } = parse_params(params)?;
    let store = svc.profiles.clone();
    to_json(blocking(move || store.get(&id).map_err(store_error)).await?)
}

pub(super) async fn save(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let profile = parse_profile(params)?;
    let id = profile.id.clone();
    let store = svc.profiles.clone();
    blocking(move || store.save(&profile).map_err(store_error)).await?;
    tracing::info!(profile = %id, "profile saved");
    to_json(ProfileSaveResult { id })
}

pub(super) async fn delete(svc: &Services, params: Value) -> Result<Value, IpcError> {
    let ProfileIdParams { id } = parse_params(params)?;
    if active_profile_id(svc).as_deref() == Some(id.as_str()) {
        return Err(IpcError::new(
            ErrorCode::ProfileInUse,
            "the profile is used by the running session",
        ));
    }
    let store = svc.profiles.clone();
    blocking(move || store.delete(&id).map_err(store_error)).await?;
    to_json(Empty {})
}

/// 迁移旧版本、严格反序列化并校验。所有问题一次返回，界面据此标到字段上。
fn parse_profile(params: Value) -> Result<Profile, IpcError> {
    let value = migrate_value(params)
        .map_err(|e| IpcError::new(ErrorCode::ProfileInvalidSchema, e.to_string()))?;
    let profile: Profile = parse_params(value)
        .map_err(|e| IpcError::new(ErrorCode::ProfileInvalidSchema, e.message))?;
    validate(&profile).map_err(|issues| to_ipc_error(&issues))?;
    Ok(profile)
}

/// 正在运行（或启动、停止过程中）的会话所用的方案。
fn active_profile_id(svc: &Services) -> Option<String> {
    let s = svc.session_snapshot();
    (s.state != SessionState::Stopped)
        .then_some(s.profile_id)
        .flatten()
}
