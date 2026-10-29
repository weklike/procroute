// SPDX-License-Identifier: GPL-3.0-or-later
//! IPC 错误码。格式为 `<领域>.<原因>`（AGENTS 5.3）。
//!
//! 错误的 `message` 只给开发者看，界面按 `code` 从 i18n 资源取文案；
//! `message` 里不得包含凭据或完整订阅地址（C-SEC-04）。

use std::fmt;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// 全部错误码。新增时在 [`ErrorCode::ALL`] 里同步登记，测试会检查。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
pub enum ErrorCode {
    #[serde(rename = "ipc.version_mismatch")]
    IpcVersionMismatch,
    #[serde(rename = "ipc.invalid_request")]
    IpcInvalidRequest,
    #[serde(rename = "ipc.payload_too_large")]
    IpcPayloadTooLarge,
    #[serde(rename = "ipc.unauthorized")]
    IpcUnauthorized,
    #[serde(rename = "ipc.unknown_method")]
    IpcUnknownMethod,
    #[serde(rename = "ipc.invalid_params")]
    IpcInvalidParams,
    #[serde(rename = "session.already_running")]
    SessionAlreadyRunning,
    #[serde(rename = "session.not_running")]
    SessionNotRunning,
    /// 当前模式无法保证 `fail_policy = block`：例如 TUN 模式下 sing-box 一退出，TUN 与路由随之撤销，
    /// 目标进程会回落直连（C-NET-03）。用户可以改用 `allow` 或精确进程模式。
    #[serde(rename = "session.fail_closed_unsupported")]
    SessionFailClosedUnsupported,
    #[serde(rename = "profile.not_found")]
    ProfileNotFound,
    #[serde(rename = "profile.invalid_schema")]
    ProfileInvalidSchema,
    #[serde(rename = "profile.in_use")]
    ProfileInUse,
    #[serde(rename = "node.not_found")]
    NodeNotFound,
    #[serde(rename = "node.import_failed")]
    NodeImportFailed,
    #[serde(rename = "driver.not_loaded")]
    DriverNotLoaded,
    #[serde(rename = "driver.load_failed")]
    DriverLoadFailed,
    #[serde(rename = "driver.busy")]
    DriverBusy,
    #[serde(rename = "kernel.unavailable")]
    KernelUnavailable,
    #[serde(rename = "internal.error")]
    Internal,
}

impl ErrorCode {
    /// 所有错误码，供测试与文档生成使用。
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::IpcVersionMismatch,
        ErrorCode::IpcInvalidRequest,
        ErrorCode::IpcPayloadTooLarge,
        ErrorCode::IpcUnauthorized,
        ErrorCode::IpcUnknownMethod,
        ErrorCode::IpcInvalidParams,
        ErrorCode::SessionAlreadyRunning,
        ErrorCode::SessionNotRunning,
        ErrorCode::SessionFailClosedUnsupported,
        ErrorCode::ProfileNotFound,
        ErrorCode::ProfileInvalidSchema,
        ErrorCode::ProfileInUse,
        ErrorCode::NodeNotFound,
        ErrorCode::NodeImportFailed,
        ErrorCode::DriverNotLoaded,
        ErrorCode::DriverLoadFailed,
        ErrorCode::DriverBusy,
        ErrorCode::KernelUnavailable,
        ErrorCode::Internal,
    ];

    /// 错误码字符串，例如 `profile.invalid_schema`。
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::IpcVersionMismatch => "ipc.version_mismatch",
            ErrorCode::IpcInvalidRequest => "ipc.invalid_request",
            ErrorCode::IpcPayloadTooLarge => "ipc.payload_too_large",
            ErrorCode::IpcUnauthorized => "ipc.unauthorized",
            ErrorCode::IpcUnknownMethod => "ipc.unknown_method",
            ErrorCode::IpcInvalidParams => "ipc.invalid_params",
            ErrorCode::SessionAlreadyRunning => "session.already_running",
            ErrorCode::SessionNotRunning => "session.not_running",
            ErrorCode::SessionFailClosedUnsupported => "session.fail_closed_unsupported",
            ErrorCode::ProfileNotFound => "profile.not_found",
            ErrorCode::ProfileInvalidSchema => "profile.invalid_schema",
            ErrorCode::ProfileInUse => "profile.in_use",
            ErrorCode::NodeNotFound => "node.not_found",
            ErrorCode::NodeImportFailed => "node.import_failed",
            ErrorCode::DriverNotLoaded => "driver.not_loaded",
            ErrorCode::DriverLoadFailed => "driver.load_failed",
            ErrorCode::DriverBusy => "driver.busy",
            ErrorCode::KernelUnavailable => "kernel.unavailable",
            ErrorCode::Internal => "internal.error",
        }
    }

    /// 对应的 JSON-RPC 2.0 错误号：协议层错误用规范保留号，业务错误统一 -32000。
    pub const fn rpc_code(self) -> i32 {
        match self {
            ErrorCode::IpcInvalidRequest | ErrorCode::IpcPayloadTooLarge => -32600,
            ErrorCode::IpcUnknownMethod => -32601,
            ErrorCode::IpcInvalidParams => -32602,
            ErrorCode::Internal => -32603,
            _ => -32000,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 字段校验问题的种类。界面按它从 i18n 资源取文案，并标到对应字段上。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
pub enum FieldIssueCode {
    SchemaVersion,
    Empty,
    TooLong,
    TooMany,
    InvalidId,
    InvalidTag,
    ControlChar,
    DuplicateTag,
    NoMatchers,
    /// 匹配规则无法编译（正则、通配符语法错误等）。
    InvalidRule,
    /// DNS 服务器地址格式不正确（`dns.remote_server`）。
    InvalidDnsServer,
}

/// 某个字段上的一个问题。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct FieldIssue {
    /// 出问题的字段，例如 `groups[1].match[0].value`。
    pub path: String,
    pub code: FieldIssueCode,
    /// 给开发者看的细节；界面文案按 `code` 取。
    pub message: String,
}

/// 返回给客户端的错误。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct IpcError {
    pub code: ErrorCode,
    pub message: String,
    /// 逐字段的校验问题（例如 `profile.invalid_schema`）；没有时省略。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub fields: Option<Vec<FieldIssue>>,
}

impl IpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            fields: None,
        }
    }

    /// 附上逐字段的校验问题。
    pub fn with_fields(mut self, fields: Vec<FieldIssue>) -> Self {
        self.fields = (!fields.is_empty()).then_some(fields);
        self
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for IpcError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_name_matches_as_str_for_every_code() {
        for code in ErrorCode::ALL {
            let json = serde_json::to_string(code).unwrap();
            assert_eq!(json, format!("\"{}\"", code.as_str()));
            assert_eq!(serde_json::from_str::<ErrorCode>(&json).unwrap(), *code);
        }
    }

    #[test]
    fn codes_follow_domain_dot_reason_format() {
        for code in ErrorCode::ALL {
            let s = code.as_str();
            let (domain, reason) = s.split_once('.').unwrap();
            assert!(!domain.is_empty() && !reason.is_empty(), "{s}");
            assert!(
                s.chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '_'),
                "{s}"
            );
        }
    }

    #[test]
    fn field_issues_are_omitted_when_empty_and_round_trip_otherwise() {
        let plain = IpcError::new(ErrorCode::ProfileNotFound, "x").with_fields(vec![]);
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("fields"), "{json}");
        assert_eq!(serde_json::from_str::<IpcError>(&json).unwrap(), plain);

        let e = IpcError::new(ErrorCode::ProfileInvalidSchema, "2 issues").with_fields(vec![
            FieldIssue {
                path: "groups[0].tag".into(),
                code: FieldIssueCode::DuplicateTag,
                message: "dup".into(),
            },
        ]);
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(v["fields"][0]["path"], "groups[0].tag");
        assert_eq!(v["fields"][0]["code"], "duplicate_tag");
        assert_eq!(serde_json::from_value::<IpcError>(v).unwrap(), e);
    }

    #[test]
    fn version_mismatch_code_is_stable() {
        assert_eq!(
            ErrorCode::IpcVersionMismatch.as_str(),
            "ipc.version_mismatch"
        );
    }
}
