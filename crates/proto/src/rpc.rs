// SPDX-License-Identifier: GPL-3.0-or-later
//! JSON-RPC 2.0 信封与握手。
//!
//! 服务端与 Tauri 后端共用：解析时强制单条消息不超过 [`MAX_MESSAGE_BYTES`]（C-SEC-03），
//! 握手时比对 [`crate::IPC_PROTOCOL_VERSION`]，不匹配返回 `ipc.version_mismatch`（C-ARCH-07）。

use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::IPC_PROTOCOL_VERSION;
use crate::error::{ErrorCode, IpcError};

/// 单条 IPC 消息的大小上限：1 MiB（C-SEC-03）。
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

const JSONRPC_VERSION: &str = "2.0";

/// 客户端请求。`params` 由具体方法再按 schema 反序列化。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub id: u64,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

impl RpcRequest {
    pub fn new(id: u64, method: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            method: method.into(),
            params,
        }
    }

    /// 从原始字节解析请求：先查大小，再查格式与版本号。
    pub fn parse(bytes: &[u8]) -> Result<Self, IpcError> {
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(IpcError::new(
                ErrorCode::IpcPayloadTooLarge,
                format!(
                    "message is {} bytes, limit is {MAX_MESSAGE_BYTES}",
                    bytes.len()
                ),
            ));
        }
        let req: RpcRequest = serde_json::from_slice(bytes)
            .map_err(|e| IpcError::new(ErrorCode::IpcInvalidRequest, e.to_string()))?;
        if req.jsonrpc != JSONRPC_VERSION {
            return Err(IpcError::new(
                ErrorCode::IpcInvalidRequest,
                "jsonrpc must be \"2.0\"",
            ));
        }
        Ok(req)
    }
}

/// JSON-RPC 错误对象：`data` 里带 ProcRoute 的错误码字符串。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcErrorObject {
    pub code: i32,
    pub message: String,
    pub data: IpcError,
}

impl From<IpcError> for RpcErrorObject {
    fn from(e: IpcError) -> Self {
        Self {
            code: e.code.rpc_code(),
            message: e.code.as_str().to_owned(),
            data: e,
        }
    }
}

/// 服务端响应：`result` 与 `error` 二选一。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
}

impl RpcResponse {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: u64, error: IpcError) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result: None,
            error: Some(error.into()),
        }
    }
}

/// 服务端主动推送的事件。`method` 为事件通道名，例如 `conn.subscribe`。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcNotification {
    pub jsonrpc: String,
    pub method: String,
    pub params: Value,
}

impl RpcNotification {
    pub fn new(channel: impl Into<String>, params: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            method: channel.into(),
            params,
        }
    }
}

/// `ipc.hello` 的参数：连接建立后的第一条请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct HelloParams {
    pub protocol_version: u32,
    pub client_version: String,
}

/// `ipc.hello` 的返回值。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
pub struct HelloResult {
    pub protocol_version: u32,
    pub service_version: String,
}

/// 服务端握手检查：协议版本必须完全一致。
pub fn check_hello(params: &HelloParams) -> Result<(), IpcError> {
    if params.protocol_version == IPC_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(IpcError::new(
            ErrorCode::IpcVersionMismatch,
            format!(
                "client speaks protocol {}, service speaks {IPC_PROTOCOL_VERSION}",
                params.protocol_version
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_valid_request() {
        let req =
            RpcRequest::parse(br#"{"jsonrpc":"2.0","id":1,"method":"session.status","params":{}}"#)
                .unwrap();
        assert_eq!(req.method, "session.status");
    }

    #[test]
    fn params_may_be_omitted() {
        let req =
            RpcRequest::parse(br#"{"jsonrpc":"2.0","id":2,"method":"profile.list"}"#).unwrap();
        assert_eq!(req.params, Value::Null);
    }

    #[test]
    fn rejects_oversized_messages() {
        let big = vec![b' '; MAX_MESSAGE_BYTES + 1];
        let err = RpcRequest::parse(&big).unwrap_err();
        assert_eq!(err.code, ErrorCode::IpcPayloadTooLarge);
    }

    #[test]
    fn rejects_wrong_jsonrpc_version_and_garbage() {
        let err =
            RpcRequest::parse(br#"{"jsonrpc":"1.0","id":1,"method":"x","params":{}}"#).unwrap_err();
        assert_eq!(err.code, ErrorCode::IpcInvalidRequest);
        let err = RpcRequest::parse(b"not json").unwrap_err();
        assert_eq!(err.code, ErrorCode::IpcInvalidRequest);
    }

    #[test]
    fn hello_rejects_other_protocol_versions() {
        let ok = HelloParams {
            protocol_version: IPC_PROTOCOL_VERSION,
            client_version: "0.1.0".into(),
        };
        assert!(check_hello(&ok).is_ok());
        let bad = HelloParams {
            protocol_version: IPC_PROTOCOL_VERSION + 1,
            client_version: "9.9.9".into(),
        };
        assert_eq!(
            check_hello(&bad).unwrap_err().code,
            ErrorCode::IpcVersionMismatch
        );
    }

    #[test]
    fn error_response_carries_code_string() {
        let resp = RpcResponse::err(3, IpcError::new(ErrorCode::ProfileNotFound, "no such id"));
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32000);
        assert_eq!(v["error"]["data"]["code"], "profile.not_found");
        assert!(v.get("result").is_none());
    }
}
