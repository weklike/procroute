// SPDX-License-Identifier: GPL-3.0-or-later
//! ProcRoute IPC 协议类型。
//!
//! 本 crate 是 UI 与服务之间契约的唯一事实来源（CONSTRAINTS C-ARCH-04）：
//! 前端的 TypeScript 类型只能由 `cargo xtask gen-types` 从这里生成。
//! 本 crate 不依赖任何平台 crate，也不做文件或网络 IO（C-ARCH-02）。
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub mod node;
pub mod profile;
pub mod session;

/// IPC 协议版本。破坏性变更必须加一（C-ARCH-07）。
pub const IPC_PROTOCOL_VERSION: u32 = 1;

/// 没有参数或没有返回值的方法使用的空对象，序列化为 `{}`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct Empty {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_an_empty_object() {
        assert_eq!(serde_json::to_string(&Empty {}).unwrap(), "{}");
        assert_eq!(serde_json::from_str::<Empty>("{}").unwrap(), Empty {});
        assert!(serde_json::from_str::<Empty>(r#"{"x":1}"#).is_err());
    }
}
