// SPDX-License-Identifier: GPL-3.0-or-later
//! 凭据包装 `Secret<T>`（T-051，C-SEC-04）。
//!
//! - `Debug` / `Display` 一律输出 `***`，凭据不会经由日志、错误信息或 `{:?}` 泄漏；
//! - 不实现 `Serialize` / `Deserialize`：凭据不能顺手被写进 IPC 响应或诊断包，
//!   需要落盘时必须显式 [`Secret::expose`] 后交给 DPAPI；
//! - 取明文只能调用名字醒目的 [`Secret::expose`]，便于审查时检索。

use std::fmt;

/// 掩码文本。
pub const MASK: &str = "***";

/// 持有凭据的包装类型。
#[derive(Clone, Default)]
pub struct Secret<T>(T);

impl<T> Secret<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// 取出明文引用。只在真正需要明文的地方调用（写入 SOCKS 认证、交给 DPAPI 等）。
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// 消耗包装，取出明文。
    pub fn into_exposed(self) -> T {
        self.0
    }
}

impl<T> From<T> for Secret<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({MASK})")
    }
}

impl<T> fmt::Display for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    #[allow(dead_code)] // 只用于检查 Debug 输出
    struct NodeCredential {
        server: String,
        password: Secret<String>,
    }

    #[test]
    fn debug_and_display_never_show_the_value() {
        let s = Secret::new("x");
        assert_eq!(format!("{s:?}"), "Secret(***)");
        assert_eq!(format!("{s}"), "***");
        assert!(!format!("{s:?}").contains('x'));
    }

    #[test]
    fn derived_debug_of_containing_types_is_masked() {
        let c = NodeCredential {
            server: "hk1.example.net:443".into(),
            password: Secret::new("hunter2-very-secret".into()),
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("hunter2"), "{dbg}");
        assert!(dbg.contains("hk1.example.net"), "{dbg}");
        let pretty = format!("{c:#?}");
        assert!(!pretty.contains("hunter2"), "{pretty}");
    }

    #[test]
    fn expose_returns_the_value() {
        let s: Secret<String> = "p@ss".to_owned().into();
        assert_eq!(s.expose(), "p@ss");
        assert_eq!(s.clone().into_exposed(), "p@ss");
    }
}
