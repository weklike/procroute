// SPDX-License-Identifier: GPL-3.0-or-later
//! UTF-16 字符串转换（Win32 宽字符 API 用）。

/// 转成以 NUL 结尾的 UTF-16。
pub(crate) fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// 从 UTF-16 转回字符串；遇到 NUL 截断，非法代理对替换为 U+FFFD。
pub(crate) fn from_wide(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_stops_at_nul() {
        let w = to_wide(r"C:\游戏\x.exe");
        assert_eq!(w.last(), Some(&0));
        assert_eq!(from_wide(&w), r"C:\游戏\x.exe");
        assert_eq!(from_wide(&[0x41, 0, 0x42]), "A");
    }
}
