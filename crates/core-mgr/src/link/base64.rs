// SPDX-License-Identifier: GPL-3.0-or-later
//! 宽松的 Base64 解码：订阅与分享链接里标准字母表与 URL 安全字母表混用，填充可有可无，
//! 还常被折行。只用于解析外部输入，不用于编码。

/// 解码；忽略空白，接受 `+/` 与 `-_` 两种字母表，填充可省略。
pub(crate) fn decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut padding = 0usize;
    let mut count = 0usize;
    for c in input.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            padding += 1;
            continue;
        }
        if padding > 0 {
            // 填充之后不能再有数据
            return None;
        }
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        count += 1;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // 只剩 1 个字符的分组不完整；填充最多 2 个
    if count % 4 == 1 || padding > 2 {
        return None;
    }
    Some(out)
}

/// 解码成 UTF-8 文本。
pub(crate) fn decode_text(input: &str) -> Option<String> {
    String::from_utf8(decode(input)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(decode_text(encoded).as_deref(), Some(plain), "{encoded}");
            assert_eq!(
                decode_text(encoded.trim_end_matches('=')).as_deref(),
                Some(plain)
            );
        }
    }

    #[test]
    fn accepts_url_safe_alphabet_and_line_breaks() {
        assert_eq!(decode(" +/-_\r\n").map(|v| v.len()), Some(3));
        assert_eq!(decode("-_8"), decode("+/8"));
        assert_eq!(
            decode_text("YWVz\nLTI1\r\nNi1n Y20=").as_deref(),
            Some("aes-256-gcm")
        );
    }

    #[test]
    fn rejects_garbage() {
        for bad in ["a", "Zg===", "Zg=a", "Z!==", "中文"] {
            assert_eq!(decode(bad), None, "{bad}");
        }
        assert_eq!(decode_text("/w=="), None, "not UTF-8");
    }
}
