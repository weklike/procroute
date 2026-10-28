// SPDX-License-Identifier: GPL-3.0-or-later
//! 路径规范化（C-DRV-04 中与平台无关的部分）。
//!
//! 规范形式：
//! - 去掉 `\\?\` 与 `\??\` 前缀；
//! - `/` 统一为 `\`，连续分隔符合并为一个（UNC 开头的 `\\` 保留）；
//! - 去掉末尾分隔符（`c:\` 这样的盘符根目录除外）；
//! - 转小写（Windows 文件系统默认不区分大小写）。
//!
//! 规范化是幂等的：`normalize_path(normalize_path(p)) == normalize_path(p)`。

const SEP: char = '\\';

/// 把路径转成规范形式。
///
/// 单趟处理在边角输入上可能不稳定（例如去掉末尾分隔符后又露出空白），
/// 所以反复处理到不再变化为止，以此保证幂等。
pub fn normalize_path(raw: &str) -> String {
    let mut current = normalize_once(raw);
    // 每一趟只会删字符或转小写，几趟内必然收敛；上限只是防御。
    for _ in 0..8 {
        let next = normalize_once(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn normalize_once(raw: &str) -> String {
    let mut s = raw.trim();
    for prefix in [r"\\?\", r"\??\", "//?/"] {
        if let Some(rest) = s.strip_prefix(prefix) {
            s = rest;
            break;
        }
    }

    let unified: String = s.chars().map(|c| if c == '/' { SEP } else { c }).collect();
    let is_unc = unified.starts_with(r"\\");

    let mut out = String::with_capacity(unified.len());
    let mut prev_sep = false;
    for c in unified.chars() {
        if c == SEP {
            if prev_sep {
                continue;
            }
            prev_sep = true;
        } else {
            prev_sep = false;
        }
        out.push(c);
    }
    if is_unc {
        out.insert(0, SEP);
    }

    while out.ends_with(SEP) && !is_drive_root(&out) && out.len() > 1 && !is_unc_marker(&out) {
        out.pop();
    }

    out.to_lowercase()
}

/// 规范路径的最后一段（文件名）。
pub fn file_name(normalized: &str) -> &str {
    normalized.rsplit(SEP).next().unwrap_or(normalized)
}

/// 规范路径的父目录；没有父目录时返回空串。
pub fn parent_dir(normalized: &str) -> &str {
    match normalized.rfind(SEP) {
        // `c:\x.exe` 的父目录是 `c:\`
        Some(i) if i == 2 && is_drive_root(&normalized[..=i]) => &normalized[..=i],
        Some(i) => &normalized[..i],
        None => "",
    }
}

/// `dir` 是否是 `path` 的祖先目录（两者都必须是规范形式）。
pub fn is_within(path: &str, dir: &str) -> bool {
    if dir.is_empty() || path.len() <= dir.len() || !path.starts_with(dir) {
        return false;
    }
    dir.ends_with(SEP) || path[dir.len()..].starts_with(SEP)
}

fn is_drive_root(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == SEP as u8
}

fn is_unc_marker(s: &str) -> bool {
    s == r"\\"
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn normalizes_common_forms() {
        let cases = [
            (
                r"C:\Program Files\Mozilla Firefox\firefox.exe",
                r"c:\program files\mozilla firefox\firefox.exe",
            ),
            ("D:/Games//MyGame/", r"d:\games\mygame"),
            (r"\\?\C:\Games\x.exe", r"c:\games\x.exe"),
            (r"\??\C:\Games\x.exe", r"c:\games\x.exe"),
            (r"C:\", r"c:\"),
            ("C:/", r"c:\"),
            (r"\\server\share\\dir\", r"\\server\share\dir"),
            ("  launcher.exe  ", "launcher.exe"),
        ];
        for (raw, want) in cases {
            assert_eq!(normalize_path(raw), want, "input {raw:?}");
        }
    }

    #[test]
    fn file_name_and_parent() {
        let p = normalize_path(r"D:\Games\MyGame\MyGame.exe");
        assert_eq!(file_name(&p), "mygame.exe");
        assert_eq!(parent_dir(&p), r"d:\games\mygame");
        assert_eq!(parent_dir(r"c:\x.exe"), r"c:\");
        assert_eq!(parent_dir("x.exe"), "");
    }

    #[test]
    fn within_requires_a_separator_boundary() {
        assert!(is_within(r"d:\games\mygame\bin\a.exe", r"d:\games\mygame"));
        assert!(!is_within(r"d:\games\mygame2\a.exe", r"d:\games\mygame"));
        assert!(!is_within(r"d:\games\mygame", r"d:\games\mygame"));
        assert!(is_within(r"c:\a.exe", r"c:\"));
    }

    proptest! {
        #[test]
        fn normalization_is_idempotent(raw in r"[ A-Za-z0-9:\\/._?\-一-龥]{0,64}") {
            let once = normalize_path(&raw);
            prop_assert_eq!(normalize_path(&once), once);
        }

        #[test]
        fn normalized_paths_have_no_forward_slash_or_double_separator(raw in r"[A-Za-z0-9:\\/._]{0,64}") {
            let n = normalize_path(&raw);
            prop_assert!(!n.contains('/'));
            let body = n.strip_prefix(r"\\").unwrap_or(&n);
            prop_assert!(!body.contains(r"\\"));
        }
    }
}
