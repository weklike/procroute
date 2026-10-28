// SPDX-License-Identifier: GPL-3.0-or-later
//! 把方案里的进程匹配规则翻译成 sing-box 的 `process_path_regex`（Go RE2 语法）。
//!
//! sing-box 1.14 的 `process_name` / `process_path` 是区分大小写的精确比较
//! （`route/rule/rule_item_process_name.go`、`rule_item_process_path.go`），而 ProcRoute 的规则
//! 不区分大小写、比较前先规范化（C-DRV-04，见 `procroute-rules`）。所以五种规则一律翻译成带 `(?i)`
//! 的正则，作用于 sing-box 拿到的 Win32 完整路径（`QueryFullProcessImageName`），语义与
//! `procroute_rules::matcher::Matcher` 一致；测试里逐条对照。
//!
//! 已知差异：
//!
//! - sing-box 拿到的路径不做 8.3 短名展开；
//! - `regex` 规则原样交给 Go RE2，只支持两者语法的交集（Rust 独有的写法会让 `sing-box check` 失败）。

use procroute_proto::profile::{MatchRule, MatchType};
use procroute_rules::matcher::{Matcher, RuleError};
use procroute_rules::path::normalize_path;

/// 永远不匹配：sing-box 只在拿到非空路径时才求值正则。
const NEVER: &str = "^$";
/// 允许 sing-box 拿到的路径带 `\\?\` 前缀（规范化时会去掉它）。
const PREFIX: &str = r"(?i)^(?:\\\\\?\\)?";
/// 正则里的一个路径分隔符。
const SEP: &str = r"\\";
/// 一段路径内的任意字符（不跨分隔符）。
const SEGMENT_CHAR: &str = r"[^\\]";

/// 翻译一条规则。规则先经 [`Matcher::compile`] 校验，校验失败时原样返回其错误。
pub(crate) fn translate(rule: &MatchRule) -> Result<String, RuleError> {
    Matcher::compile(rule)?;
    let value = rule.value.trim();
    Ok(match rule.kind {
        MatchType::Name => {
            let name = value.to_lowercase();
            // 进程名取自路径最后一段，含分隔符的名字在规则引擎里永远不会命中
            if name.contains(['\\', '/']) {
                NEVER.to_owned()
            } else {
                format!(r"(?i)(?:^|\\){}$", quote(&name))
            }
        }
        MatchType::Path => format!("{PREFIX}{}$", quote(&normalize_path(value))),
        MatchType::Dir => {
            let mut dir = normalize_path(value);
            if !dir.ends_with('\\') {
                dir.push('\\');
            }
            if rule.recursive {
                format!("{PREFIX}{}.+$", quote(&dir))
            } else {
                format!("{PREFIX}{}{SEGMENT_CHAR}+$", quote(&dir))
            }
        }
        MatchType::Glob => {
            let chars: Vec<char> = normalize_path(value).chars().collect();
            let mut out = PREFIX.to_owned();
            glob(&chars, &mut out)?;
            out.push('$');
            out
        }
        MatchType::Regex => format!("(?i){value}"),
    })
}

/// 翻译通配符（已规范化：小写、`\` 分隔）。语义同 globset 的 `literal_separator(true)`：
/// `*` / `?` 不跨目录，`**` 只能单独成段。
fn glob(chars: &[char], out: &mut String) -> Result<(), RuleError> {
    let bad = |why: &str| RuleError::InvalidGlob(why.to_owned());
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' if chars.get(i + 1) == Some(&'*') => {
                let at_segment_start = i == 0 || chars[i - 1] == '\\';
                match chars.get(i + 2) {
                    // `**\`：零个或多个目录
                    Some('\\') if at_segment_start => {
                        out.push_str(r"(?:.*\\)?");
                        i += 3;
                    }
                    // 结尾的 `**`：其后任意内容
                    None if at_segment_start => {
                        out.push_str(".*");
                        i += 2;
                    }
                    _ => return Err(bad("`**` 必须单独成段")),
                }
            }
            '*' => {
                out.push_str(SEGMENT_CHAR);
                out.push('*');
                i += 1;
            }
            '?' => {
                out.push_str(SEGMENT_CHAR);
                i += 1;
            }
            '[' => i = class(chars, i, out)?,
            '{' => {
                let end = chars[i..]
                    .iter()
                    .position(|&c| c == '}')
                    .map(|p| i + p)
                    .ok_or_else(|| bad("缺少 `}`"))?;
                out.push_str("(?:");
                for (n, alt) in chars[i + 1..end].split(|&c| c == ',').enumerate() {
                    if n > 0 {
                        out.push('|');
                    }
                    glob(alt, out)?;
                }
                out.push(')');
                i = end + 1;
            }
            '\\' => {
                out.push_str(SEP);
                i += 1;
            }
            c => {
                out.push_str(&quote(&c.to_string()));
                i += 1;
            }
        }
    }
    Ok(())
}

/// 字符类 `[...]` / `[!...]`，返回 `]` 之后的位置。取反的类不匹配分隔符。
fn class(chars: &[char], start: usize, out: &mut String) -> Result<usize, RuleError> {
    let mut i = start + 1;
    let negated = matches!(chars.get(i), Some('!' | '^'));
    if negated {
        i += 1;
    }
    let body_start = i;
    // 紧跟在 `[` 或 `[!` 后面的 `]` 是字面量
    if chars.get(i) == Some(&']') {
        i += 1;
    }
    while chars.get(i).is_some_and(|&c| c != ']') {
        i += 1;
    }
    if i >= chars.len() {
        return Err(RuleError::InvalidGlob("缺少 `]`".to_owned()));
    }
    out.push('[');
    if negated {
        out.push('^');
        out.push_str(SEP);
    }
    for &c in &chars[body_start..i] {
        match c {
            '\\' | ']' | '[' | '^' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push(']');
    Ok(i + 1)
}

/// 转义 RE2 元字符（同 Go 的 `regexp.QuoteMeta`）。
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        if r"\.+*?()|[]{}^$".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use procroute_rules::matcher::NormalizedProcess;
    use regex::Regex;

    use super::*;

    fn rule(kind: MatchType, value: &str, recursive: bool) -> MatchRule {
        MatchRule {
            kind,
            value: value.into(),
            recursive,
        }
    }

    /// 翻译结果对原始大小写路径的判定，必须与规则引擎对同一路径的判定一致。
    fn assert_same(r: &MatchRule, paths: &[&str]) {
        let matcher = Matcher::compile(r).unwrap();
        let re = Regex::new(&translate(r).unwrap()).unwrap();
        for path in paths {
            let expected = matcher.matches(&NormalizedProcess::new("", path));
            assert_eq!(
                re.is_match(path),
                expected,
                "rule {r:?} -> {re} on {path:?} (engine says {expected})"
            );
        }
    }

    const PATHS: &[&str] = &[
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files\Mozilla Firefox\updater.exe",
        r"C:\Program Files\Mozilla Firefox\sub\firefox.exe",
        r"D:\Games\MyGame\MyGame.exe",
        r"D:\Games\MyGame\bin\x64\MyGame.exe",
        r"D:\Games\MyGame2\MyGame.exe",
        r"D:\Games\Other\Launcher.EXE",
        r"D:\游戏\原神\YuanShen.exe",
        r"C:\a+b (x86)\[v1]\app$.exe",
        r"C:\app.exe",
        r"\\?\C:\Program Files\Mozilla Firefox\FIREFOX.EXE",
    ];

    #[test]
    fn name_rules_match_like_the_engine() {
        for v in [
            "firefox.exe",
            "MyGame.exe",
            "LAUNCHER.exe",
            "app$.exe",
            "yuanshen.exe",
            r"x\firefox.exe",
        ] {
            assert_same(&rule(MatchType::Name, v, false), PATHS);
        }
    }

    #[test]
    fn path_rules_match_like_the_engine() {
        for v in [
            "C:/Program Files/Mozilla Firefox/firefox.exe",
            r"c:\a+b (x86)\[v1]\APP$.exe",
            r"D:\游戏\原神\yuanshen.exe",
            r"C:\app.exe",
        ] {
            assert_same(&rule(MatchType::Path, v, false), PATHS);
        }
    }

    #[test]
    fn dir_rules_match_like_the_engine() {
        for v in [
            r"D:\Games\MyGame\",
            r"D:\Games\MyGame",
            "c:/program files",
            r"C:\",
            r"C:\a+b (x86)\[v1]",
        ] {
            assert_same(&rule(MatchType::Dir, v, false), PATHS);
            assert_same(&rule(MatchType::Dir, v, true), PATHS);
        }
    }

    #[test]
    fn glob_rules_match_like_the_engine() {
        for v in [
            r"D:\Games\*\MyGame.exe",
            r"D:\Games\**\MyGame.exe",
            r"D:\Games\MyGame\**",
            r"**\firefox.exe",
            "**",
            r"C:\Program Files\Mozilla Firefox\*.exe",
            r"C:\Program Files\Mozilla Firefox\?????????.exe",
            r"D:\Games\MyGame[0-9]\*.exe",
            r"D:\Games\MyGame[!0-9]*\*.exe",
            r"C:\Program Files\Mozilla Firefox\{firefox,updater}.exe",
            r"D:\Games\{MyGame,Other}\*.exe",
            r"C:\a+b (x86)\[[]v1]\app$.exe",
        ] {
            assert_same(&rule(MatchType::Glob, v, false), PATHS);
        }
    }

    #[test]
    fn regex_rules_keep_engine_semantics() {
        for v in [
            r"\\mygame\.exe$",
            r"^d:\\games\\",
            "firefox",
            r"\\(?:launcher|updater)\.exe$",
        ] {
            assert_same(&rule(MatchType::Regex, v, false), PATHS);
        }
    }

    #[test]
    fn invalid_rules_are_rejected_before_translation() {
        assert!(matches!(
            translate(&rule(MatchType::Regex, "(", false)),
            Err(RuleError::InvalidRegex(_))
        ));
        assert!(matches!(
            translate(&rule(MatchType::Glob, "a**b", false)),
            Err(RuleError::InvalidGlob(_))
        ));
        assert_eq!(
            translate(&rule(MatchType::Name, " ", false)),
            Err(RuleError::Empty)
        );
    }

    #[test]
    fn output_is_case_insensitive_and_anchored() {
        assert_eq!(
            translate(&rule(MatchType::Path, r"C:\Apps\x.exe", false)).unwrap(),
            r"(?i)^(?:\\\\\?\\)?c:\\apps\\x\.exe$"
        );
        assert_eq!(
            translate(&rule(MatchType::Name, "a.exe", false)).unwrap(),
            r"(?i)(?:^|\\)a\.exe$"
        );
    }
}
