// SPDX-License-Identifier: GPL-3.0-or-later
//! 单条匹配规则的编译与求值（T-031）。
//!
//! 所有比较都在规范形式上进行（见 [`crate::path`]）：小写、`\` 分隔。
//! - `name`：与进程名比较，不区分大小写；
//! - `path`：与完整路径比较；
//! - `dir`：进程所在目录等于该目录，`recursive` 时也匹配子目录；
//! - `glob`：作用于完整路径，`*` 不跨目录、`**` 跨目录；
//! - `regex`：作用于规范化后的完整路径，不区分大小写。

use globset::{GlobBuilder, GlobMatcher};
use procroute_proto::profile::{MatchRule, MatchType};
use regex::{Regex, RegexBuilder};
use thiserror::Error;

use crate::path::{file_name, is_within, normalize_path, parent_dir};

/// 规则值的长度上限。
pub const MAX_RULE_VALUE_LEN: usize = 1024;
/// 编译后正则的大小上限，防止病态表达式占用过多内存。
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// 已规范化的进程身份，供匹配使用。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedProcess {
    /// 小写进程名，例如 `mygame.exe`。
    pub name: String,
    /// 规范化后的完整路径。
    pub path: String,
}

impl NormalizedProcess {
    /// `name` 为空时取路径的最后一段。
    pub fn new(name: &str, path: &str) -> Self {
        let path = normalize_path(path);
        let name = name.trim();
        let name = if name.is_empty() {
            file_name(&path).to_owned()
        } else {
            name.to_lowercase()
        };
        Self { name, path }
    }
}

/// 规则编译失败的原因。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RuleError {
    #[error("规则内容为空")]
    Empty,
    #[error("规则内容过长：{len} 个字符，上限 {max}")]
    TooLong { len: usize, max: usize },
    #[error("只有目录规则可以设置 recursive")]
    RecursiveOnlyForDir,
    #[error("通配符无效：{0}")]
    InvalidGlob(String),
    #[error("正则表达式无效：{0}")]
    InvalidRegex(String),
}

/// 编译好的单条规则。
#[derive(Debug, Clone)]
pub enum Matcher {
    Name(String),
    Path(String),
    Dir { dir: String, recursive: bool },
    Glob(GlobMatcher),
    Regex(Regex),
}

impl Matcher {
    pub fn compile(rule: &MatchRule) -> Result<Self, RuleError> {
        let value = rule.value.trim();
        if value.is_empty() {
            return Err(RuleError::Empty);
        }
        let len = value.chars().count();
        if len > MAX_RULE_VALUE_LEN {
            return Err(RuleError::TooLong {
                len,
                max: MAX_RULE_VALUE_LEN,
            });
        }
        if rule.recursive && rule.kind != MatchType::Dir {
            return Err(RuleError::RecursiveOnlyForDir);
        }
        Ok(match rule.kind {
            MatchType::Name => Matcher::Name(value.to_lowercase()),
            MatchType::Path => Matcher::Path(normalize_path(value)),
            MatchType::Dir => Matcher::Dir {
                dir: normalize_path(value),
                recursive: rule.recursive,
            },
            MatchType::Glob => Matcher::Glob(compile_glob(value)?),
            MatchType::Regex => Matcher::Regex(
                RegexBuilder::new(value)
                    .case_insensitive(true)
                    .size_limit(REGEX_SIZE_LIMIT)
                    .build()
                    .map_err(|e| RuleError::InvalidRegex(e.to_string()))?,
            ),
        })
    }

    pub fn kind(&self) -> MatchType {
        match self {
            Matcher::Name(_) => MatchType::Name,
            Matcher::Path(_) => MatchType::Path,
            Matcher::Dir { .. } => MatchType::Dir,
            Matcher::Glob(_) => MatchType::Glob,
            Matcher::Regex(_) => MatchType::Regex,
        }
    }

    pub fn matches(&self, p: &NormalizedProcess) -> bool {
        match self {
            Matcher::Name(name) => p.name == *name,
            Matcher::Path(path) => p.path == *path,
            Matcher::Dir { dir, recursive } => {
                if *recursive {
                    is_within(&p.path, dir)
                } else {
                    parent_dir(&p.path) == dir
                }
            }
            Matcher::Glob(glob) => glob.is_match(to_slashes(&p.path)),
            Matcher::Regex(re) => re.is_match(&p.path),
        }
    }
}

/// 通配符与路径都转成 `/` 分隔再交给 globset，保证在任何操作系统上行为一致。
fn compile_glob(pattern: &str) -> Result<GlobMatcher, RuleError> {
    let normalized = to_slashes(&normalize_path(pattern));
    GlobBuilder::new(&normalized)
        .case_insensitive(true)
        .literal_separator(true)
        .backslash_escape(false)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| RuleError::InvalidGlob(e.to_string()))
}

fn to_slashes(s: &str) -> String {
    s.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(kind: MatchType, value: &str, recursive: bool) -> MatchRule {
        MatchRule {
            kind,
            value: value.into(),
            recursive,
        }
    }

    fn proc(path: &str) -> NormalizedProcess {
        NormalizedProcess::new("", path)
    }

    fn hit(r: &MatchRule, path: &str) -> bool {
        Matcher::compile(r).unwrap().matches(&proc(path))
    }

    #[test]
    fn name_is_case_insensitive() {
        let r = rule(MatchType::Name, "Launcher.EXE", false);
        assert!(hit(&r, r"D:\Games\MyGame\launcher.exe"));
        assert!(!hit(&r, r"D:\Games\MyGame\launcher2.exe"));
    }

    #[test]
    fn path_compares_normalized_forms() {
        let r = rule(
            MatchType::Path,
            "C:/Program Files/Mozilla Firefox/firefox.exe",
            false,
        );
        assert!(hit(&r, r"\\?\C:\Program Files\Mozilla Firefox\FIREFOX.EXE"));
        assert!(!hit(&r, r"C:\Program Files\Mozilla Firefox\updater.exe"));
    }

    #[test]
    fn dir_respects_recursive_flag() {
        let flat = rule(MatchType::Dir, r"D:\Games\MyGame\", false);
        assert!(hit(&flat, r"D:\Games\MyGame\MyGame.exe"));
        assert!(!hit(&flat, r"D:\Games\MyGame\bin\Crash.exe"));
        assert!(!hit(&flat, r"D:\Games\MyGame2\MyGame.exe"));

        let deep = rule(MatchType::Dir, r"D:\Games\MyGame", true);
        assert!(hit(&deep, r"D:\Games\MyGame\bin\Crash.exe"));
        assert!(!hit(&deep, r"D:\Games\MyGame2\x.exe"));
    }

    #[test]
    fn glob_star_stays_within_one_directory() {
        let r = rule(MatchType::Glob, r"D:\Games\*\bin\*.exe", false);
        assert!(hit(&r, r"D:\Games\MyGame\bin\MyGame.exe"));
        assert!(!hit(&r, r"D:\Games\MyGame\x\bin\MyGame.exe"));
        let deep = rule(MatchType::Glob, r"D:\Games\**\*.exe", false);
        assert!(hit(&deep, r"D:\Games\MyGame\x\bin\MyGame.exe"));
    }

    #[test]
    fn regex_is_case_insensitive_on_normalized_path() {
        let r = rule(MatchType::Regex, r"^C:\\Games\\.+\.EXE$", false);
        assert!(hit(&r, r"c:\games\a\b.exe"));
        assert!(!hit(&r, r"d:\games\a\b.exe"));
    }

    #[test]
    fn rejects_bad_rules() {
        assert_eq!(
            Matcher::compile(&rule(MatchType::Name, "  ", false)).unwrap_err(),
            RuleError::Empty
        );
        assert_eq!(
            Matcher::compile(&rule(MatchType::Name, "a.exe", true)).unwrap_err(),
            RuleError::RecursiveOnlyForDir
        );
        assert!(matches!(
            Matcher::compile(&rule(MatchType::Regex, "(", false)).unwrap_err(),
            RuleError::InvalidRegex(_)
        ));
        assert!(matches!(
            Matcher::compile(&rule(MatchType::Glob, "a[", false)).unwrap_err(),
            RuleError::InvalidGlob(_)
        ));
        let long = "a".repeat(MAX_RULE_VALUE_LEN + 1);
        assert!(matches!(
            Matcher::compile(&rule(MatchType::Name, &long, false)).unwrap_err(),
            RuleError::TooLong { .. }
        ));
    }

    #[test]
    fn process_name_falls_back_to_file_name() {
        let p = NormalizedProcess::new("", r"D:\Games\MyGame.exe");
        assert_eq!(p.name, "mygame.exe");
        let p = NormalizedProcess::new("MyGame.exe", r"D:\x.exe");
        assert_eq!(p.name, "mygame.exe");
    }
}
