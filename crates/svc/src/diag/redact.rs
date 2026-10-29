// SPDX-License-Identifier: GPL-3.0-or-later
//! 诊断包里文本的脱敏（C-SEC-04）。
//!
//! 服务的日志从设计上就不含凭据与完整节点地址，这里是导出前的第二道防线，按顺序做四件事：
//!
//! 1. 登记过的文本（节点地址、TLS 服务器名、凭据、订阅地址）整体替换成占位符，不区分 ASCII 大小写；
//!    短于 [`WHOLE_WORD_BELOW`] 个字符的只在词边界上替换，免得把日志弄得面目全非；
//! 2. 字段名像凭据的 `key=value`（与界面 `features/log/redact.ts` 同一组关键词），值换成 `***`；
//! 3. 公网 IP 换成 `<ip>`（端口保留）；回环、私有、链路本地等地址保留，便于排查；
//! 4. `\Users\<名字>` 里的用户名换成 `<user>`。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

use procroute_platform_win::secret::Secret;

pub const MASK: &str = "***";
pub const IP: &str = "<ip>";
pub const USER: &str = "<user>";

/// 短于这个长度的登记文本不处理：一两个字符无法有意义地替换。
const MIN_LITERAL_CHARS: usize = 3;
/// 短于这个长度的登记文本只在词边界上替换。
const WHOLE_WORD_BELOW: usize = 8;

/// 字段名里出现这些片段即视为凭据（不区分大小写）。
const SENSITIVE_KEYS: &[&str] = &[
    "pass",
    "pwd",
    "secret",
    "token",
    "private_key",
    "privatekey",
    "private-key",
    "psk",
    "pre_shared",
    "preshared",
    "pre-shared",
    "uuid",
    "credential",
    "auth",
];

/// 不是个人用户名的 `Users` 子目录。
const SHARED_PROFILE_DIRS: &[&str] = &["public", "default", "default user", "all users"];

struct Literal {
    /// ASCII 小写形式。
    needle: Secret<String>,
    placeholder: &'static str,
    whole_word: bool,
}

/// 文本脱敏器。登记的文本可能是凭据，只以 [`Secret`] 持有。
#[derive(Default)]
pub struct Redactor {
    /// 按长度从长到短，长的先替换（完整地址先于其中的主机名）。
    literals: Vec<Literal>,
}

impl Redactor {
    /// 登记一段要整体替换的文本。
    pub fn add(&mut self, text: &str, placeholder: &'static str) {
        let chars = text.chars().count();
        if chars < MIN_LITERAL_CHARS {
            return;
        }
        let needle = text.to_ascii_lowercase();
        if self.literals.iter().any(|l| *l.needle.expose() == needle) {
            return;
        }
        self.literals.push(Literal {
            needle: Secret::new(needle),
            placeholder,
            whole_word: chars < WHOLE_WORD_BELOW,
        });
        self.literals
            .sort_by_key(|l| std::cmp::Reverse(l.needle.expose().len()));
    }

    /// 对一行文本做全部四步脱敏。
    pub fn redact(&self, line: &str) -> String {
        let mut out = line.to_owned();
        for l in &self.literals {
            out = replace_literal(&out, l);
        }
        scrub_user_dirs(&mask_public_ips(&mask_sensitive_fields(&out)))
    }
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn replace_literal(text: &str, l: &Literal) -> String {
    let needle = l.needle.expose();
    // ASCII 小写不改变字节长度与字符边界，小写副本里的位置可以直接用在原文上。
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (i, _) in lower.match_indices(needle.as_str()) {
        if i < last {
            continue;
        }
        let end = i + needle.len();
        if l.whole_word {
            let before = text[..i].chars().next_back().is_some_and(is_word_char);
            let after = text[end..].chars().next().is_some_and(is_word_char);
            if before || after {
                continue;
            }
        }
        out.push_str(&text[last..i]);
        out.push_str(l.placeholder);
        last = end;
    }
    out.push_str(&text[last..]);
    out
}

fn is_key_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|k| key.contains(k))
}

/// `password=abc`、`token="a b"` → `password=***`、`token=***`。
pub fn mask_sensitive_fields(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (eq, _) in text.match_indices('=') {
        if eq < last {
            continue;
        }
        let key_start = text[..eq]
            .char_indices()
            .rev()
            .take_while(|&(_, c)| is_key_char(c))
            .last()
            .map_or(eq, |(i, _)| i);
        if key_start == eq || !is_sensitive_key(&text[key_start..eq]) {
            continue;
        }
        let value_end = value_end(text, eq + 1);
        out.push_str(&text[last..=eq]);
        out.push_str(MASK);
        last = value_end;
    }
    out.push_str(&text[last..]);
    out
}

/// 值的结束位置：带引号的值到配对的引号为止（跳过 `\` 转义），否则到下一个空白。
fn value_end(text: &str, start: usize) -> usize {
    let rest = &text[start..];
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut escaped = false;
        for (i, c) in quoted.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => return start + 1 + i + 1,
                _ => {}
            }
        }
        return text.len();
    }
    rest.find(char::is_whitespace)
        .map_or(text.len(), |i| start + i)
}

fn is_ip_char(c: char) -> bool {
    c.is_ascii_hexdigit() || c == ':' || c == '.'
}

/// 公网 IP 换成 [`IP`]；`1.2.3.4:443` 保留端口。
pub fn mask_public_ips(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((start, c)) = chars.next() {
        if !is_ip_char(c) {
            continue;
        }
        let mut end = start + c.len_utf8();
        while let Some(&(i, c)) = chars.peek() {
            if !is_ip_char(c) {
                break;
            }
            end = i + c.len_utf8();
            chars.next();
        }
        // 必须是独立的一段：`svc::handlers` 里的 `c::`、时间戳里的 `12:34:56` 都不算
        let before = text[..start].chars().next_back().is_some_and(is_word_char);
        let after = text[end..].chars().next().is_some_and(is_word_char);
        if before || after {
            continue;
        }
        if let Some(masked) = mask_run(&text[start..end]) {
            out.push_str(&text[last..start]);
            out.push_str(&masked);
            last = end;
        }
    }
    out.push_str(&text[last..]);
    out
}

/// 一段由十六进制数字、`:`、`.` 组成的文本：是公网地址时返回替换结果。
fn mask_run(run: &str) -> Option<String> {
    let trimmed = run.trim_end_matches(['.', ':']);
    let tail = &run[trimmed.len()..];
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return is_public(ip).then(|| format!("{IP}{tail}"));
    }
    let sock = trimmed.parse::<SocketAddrV4>().ok()?;
    is_public(IpAddr::V4(*sock.ip())).then(|| format!("{IP}:{}{tail}", sock.port()))
}

fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or_else(|| is_public_v6(v6), is_public_v4),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, ..] = ip.octets();
    let shared = a == 100 && (64..128).contains(&b); // 100.64.0.0/10
    let benchmarking = a == 198 && (b == 18 || b == 19); // 198.18.0.0/15，常见的 fake-ip 网段
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || shared
        || benchmarking)
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let first = ip.segments()[0];
    let link_local = first & 0xffc0 == 0xfe80; // fe80::/10
    let unique_local = first & 0xfe00 == 0xfc00; // fc00::/7
    !(ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || link_local || unique_local)
}

fn is_separator(c: char) -> bool {
    c == '\\' || c == '/'
}

/// 结束用户名的字符：引号、分隔用的标点，以及通配符与正则元字符（规则里的 `Users\*` 原样保留）。
fn ends_user_name(c: char) -> bool {
    matches!(
        c,
        '"' | '\''
            | ','
            | ';'
            | ':'
            | '*'
            | '?'
            | '<'
            | '>'
            | '|'
            | '['
            | ']'
            | '('
            | ')'
            | '{'
            | '}'
            | '^'
            | '$'
            | '+'
            | '='
    ) || (c.is_whitespace() && c != ' ')
}

/// `C:\Users\alice\x.exe`、`C:\\Users\\alice` → 用户名换成 [`USER`]。
pub fn scrub_user_dirs(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    for (i, _) in lower.match_indices("users") {
        if i < last || !text[..i].ends_with(is_separator) {
            continue;
        }
        let after = &text[i + "users".len()..];
        let seps = after.len() - after.trim_start_matches(is_separator).len();
        if seps == 0 {
            continue;
        }
        let start = i + "users".len() + seps;
        let end = start + user_name_len(&text[start..]);
        let name = &text[start..end];
        if name.is_empty() || SHARED_PROFILE_DIRS.contains(&name.to_lowercase().as_str()) {
            continue;
        }
        out.push_str(&text[last..start]);
        out.push_str(USER);
        last = end;
    }
    out.push_str(&text[last..]);
    out
}

/// 用户名到下一个路径分隔符为止。用户名可以含空格，但后面没有分隔符时只取到第一个空格，
/// 免得把一句话的其余部分当成用户名。
fn user_name_len(rest: &str) -> usize {
    let mut first_space = None;
    for (i, c) in rest.char_indices() {
        if is_separator(c) {
            return i;
        }
        if ends_user_name(c) {
            return first_space.unwrap_or(i);
        }
        if c == ' ' && first_space.is_none() {
            first_space = Some(i);
        }
    }
    first_space.unwrap_or(rest.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(entries: &[(&str, &'static str)]) -> Redactor {
        let mut r = Redactor::default();
        for (text, placeholder) in entries {
            r.add(text, placeholder);
        }
        r
    }

    #[test]
    fn registered_text_is_replaced_case_insensitively_longest_first() {
        let r = redactor(&[
            ("hk1.example.net", "<node>"),
            ("https://sub.example.org/api?token=abc123", "<subscription>"),
            ("sub.example.org", "<subscription>"),
        ]);
        assert_eq!(
            r.redact("dial HK1.Example.NET:443 failed"),
            "dial <node>:443 failed"
        );
        assert_eq!(
            r.redact("fetch https://sub.example.org/api?token=abc123 then sub.example.org"),
            "fetch <subscription> then <subscription>"
        );
    }

    #[test]
    fn short_secrets_only_match_whole_words() {
        let r = redactor(&[("user", "***"), ("s3cr3t", "***"), ("ab", "***")]);
        // `Users` 目录与 `username` 不受影响，独立的词被替换
        assert_eq!(r.redact("login user ok"), "login *** ok");
        assert_eq!(r.redact("Users username"), "Users username");
        assert_eq!(r.redact("x=s3cr3t."), "x=***.");
        assert_eq!(r.redact("x=as3cr3t"), "x=as3cr3t");
        // 太短的不登记
        assert_eq!(r.redact("ab cd"), "ab cd");
    }

    #[test]
    fn long_secrets_match_anywhere_and_non_ascii_is_safe() {
        let pw = "Pa55-w0rd-密码-long";
        let r = redactor(&[(pw, "***")]);
        assert_eq!(r.redact(&format!("前缀{pw}后缀")), "前缀***后缀");
        assert_eq!(
            r.redact(&format!("{}{}", "x", pw.to_uppercase())),
            "x***",
            "ASCII case is ignored"
        );
    }

    #[test]
    fn sensitive_fields_are_masked() {
        assert_eq!(
            mask_sensitive_fields(r#"login password=hunter2 user=bob"#),
            "login password=*** user=bob"
        );
        assert_eq!(
            mask_sensitive_fields(r#"x api_token="a \"b\" c" y=1"#),
            "x api_token=*** y=1"
        );
        assert_eq!(
            mask_sensitive_fields("PSK=abc, uuid=1234 Authorization=Bearer"),
            "PSK=*** uuid=*** Authorization=***"
        );
        assert_eq!(mask_sensitive_fields("secret=\"unterminated"), "secret=***");
        assert_eq!(mask_sensitive_fields("a==b =c count=3"), "a==b =c count=3");
    }

    #[test]
    fn public_ips_are_masked_and_local_ones_kept() {
        assert_eq!(
            mask_public_ips("dial 203.0.113.7:443 via 127.0.0.1:9090"),
            "dial <ip>:443 via 127.0.0.1:9090"
        );
        assert_eq!(
            mask_public_ips("peer [2001:db8::1]:443 lan 192.168.1.2 tun 172.19.0.1"),
            "peer [<ip>]:443 lan 192.168.1.2 tun 172.19.0.1"
        );
        assert_eq!(
            mask_public_ips("ula fd00::1 ll fe80::1 any :: mapped ::ffff:8.8.4.4"),
            "ula fd00::1 ll fe80::1 any :: mapped <ip>"
        );
        assert_eq!(
            mask_public_ips("fake 198.18.0.5 cgnat 100.64.1.1 end 1.1.1.1."),
            "fake 198.18.0.5 cgnat 100.64.1.1 end <ip>."
        );
    }

    #[test]
    fn non_addresses_are_left_alone() {
        for text in [
            "2026-10-29T12:34:56.789012Z  INFO procroute_svc::handlers: started",
            "sing-box 1.14.4 build 10.0.26100.2314",
            "hash deadbeef cafe::babe_x",
            "ratio 12:34",
        ] {
            assert_eq!(mask_public_ips(text), text);
        }
    }

    #[test]
    fn user_names_in_paths_are_replaced() {
        assert_eq!(
            scrub_user_dirs(r"image=C:\Users\alice\AppData\x.exe"),
            r"image=C:\Users\<user>\AppData\x.exe"
        );
        assert_eq!(
            scrub_user_dirs(r#"path="C:\\Users\\Bob Smith\\Games\\a.exe""#),
            r#"path="C:\\Users\\<user>\\Games\\a.exe""#
        );
        assert_eq!(
            scrub_user_dirs(r"\Device\HarddiskVolume3\USERS\carol"),
            r"\Device\HarddiskVolume3\USERS\<user>"
        );
        assert_eq!(
            scrub_user_dirs(r"C:\Users\dave launched C:\x.exe"),
            r"C:\Users\<user> launched C:\x.exe"
        );
    }

    #[test]
    fn shared_dirs_and_patterns_are_kept() {
        for text in [
            r"C:\Users\Public\Desktop",
            r"C:\Users\Default\x",
            r"C:\Users\*\Games\*.exe",
            r"(?i)^C:\\Users\\[^\\]+\\Games",
            r"MyUsers\alice",
            r"C:\Users",
        ] {
            assert_eq!(scrub_user_dirs(text), text);
        }
    }

    #[test]
    fn all_steps_combine() {
        let r = redactor(&[("node.example.net", "<node>")]);
        assert_eq!(
            r.redact(r"connect node.example.net 203.0.113.9 password=x C:\Users\eve\a.exe"),
            r"connect <node> <ip> password=*** C:\Users\<user>\a.exe"
        );
    }
}
