// SPDX-License-Identifier: GPL-3.0-or-later
//! 分享链接用到的 URI 子集：`scheme://[userinfo@]host[:port][/path][?query][#fragment]`。
//!
//! 只做分享链接需要的拆分与百分号解码，不处理相对引用、规范化等。`+` 按字面量处理
//! （不当作空格）：密码里常有 `+`，把它变成空格会悄悄改掉凭据。

use super::LinkError;

/// 拆开的链接。除 `userinfo` 与 `port` 外均已百分号解码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uri {
    /// 小写的协议名。
    pub scheme: String,
    /// 原始（未解码）的 userinfo；不同协议的编码方式不同，由各自的解析器处理。
    pub userinfo: Option<String>,
    /// 主机名；IPv6 字面量不带方括号。
    pub host: String,
    /// 原始的端口部分（可能是 Hysteria2 的多端口写法）。
    pub port: Option<String>,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub fragment: Option<String>,
}

impl Uri {
    pub fn parse(link: &str) -> Result<Self, LinkError> {
        let (scheme, rest) = link.split_once("://").ok_or(LinkError::Malformed)?;
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(LinkError::Malformed);
        }
        let (rest, fragment) = match rest.split_once('#') {
            Some((r, f)) => (r, Some(decode(f)?)),
            None => (rest, None),
        };
        let (rest, query) = match rest.split_once('?') {
            Some((r, q)) => (r, parse_query(q)?),
            None => (rest, Vec::new()),
        };
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], decode(&rest[i..])?),
            None => (rest, String::new()),
        };
        let (userinfo, hostport) = match authority.rfind('@') {
            Some(i) => (Some(authority[..i].to_owned()), &authority[i + 1..]),
            None => (None, authority),
        };
        let (host, port) = split_host_port(hostport)?;
        Ok(Self {
            scheme: scheme.to_ascii_lowercase(),
            userinfo,
            host,
            port,
            path,
            query,
            fragment,
        })
    }

    /// 第一个同名查询参数（参数名不区分大小写）。
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// 非空的查询参数。
    pub fn non_empty(&self, name: &str) -> Option<&str> {
        self.param(name).filter(|v| !v.is_empty())
    }

    /// 布尔型参数：`1` / `true` 为真。
    pub fn flag(&self, name: &str) -> bool {
        self.param(name)
            .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    }

    /// 单个端口。
    pub fn single_port(&self) -> Result<u16, LinkError> {
        parse_port(self.port.as_deref().ok_or(LinkError::Malformed)?)
    }
}

fn split_host_port(s: &str) -> Result<(String, Option<String>), LinkError> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(LinkError::Malformed)?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(LinkError::Malformed)?.to_owned()),
        };
        return Ok((decode(host)?, port));
    }
    match s.rsplit_once(':') {
        Some((host, port)) => Ok((decode(host)?, Some(port.to_owned()))),
        None => Ok((decode(s)?, None)),
    }
}

/// 1–65535 的端口号。
pub(crate) fn parse_port(s: &str) -> Result<u16, LinkError> {
    match s.trim().parse::<u16>() {
        Ok(p) if p != 0 => Ok(p),
        _ => Err(LinkError::InvalidPort),
    }
}

fn parse_query(q: &str) -> Result<Vec<(String, String)>, LinkError> {
    q.split('&')
        .filter(|kv| !kv.is_empty())
        .map(|kv| {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            Ok((decode(k)?, decode(v)?))
        })
        .collect()
}

/// 百分号解码；结果必须是合法 UTF-8。
pub(crate) fn decode(s: &str) -> Result<String, LinkError> {
    if !s.contains('%') {
        return Ok(s.to_owned());
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).ok_or(LinkError::Malformed)?;
            let hi = hex_val(hex[0]).ok_or(LinkError::Malformed)?;
            let lo = hex_val(hex[1]).ok_or(LinkError::Malformed)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| LinkError::Malformed)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_every_part() {
        let u = Uri::parse("VLESS://id@example.com:443/p%2Fq?security=tls&sni=a.example.com&x#%E9%A6%99%E6%B8%AF%2001")
            .unwrap();
        assert_eq!(u.scheme, "vless");
        assert_eq!(u.userinfo.as_deref(), Some("id"));
        assert_eq!(u.host, "example.com");
        assert_eq!(u.port.as_deref(), Some("443"));
        assert_eq!(u.path, "/p/q");
        assert_eq!(u.param("SNI"), Some("a.example.com"));
        assert_eq!(u.param("x"), Some(""));
        assert_eq!(u.non_empty("x"), None);
        assert_eq!(u.fragment.as_deref(), Some("香港 01"));
        assert_eq!(u.single_port(), Ok(443));
    }

    #[test]
    fn handles_ipv6_and_missing_parts() {
        let u = Uri::parse("ss://abc@[2001:db8::1]:8388").unwrap();
        assert_eq!(u.host, "2001:db8::1");
        assert_eq!(u.port.as_deref(), Some("8388"));
        assert!(u.query.is_empty() && u.fragment.is_none() && u.path.is_empty());
        let u = Uri::parse("socks5://host").unwrap();
        assert_eq!(u.port, None);
        assert_eq!(u.single_port(), Err(LinkError::Malformed));
    }

    #[test]
    fn userinfo_uses_the_last_at_sign() {
        // 未编码的 `@` 出现在密码里时，以最后一个 `@` 为界
        let u = Uri::parse("trojan://p@ss@host:443").unwrap();
        assert_eq!(u.userinfo.as_deref(), Some("p@ss"));
        assert_eq!(u.host, "host");
    }

    #[test]
    fn plus_is_literal() {
        assert_eq!(decode("a+b%2Bc").unwrap(), "a+b+c");
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "no-scheme",
            "://x",
            "a b://x",
            "v://[::1",
            "v://[::1]x",
            "v://h:1#%zz",
            "v://h:1#%e9",
        ] {
            assert!(Uri::parse(bad).is_err(), "{bad}");
        }
        assert_eq!(parse_port("0"), Err(LinkError::InvalidPort));
        assert_eq!(parse_port("65536"), Err(LinkError::InvalidPort));
        assert_eq!(parse_port("x"), Err(LinkError::InvalidPort));
    }
}
