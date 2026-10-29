// SPDX-License-Identifier: GPL-3.0-or-later
//! 远程 DNS 服务器地址（`dns.remote_server`，v2 起）。
//!
//! 只做字符串解析，不解析域名、不联网（C-ARCH-02）。校验（[`crate::validate`]）与 sing-box 配置生成
//! （`procroute-core-mgr`）共用这里的结果，保证「校验通过」与「能生成」一致。

use std::net::IpAddr;

use thiserror::Error;

/// 地址的最大长度。
pub const MAX_SERVER_LEN: usize = 256;

/// 传输方式，对应 sing-box 的 DNS 服务器类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
    /// DNS over TLS。
    Tls,
    /// DNS over HTTPS。
    Https,
}

impl DnsTransport {
    /// sing-box 的 `type` 取值。
    pub fn sing_box_type(self) -> &'static str {
        match self {
            DnsTransport::Udp => "udp",
            DnsTransport::Tcp => "tcp",
            DnsTransport::Tls => "tls",
            DnsTransport::Https => "https",
        }
    }
}

/// 解析后的远程 DNS 服务器。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDns {
    pub transport: DnsTransport,
    /// IP 字面量（IPv6 不带方括号）或域名（已转小写）。
    pub host: String,
    /// 地址是不是域名；是域名时 sing-box 需要先用本地 DNS 解析它。
    pub host_is_domain: bool,
    pub port: Option<u16>,
    /// 只有 DoH 有路径；未写时由 sing-box 使用默认的 `/dns-query`。
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DnsServerError {
    #[error("只支持 udp://、tcp://、tls://、https:// 地址")]
    Scheme,
    #[error("地址过长（上限 {MAX_SERVER_LEN} 个字符）")]
    TooLong,
    #[error("地址里不能有空白、控制字符、用户信息、查询串或片段")]
    Characters,
    #[error("主机名不是合法的域名或 IP 地址")]
    Host,
    #[error("端口必须是 1–65535")]
    Port,
    #[error("只有 https:// 地址可以带路径")]
    Path,
}

/// 解析远程 DNS 服务器地址。
pub fn parse_remote(s: &str) -> Result<RemoteDns, DnsServerError> {
    if s.len() > MAX_SERVER_LEN {
        return Err(DnsServerError::TooLong);
    }
    if s.chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '?' | '#'))
    {
        return Err(DnsServerError::Characters);
    }
    let (scheme, rest) = s.split_once("://").ok_or(DnsServerError::Scheme)?;
    let transport = match scheme.to_ascii_lowercase().as_str() {
        "udp" => DnsTransport::Udp,
        "tcp" => DnsTransport::Tcp,
        "tls" => DnsTransport::Tls,
        "https" => DnsTransport::Https,
        _ => return Err(DnsServerError::Scheme),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let path = match path {
        None | Some("/") => None,
        Some(p) if transport == DnsTransport::Https => Some(p.to_owned()),
        Some(_) => return Err(DnsServerError::Path),
    };
    let (host, port) = split_host_port(authority)?;
    let (host, host_is_domain) = match host.parse::<IpAddr>() {
        Ok(ip) => (ip.to_string(), false),
        Err(_) if authority.starts_with('[') => return Err(DnsServerError::Host),
        Err(_) => (domain(host).ok_or(DnsServerError::Host)?, true),
    };
    Ok(RemoteDns {
        transport,
        host,
        host_is_domain,
        port,
        path,
    })
}

/// `host[:port]` 或 `[v6][:port]`。
fn split_host_port(authority: &str) -> Result<(&str, Option<u16>), DnsServerError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']').ok_or(DnsServerError::Host)?;
        match after {
            "" => (host, None),
            p => (host, Some(p.strip_prefix(':').ok_or(DnsServerError::Host)?)),
        }
    } else {
        match authority.rsplit_once(':') {
            // 没加方括号的 IPv6 字面量
            Some((h, _)) if h.contains(':') => (authority, None),
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let port = match port {
        None => None,
        Some(p) => Some(
            p.parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or(DnsServerError::Port)?,
        ),
    };
    if host.is_empty() {
        return Err(DnsServerError::Host);
    }
    Ok((host, port))
}

/// 合法的 ASCII 域名（标签 1–63 个字母、数字、`-`，总长不超过 253），返回小写形式。
fn domain(host: &str) -> Option<String> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    });
    ok.then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &str) -> RemoteDns {
        parse_remote(s).unwrap_or_else(|e| panic!("{s}: {e}"))
    }

    #[test]
    fn accepts_the_four_transports() {
        let udp = ok("udp://198.51.100.53");
        assert_eq!(udp.transport, DnsTransport::Udp);
        assert_eq!(udp.host, "198.51.100.53");
        assert!(!udp.host_is_domain);
        assert_eq!(udp.port, None);

        let tcp = ok("tcp://198.51.100.53:5353");
        assert_eq!((tcp.transport, tcp.port), (DnsTransport::Tcp, Some(5353)));

        let tls = ok("TLS://DNS.Example.:853");
        assert_eq!(tls.transport, DnsTransport::Tls);
        assert_eq!(tls.host, "dns.example");
        assert!(tls.host_is_domain);

        let doh = ok("https://dns.example/dns-query");
        assert_eq!(doh.transport, DnsTransport::Https);
        assert_eq!(doh.path.as_deref(), Some("/dns-query"));
        assert_eq!(ok("https://dns.example/").path, None);
    }

    #[test]
    fn ipv6_literals_with_and_without_brackets() {
        let v6 = ok("tls://[2001:db8::53]:853");
        assert_eq!((v6.host.as_str(), v6.port), ("2001:db8::53", Some(853)));
        assert_eq!(ok("udp://2001:db8::53").host, "2001:db8::53");
        assert_eq!(ok("udp://[2001:db8::53]").port, None);
    }

    #[test]
    fn rejects_malformed_addresses() {
        use DnsServerError::*;
        for (s, err) in [
            ("dns.example", Scheme),
            ("quic://dns.example", Scheme),
            ("h3://dns.example", Scheme),
            ("udp://", Host),
            ("udp://:53", Host),
            ("udp://dns..example", Host),
            ("udp://-dns.example", Host),
            ("udp://[2001:db8::53", Host),
            ("udp://[not-an-ip]", Host),
            ("udp://198.51.100.53:0", Port),
            ("udp://198.51.100.53:99999", Port),
            ("udp://198.51.100.53/path", Path),
            ("https://user@dns.example/dns-query", Characters),
            ("https://dns.example/dns-query?x=1", Characters),
            ("udp://dns.example #x", Characters),
            ("udp://例子.测试", Host),
        ] {
            assert_eq!(parse_remote(s), Err(err), "{s}");
        }
        let long = format!("https://dns.example/{}", "a".repeat(MAX_SERVER_LEN));
        assert_eq!(parse_remote(&long), Err(TooLong));
    }
}
