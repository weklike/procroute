// SPDX-License-Identifier: GPL-3.0-or-later
//! 从客户端的首包里取出目标域名（T-092，设计文档 6.3）：TLS ClientHello 的 SNI、HTTP 请求的 Host。
//!
//! 中继按域名向 sing-box 发 CONNECT，由远端重新解析，绕开本地被污染的 DNS 结果。sing-box 1.13 起删除了
//! 入站的 `sniff_override_destination`，规则动作里也没有替代，所以这一步放在中继里做。
//!
//! 纯函数、只读输入：任何输入都不会 panic（有属性测试），也不会读越界；取不到域名就退回按 IP 连接。
//! 只接受 ASCII 主机名（SNI 规定用 A-label），IP 字面量不当作域名。

/// 最多为嗅探缓存这么多字节。带后量子密钥交换的 ClientHello 约 1.8 KB，常被拆成两个 TCP 段。
pub const MAX_SNIFF_BYTES: usize = 16 * 1024;

/// 嗅探结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sniffed {
    /// 取到了域名（已转小写，去掉末尾的点）。
    Host(String),
    /// 看起来是 TLS / HTTP，但数据还不完整。
    NeedMore,
    /// 不是能识别的协议，或者里面没有可用的域名。
    Unknown,
}

const TLS_HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const HOST_NAME: u8 = 0x00;

const HTTP_METHODS: [&[u8]; 8] = [
    b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE",
];

/// 从首包取域名。
pub fn sniff_host(buf: &[u8]) -> Sniffed {
    match buf.first() {
        None => Sniffed::NeedMore,
        Some(&TLS_HANDSHAKE) => tls_sni(buf),
        Some(b) if b.is_ascii_uppercase() => http_host(buf),
        Some(_) => Sniffed::Unknown,
    }
}

/// 按大端读数字的游标；越界返回 `None`。
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|s| u16::from_be_bytes([s[0], s[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        self.take(3)
            .map(|s| usize::from(s[0]) << 16 | usize::from(s[1]) << 8 | usize::from(s[2]))
    }

    /// 读一个以 `len_bytes`（1 或 2）字节长度开头的块。
    fn block(&mut self, len_bytes: u8) -> Option<&'a [u8]> {
        let len = match len_bytes {
            1 => usize::from(self.u8()?),
            _ => usize::from(self.u16()?),
        };
        self.take(len)
    }
}

fn tls_sni(buf: &[u8]) -> Sniffed {
    let mut r = Reader::new(buf);
    let Some(header) = r.take(5) else {
        return Sniffed::NeedMore;
    };
    // 记录层版本 3.x；记录长度不超过 TLS 规定的 2^14 + 2048
    if header[1] != 3 {
        return Sniffed::Unknown;
    }
    let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
    if record_len > 18_432 {
        return Sniffed::Unknown;
    }
    let Some(record) = r.take(record_len) else {
        return if 5 + record_len <= MAX_SNIFF_BYTES {
            Sniffed::NeedMore
        } else {
            Sniffed::Unknown
        };
    };
    client_hello_sni(record).unwrap_or(Sniffed::Unknown)
}

/// 只解析第一个记录里的完整 ClientHello；跨记录的超大 ClientHello 不处理，退回按 IP 连接。
fn client_hello_sni(record: &[u8]) -> Option<Sniffed> {
    let mut r = Reader::new(record);
    if r.u8()? != CLIENT_HELLO {
        return None;
    }
    let len = r.u24()?;
    let mut hello = Reader::new(r.take(len)?);
    hello.take(2 + 32)?; // client_version + random
    hello.block(1)?; // session_id
    hello.block(2)?; // cipher_suites
    hello.block(1)?; // compression_methods
    let mut exts = Reader::new(hello.block(2)?);
    while let Some(kind) = exts.u16() {
        let data = exts.block(2)?;
        if kind != EXT_SERVER_NAME {
            continue;
        }
        let mut list = Reader::new(Reader::new(data).block(2)?);
        while let Some(name_type) = list.u8() {
            let name = list.block(2)?;
            if name_type == HOST_NAME {
                let name = std::str::from_utf8(name).ok()?;
                return Some(normalize_host(name).map_or(Sniffed::Unknown, Sniffed::Host));
            }
        }
        return None;
    }
    None
}

fn http_host(buf: &[u8]) -> Sniffed {
    let method_end = buf.iter().take(9).position(|&b| b == b' ');
    let Some(method_end) = method_end else {
        // 方法名还没收全
        return if buf.len() < 9 && buf.iter().all(u8::is_ascii_uppercase) {
            Sniffed::NeedMore
        } else {
            Sniffed::Unknown
        };
    };
    if !HTTP_METHODS.contains(&&buf[..method_end]) {
        return Sniffed::Unknown;
    }
    let Some(head_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return if buf.len() < MAX_SNIFF_BYTES {
            Sniffed::NeedMore
        } else {
            Sniffed::Unknown
        };
    };
    let Ok(head) = std::str::from_utf8(&buf[..head_end]) else {
        return Sniffed::Unknown;
    };
    for line in head.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("host") {
            return host_without_port(value.trim())
                .and_then(normalize_host)
                .map_or(Sniffed::Unknown, Sniffed::Host);
        }
    }
    Sniffed::Unknown
}

/// `example.com:8080` → `example.com`；IPv6 字面量（`[::1]:80`）不是域名。
fn host_without_port(value: &str) -> Option<&str> {
    if value.starts_with('[') {
        return None;
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            Some(host)
        }
        Some(_) => None,
        None => Some(value),
    }
}

/// 合法的 ASCII 主机名才当作域名：标签 1–63 个字母、数字、`-`、`_`，总长不超过 253，不是 IP 字面量。
fn normalize_host(raw: &str) -> Option<String> {
    let host = raw.strip_suffix('.').unwrap_or(raw);
    if host.is_empty() || host.len() > 253 || host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let valid = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    valid.then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
pub(crate) mod tests {
    use proptest::prelude::*;

    use super::*;

    /// 构造一个带 SNI 扩展（以及一个在它前面的无关扩展）的 TLS 1.2/1.3 ClientHello 记录。
    pub(crate) fn client_hello(sni: Option<&str>) -> Vec<u8> {
        let mut exts = Vec::new();
        // supported_versions：放在 SNI 前面，确认会跳过无关扩展
        exts.extend_from_slice(&[0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]);
        if let Some(name) = sni {
            let name = name.as_bytes();
            let entry_len = 1 + 2 + name.len();
            let ext_len = 2 + entry_len;
            exts.extend_from_slice(&EXT_SERVER_NAME.to_be_bytes());
            exts.extend_from_slice(&(ext_len as u16).to_be_bytes());
            exts.extend_from_slice(&(entry_len as u16).to_be_bytes());
            exts.push(HOST_NAME);
            exts.extend_from_slice(&(name.len() as u16).to_be_bytes());
            exts.extend_from_slice(name);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]);
        body.push(32);
        body.extend_from_slice(&[9u8; 32]);
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);
        let mut rec = vec![TLS_HANDSHAKE, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn tls_sni_is_extracted_and_normalized() {
        let hello = client_hello(Some("Game.Example.COM."));
        assert_eq!(sniff_host(&hello), Sniffed::Host("game.example.com".into()));
    }

    #[test]
    fn partial_client_hello_needs_more() {
        let hello = client_hello(Some("game.example.com"));
        for cut in [1, 4, 5, 40, hello.len() - 1] {
            assert_eq!(sniff_host(&hello[..cut]), Sniffed::NeedMore, "cut at {cut}");
        }
    }

    #[test]
    fn tls_without_usable_sni_is_unknown() {
        assert_eq!(sniff_host(&client_hello(None)), Sniffed::Unknown);
        assert_eq!(
            sniff_host(&client_hello(Some("203.0.113.9"))),
            Sniffed::Unknown
        );
        assert_eq!(
            sniff_host(&client_hello(Some("bad host"))),
            Sniffed::Unknown
        );
        let mut not_hello = client_hello(Some("a.example"));
        not_hello[5] = 0x02; // ServerHello
        assert_eq!(sniff_host(&not_hello), Sniffed::Unknown);
        let mut old_record = client_hello(Some("a.example"));
        old_record[1] = 2; // SSLv2 风格
        assert_eq!(sniff_host(&old_record), Sniffed::Unknown);
    }

    #[test]
    fn http_host_header_is_extracted() {
        let req =
            b"GET /index.html HTTP/1.1\r\nUser-Agent: x\r\nhOsT:  Static.Example.net:8080 \r\n\r\n";
        assert_eq!(sniff_host(req), Sniffed::Host("static.example.net".into()));
        let no_port = b"POST / HTTP/1.1\r\nHost: api.example.org\r\nContent-Length: 0\r\n\r\n";
        assert_eq!(sniff_host(no_port), Sniffed::Host("api.example.org".into()));
    }

    #[test]
    fn http_edge_cases() {
        assert_eq!(sniff_host(b"GE"), Sniffed::NeedMore);
        assert_eq!(
            sniff_host(b"GET / HTTP/1.1\r\nHost: a.example"),
            Sniffed::NeedMore
        );
        assert_eq!(sniff_host(b"HELLO world\r\n\r\n"), Sniffed::Unknown);
        assert_eq!(
            sniff_host(b"GET / HTTP/1.1\r\n\r\n"),
            Sniffed::Unknown,
            "no Host"
        );
        assert_eq!(
            sniff_host(b"GET / HTTP/1.1\r\nHost: [2001:db8::1]:80\r\n\r\n"),
            Sniffed::Unknown
        );
        assert_eq!(
            sniff_host(b"GET / HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"),
            Sniffed::Unknown
        );
        assert_eq!(
            sniff_host(b"GET / HTTP/1.1\r\nHost: a.example:http\r\n\r\n"),
            Sniffed::Unknown
        );
    }

    #[test]
    fn other_protocols_are_unknown() {
        assert_eq!(sniff_host(b"SSH-2.0-OpenSSH_9.6\r\n"), Sniffed::Unknown);
        assert_eq!(sniff_host(&[0x00, 0x01, 0x02]), Sniffed::Unknown);
        assert_eq!(sniff_host(b""), Sniffed::NeedMore);
    }

    #[test]
    fn host_names_are_validated() {
        assert_eq!(
            normalize_host("a-b_c.EXAMPLE"),
            Some("a-b_c.example".into())
        );
        assert_eq!(normalize_host(&format!("{}.com", "a".repeat(64))), None);
        assert_eq!(normalize_host(&"a.".repeat(128)), None, "too long");
        assert_eq!(normalize_host("a..b"), None);
        assert_eq!(normalize_host("例子.测试"), None, "SNI uses A-labels");
        assert_eq!(normalize_host("::1"), None);
    }

    proptest! {
        #[test]
        fn never_panics_on_arbitrary_input(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = sniff_host(&bytes);
        }

        #[test]
        fn never_panics_on_mutated_client_hellos(
            flips in proptest::collection::vec((0usize..256, any::<u8>()), 1..8),
            cut in 0usize..300,
        ) {
            let mut hello = client_hello(Some("game.example.com"));
            for (i, b) in flips {
                let i = i % hello.len();
                hello[i] = b;
            }
            let cut = cut.min(hello.len());
            let _ = sniff_host(&hello[..cut]);
        }
    }
}
