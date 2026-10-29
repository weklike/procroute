// SPDX-License-Identifier: GPL-3.0-or-later
//! sing-box 控制 API（Clash API）客户端：读当前连接列表（TUN 模式的连接面板，F10）与节点测速（`node.test`）。
//!
//! 只连接 127.0.0.1 上的控制 API，带每次启动随机生成的密钥（C-NET-08）。请求是手写的最小 HTTP/1.0 GET：
//! 用 1.0 是为了让服务端以关闭连接作为响应结束，不必处理分块编码；不为此引入 HTTP 库（C-DEP-03）。
//! 阻塞调用，异步代码应经 `spawn_blocking` 调用（C-CODE-05）。
//!
//! 连接列表里的地址、域名、进程路径是外部数据：这里只解析，不写日志。

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use procroute_platform_win::secret::Secret;
use procroute_proto::event::Network;
use serde_json::Value;
use thiserror::Error;

/// 响应大小上限：几千条连接也远小于它。
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// 内核里的一条连接。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelConnection {
    /// 内核分配的连接 id（UUID 字符串）。
    pub id: String,
    pub network: Network,
    /// 嗅探或请求里的域名；没有时为空。
    pub host: String,
    pub destination_ip: String,
    pub destination_port: u16,
    /// 发起连接的进程路径；内核没查到时为空。
    pub process_path: String,
    /// 经过的出站，从实际使用的节点到规则选中的出站，例如 `["节点", "自动选择"]`。
    pub chains: Vec<String>,
    pub upload: u64,
    pub download: u64,
    /// 连接开始的 Unix 毫秒时间；无法解析时为空。
    pub started_at_ms: Option<u64>,
}

impl KernelConnection {
    /// 规则选中的出站（`chains` 的最后一项）。
    pub fn routed_outbound(&self) -> Option<&str> {
        self.chains.last().map(String::as_str)
    }
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("cannot reach the control API: {0}")]
    Io(#[from] io::Error),
    #[error("the control API answered with HTTP status {0}")]
    Status(u16),
    #[error("malformed response from the control API")]
    Malformed,
    #[error("response from the control API exceeds {MAX_RESPONSE_BYTES} bytes")]
    TooLarge,
    #[error("the latency test URL must start with https://")]
    InsecureProbeUrl,
}

/// 读取当前连接列表。
pub fn fetch_connections(
    addr: SocketAddr,
    secret: &Secret<String>,
    timeout: Duration,
) -> Result<Vec<KernelConnection>, ApiError> {
    let body = get(addr, "/connections", secret, timeout)?;
    parse_connections(&body)
}

fn get(
    addr: SocketAddr,
    path: &str,
    secret: &Secret<String>,
    timeout: Duration,
) -> Result<Vec<u8>, ApiError> {
    let mut stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {addr}\r\nAuthorization: Bearer {}\r\nAccept: application/json\r\n\r\n",
        secret.expose()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut response)?;
    if response.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(ApiError::TooLarge);
    }
    split_response(response)
}

/// 检查状态码，返回响应体。
fn split_response(response: Vec<u8>) -> Result<Vec<u8>, ApiError> {
    let header_end = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or(ApiError::Malformed)?;
    let head = std::str::from_utf8(&response[..header_end]).map_err(|_| ApiError::Malformed)?;
    let status_line = head.lines().next().ok_or(ApiError::Malformed)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().ok_or(ApiError::Malformed)?;
    if !version.starts_with("HTTP/1.") {
        return Err(ApiError::Malformed);
    }
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or(ApiError::Malformed)?;
    if status != 200 {
        return Err(ApiError::Status(status));
    }
    Ok(response[header_end + 4..].to_vec())
}

/// 一次测速的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delay {
    /// 往返耗时（毫秒）。
    Ms(u32),
    /// 在限定时间内没有完成。
    TimedOut,
    /// 连不上或出错。
    Failed,
}

/// 经出站 `tag` 访问 `url` 并计时（`GET /proxies/{tag}/delay`）。`timeout` 是内核测速的超时，
/// 读取响应时多等 2 秒。`url` 必须由用户配置（C-SEC-08、C-SEC-09）。
///
/// `url` 必须以 `https://` 开头：锁定版本的 sing-box 在这个接口上会把 `http://` 开头的地址悄悄换成
/// 它内置的默认测速地址（2026-10-29 实测），那样既不是用户选的地址，也违反 C-SEC-09。
pub fn fetch_delay(
    addr: SocketAddr,
    secret: &Secret<String>,
    tag: &str,
    url: &str,
    timeout: Duration,
) -> Result<Delay, ApiError> {
    if !url.starts_with("https://") {
        return Err(ApiError::InsecureProbeUrl);
    }
    let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
    let path = format!(
        "/proxies/{}/delay?timeout={ms}&url={}",
        encode_component(tag),
        encode_component(url)
    );
    match get(addr, &path, secret, timeout + Duration::from_secs(2)) {
        Ok(body) => {
            let v: Value = serde_json::from_slice(&body).map_err(|_| ApiError::Malformed)?;
            match v.get("delay").and_then(Value::as_u64) {
                Some(0) | None => Ok(Delay::Failed),
                Some(ms) => Ok(Delay::Ms(u32::try_from(ms).unwrap_or(u32::MAX))),
            }
        }
        // 内核的约定：超时回 504，测速失败回 503
        Err(ApiError::Status(504 | 408)) => Ok(Delay::TimedOut),
        Err(ApiError::Status(503)) => Ok(Delay::Failed),
        Err(e) => Err(e),
    }
}

/// 百分号编码 URL 的一个组成部分：只保留 RFC 3986 的非保留字符。
fn encode_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// 解析 `GET /connections` 的响应体。字段缺失时取空值，单条连接解析不了就跳过。
pub fn parse_connections(body: &[u8]) -> Result<Vec<KernelConnection>, ApiError> {
    let root: Value = serde_json::from_slice(body).map_err(|_| ApiError::Malformed)?;
    let list = match root.get("connections") {
        Some(Value::Array(list)) => list.as_slice(),
        // 没有连接时 sing-box 给出 null
        Some(Value::Null) | None => &[],
        Some(_) => return Err(ApiError::Malformed),
    };
    Ok(list.iter().filter_map(connection).collect())
}

fn connection(v: &Value) -> Option<KernelConnection> {
    let meta = v.get("metadata")?;
    let text = |o: &Value, key: &str| o.get(key).and_then(Value::as_str).unwrap_or("").to_owned();
    let network = match meta.get("network").and_then(Value::as_str)? {
        "tcp" => Network::Tcp,
        "udp" => Network::Udp,
        _ => return None,
    };
    // 端口在 sing-box 里是字符串
    let port = match meta.get("destinationPort") {
        Some(Value::String(s)) => s.parse().ok()?,
        Some(Value::Number(n)) => u16::try_from(n.as_u64()?).ok()?,
        _ => return None,
    };
    let chains = v
        .get("chains")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Some(KernelConnection {
        id: v.get("id").and_then(Value::as_str)?.to_owned(),
        network,
        host: text(meta, "host"),
        destination_ip: text(meta, "destinationIP"),
        destination_port: port,
        process_path: text(meta, "processPath"),
        chains,
        upload: v.get("upload").and_then(Value::as_u64).unwrap_or(0),
        download: v.get("download").and_then(Value::as_u64).unwrap_or(0),
        started_at_ms: v
            .get("start")
            .and_then(Value::as_str)
            .and_then(parse_rfc3339_ms),
    })
}

/// 解析 Go 的 RFC 3339（可带纳秒与时区偏移）为 Unix 毫秒，例如 `2026-10-29T08:00:01.5+08:00`。
pub fn parse_rfc3339_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let part = s.get(from..from + len)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hour, minute, second) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return None;
    }
    let mut i = 19;
    let mut millis = 0i64;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while b.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let frac = &s[start..i];
        if frac.is_empty() {
            return None;
        }
        let padded = format!("{:0<3}", &frac[..frac.len().min(3)]);
        millis = padded.parse().ok()?;
    }
    let offset_secs = match b.get(i)? {
        b'Z' | b'z' if i + 1 == b.len() => 0,
        sign @ (b'+' | b'-') if i + 6 == b.len() && b[i + 3] == b':' => {
            let secs = num(i + 1, 2)? * 3600 + num(i + 4, 2)? * 60;
            if *sign == b'+' { secs } else { -secs }
        }
        _ => return None,
    };
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second - offset_secs;
    u64::try_from(secs * 1000 + millis).ok()
}

/// 公历日期到 1970-01-01 起的天数（Howard Hinnant 的 days_from_civil）。
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::mpsc;

    use super::*;

    const SAMPLE: &str = r#"{
      "downloadTotal": 10, "uploadTotal": 20, "memory": 0,
      "connections": [
        {
          "id": "0e2b6f5a-1111-4c3b-9d0e-000000000001",
          "metadata": {
            "network": "tcp", "type": "tun/tun-in", "sourceIP": "198.18.0.1", "sourcePort": "50001",
            "destinationIP": "203.0.113.24", "destinationPort": "443", "host": "game.example.com",
            "dnsMode": "normal", "processPath": "D:\\Games\\MyGame\\MyGame.exe"
          },
          "upload": 120, "download": 4096,
          "start": "2026-10-29T08:00:01.5+08:00",
          "chains": ["n1", "hk-auto"], "rule": "process_path_regex => route(hk-auto)", "rulePayload": ""
        },
        {
          "id": "0e2b6f5a-1111-4c3b-9d0e-000000000002",
          "metadata": { "network": "udp", "destinationIP": "198.51.100.7", "destinationPort": 27015 },
          "chains": ["direct"]
        },
        { "id": "broken", "metadata": { "network": "icmp", "destinationPort": "1" } }
      ]
    }"#;

    #[test]
    fn parses_connections_and_skips_unusable_ones() {
        let conns = parse_connections(SAMPLE.as_bytes()).expect("parse");
        assert_eq!(conns.len(), 2);
        let c = &conns[0];
        assert_eq!(c.network, Network::Tcp);
        assert_eq!(c.host, "game.example.com");
        assert_eq!(c.destination_ip, "203.0.113.24");
        assert_eq!(c.destination_port, 443);
        assert_eq!(c.process_path, r"D:\Games\MyGame\MyGame.exe");
        assert_eq!(c.routed_outbound(), Some("hk-auto"));
        assert_eq!((c.upload, c.download), (120, 4096));
        assert_eq!(c.started_at_ms, parse_rfc3339_ms("2026-10-29T00:00:01.5Z"));
        let d = &conns[1];
        assert_eq!(d.network, Network::Udp);
        assert_eq!(d.destination_port, 27015, "numeric ports are accepted too");
        assert_eq!(d.routed_outbound(), Some("direct"));
        assert_eq!(d.started_at_ms, None);
    }

    #[test]
    fn empty_and_malformed_bodies() {
        assert!(
            parse_connections(br#"{"connections":null}"#)
                .expect("null")
                .is_empty()
        );
        assert!(parse_connections(br#"{}"#).expect("missing").is_empty());
        assert!(matches!(
            parse_connections(br#"{"connections":5}"#),
            Err(ApiError::Malformed)
        ));
        assert!(matches!(
            parse_connections(b"<html>"),
            Err(ApiError::Malformed)
        ));
    }

    #[test]
    fn rfc3339_timestamps() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2000-03-01T00:00:00Z"),
            Some(951_868_800_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2026-10-29T08:00:01.123456789+08:00"),
            parse_rfc3339_ms("2026-10-29T00:00:01.123Z")
        );
        assert_eq!(
            parse_rfc3339_ms("2026-10-28T19:00:00-05:00"),
            parse_rfc3339_ms("2026-10-29T00:00:00Z")
        );
        for bad in [
            "",
            "2026-10-29",
            "2026-13-01T00:00:00Z",
            "2026-10-29T00:00:00",
            "2026-10-29T00:00:00.Z",
            "2026-10-29T00:00:00+0800",
            "１９７０-01-01T00:00:00Z",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
    }

    /// 回答一次请求的假控制 API；把收到的请求交给测试检查。
    fn fake_api(response: &'static [u8]) -> (SocketAddr, mpsc::Receiver<String>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let mut request = Vec::new();
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = s.read(&mut buf).expect("read");
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buf[..n]);
            }
            tx.send(String::from_utf8_lossy(&request).into_owned())
                .expect("send");
            s.write_all(response).expect("write");
        });
        (addr, rx)
    }

    #[test]
    fn delay_requests_are_encoded_and_answers_mapped() {
        let (addr, rx) = fake_api(b"HTTP/1.1 200 OK\r\n\r\n{\"delay\":123}");
        let d = fetch_delay(
            addr,
            &secret(),
            "n1a2-0",
            "https://probe.example/gen 204?a=1&b=2",
            Duration::from_secs(1),
        )
        .expect("delay");
        assert_eq!(d, Delay::Ms(123));
        let request = rx.recv().expect("request");
        assert!(
            request.starts_with(
                "GET /proxies/n1a2-0/delay?timeout=1000&url=https%3A%2F%2Fprobe.example%2Fgen%20204%3Fa%3D1%26b%3D2 HTTP/1.0\r\n"
            ),
            "{request}"
        );
        let (addr, _rx) = fake_api(b"HTTP/1.1 504 Gateway Timeout\r\n\r\n{}");
        assert!(matches!(
            fetch_delay(
                addr,
                &secret(),
                "n",
                "https://x.example",
                Duration::from_secs(1)
            ),
            Ok(Delay::TimedOut)
        ));
        let (addr, _rx) = fake_api(b"HTTP/1.1 503 Service Unavailable\r\n\r\n{}");
        assert!(matches!(
            fetch_delay(
                addr,
                &secret(),
                "n",
                "https://x.example",
                Duration::from_secs(1)
            ),
            Ok(Delay::Failed)
        ));
        let (addr, _rx) = fake_api(b"HTTP/1.1 404 Not Found\r\n\r\n{}");
        assert!(matches!(
            fetch_delay(
                addr,
                &secret(),
                "n",
                "https://x.example",
                Duration::from_secs(1)
            ),
            Err(ApiError::Status(404))
        ));
    }

    #[test]
    fn plain_http_probe_urls_are_refused_before_asking_the_kernel() {
        // 没有服务在监听：被拒绝的请求根本不会发出
        let addr = SocketAddr::from(([127, 0, 0, 1], 9));
        for url in [
            "http://probe.example/204",
            "HTTP://probe.example/204",
            "ftp://x",
        ] {
            assert!(matches!(
                fetch_delay(addr, &secret(), "n", url, Duration::from_secs(1)),
                Err(ApiError::InsecureProbeUrl)
            ));
        }
    }

    #[test]
    fn components_are_percent_encoded() {
        assert_eq!(encode_component("a-Z_0.9~"), "a-Z_0.9~");
        assert_eq!(encode_component("a b/中"), "a%20b%2F%E4%B8%AD");
    }

    fn secret() -> Secret<String> {
        Secret::new("0123456789abcdefABCDEF0123456789".into())
    }

    #[test]
    fn fetch_sends_the_secret_and_parses_the_body() {
        let (addr, rx) = fake_api(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"connections\":null}",
        );
        let conns = fetch_connections(addr, &secret(), Duration::from_secs(5)).expect("fetch");
        assert!(conns.is_empty());
        let request = rx.recv().expect("request");
        assert!(
            request.starts_with("GET /connections HTTP/1.0\r\n"),
            "{request}"
        );
        assert!(
            request.contains("\r\nAuthorization: Bearer 0123456789abcdefABCDEF0123456789\r\n"),
            "{request}"
        );
    }

    #[test]
    fn fetch_reports_http_errors() {
        let (addr, _rx) = fake_api(b"HTTP/1.1 401 Unauthorized\r\n\r\n{\"message\":\"x\"}");
        assert!(matches!(
            fetch_connections(addr, &secret(), Duration::from_secs(5)),
            Err(ApiError::Status(401))
        ));
        let (addr, _rx) = fake_api(b"garbage without a header end");
        assert!(matches!(
            fetch_connections(addr, &secret(), Duration::from_secs(5)),
            Err(ApiError::Malformed)
        ));
    }

    #[test]
    fn fetch_fails_without_a_server() {
        let addr = {
            let l = TcpListener::bind(("127.0.0.1", 0)).expect("bind");
            l.local_addr().expect("addr")
        };
        assert!(matches!(
            fetch_connections(addr, &secret(), Duration::from_secs(2)),
            Err(ApiError::Io(_))
        ));
    }
}
