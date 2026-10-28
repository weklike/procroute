// SPDX-License-Identifier: GPL-3.0-or-later
//! SOCKS5 客户端（RFC 1928 / RFC 1929），只实现与 sing-box 本地入口对接所需的部分。
//!
//! - 只提供用户名/密码认证：用户名是进程组标签，sing-box 用 `auth_user` 规则把它路由到
//!   对应出站；密码是服务每次启动随机生成的凭据（C-NET-08）。
//! - 支持 CONNECT 与 UDP ASSOCIATE，以及 UDP 数据报头的编解码。
//!
//! 错误信息里不带密码（C-SEC-04）。

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const VERSION: u8 = 0x05;
const AUTH_VERSION: u8 = 0x01;
const METHOD_USER_PASS: u8 = 0x02;
const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_V4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_V6: u8 = 0x04;

/// UDP 数据报头的最大长度：RSV(2) + FRAG(1) + ATYP(1) + 域名(1 + 255) + 端口(2)。
pub const MAX_UDP_HEADER: usize = 262;

/// 本地 SOCKS 入口的密码。`Debug` 只输出掩码（C-SEC-04）。
///
/// TODO(T-051)：`platform-win` 的 `Secret<T>` 就绪后改用它。
#[derive(Clone, PartialEq, Eq)]
pub struct Password(String);

impl Password {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// 显式取出明文，只在写入 SOCKS 认证报文时使用。
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(***)")
    }
}

/// SOCKS 地址：IP 或域名。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl From<SocketAddr> for TargetAddr {
    fn from(a: SocketAddr) -> Self {
        TargetAddr::Ip(a)
    }
}

/// 服务端的应答码（RFC 1928 §6）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplyCode {
    GeneralFailure,
    NotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Other(u8),
}

impl From<u8> for ReplyCode {
    fn from(b: u8) -> Self {
        match b {
            0x01 => ReplyCode::GeneralFailure,
            0x02 => ReplyCode::NotAllowed,
            0x03 => ReplyCode::NetworkUnreachable,
            0x04 => ReplyCode::HostUnreachable,
            0x05 => ReplyCode::ConnectionRefused,
            0x06 => ReplyCode::TtlExpired,
            0x07 => ReplyCode::CommandNotSupported,
            0x08 => ReplyCode::AddressTypeNotSupported,
            other => ReplyCode::Other(other),
        }
    }
}

#[derive(Debug, Error)]
pub enum Socks5Error {
    #[error("SOCKS5 连接出错：{0}")]
    Io(#[from] std::io::Error),
    #[error("SOCKS5 协议错误：{0}")]
    Protocol(&'static str),
    #[error("SOCKS5 服务端不接受用户名/密码认证")]
    NoAcceptableMethod,
    #[error("SOCKS5 认证失败")]
    AuthFailed,
    #[error("SOCKS5 请求被拒绝：{0:?}")]
    Rejected(ReplyCode),
    #[error("SOCKS5 字段超过 255 字节")]
    FieldTooLong,
}

pub type Result<T> = std::result::Result<T, Socks5Error>;

/// 方法协商 + 用户名/密码认证。
pub async fn handshake<S>(stream: &mut S, username: &str, password: &Password) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream.write_all(&[VERSION, 1, METHOD_USER_PASS]).await?;
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await?;
    if reply[0] != VERSION {
        return Err(Socks5Error::Protocol("unexpected version in method reply"));
    }
    match reply[1] {
        METHOD_USER_PASS => {}
        METHOD_NONE_ACCEPTABLE => return Err(Socks5Error::NoAcceptableMethod),
        _ => {
            return Err(Socks5Error::Protocol(
                "server chose a method we did not offer",
            ));
        }
    }

    let user = username.as_bytes();
    let pass = password.expose().as_bytes();
    let (Ok(user_len), Ok(pass_len)) = (u8::try_from(user.len()), u8::try_from(pass.len())) else {
        return Err(Socks5Error::FieldTooLong);
    };
    // 1 + 1 + 255 + 1 + 255
    let mut buf = [0u8; 513];
    let mut n = 0;
    for part in [&[AUTH_VERSION, user_len][..], user, &[pass_len], pass] {
        buf[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    stream.write_all(&buf[..n]).await?;
    let mut status = [0u8; 2];
    stream.read_exact(&mut status).await?;
    if status[0] != AUTH_VERSION || status[1] != 0 {
        return Err(Socks5Error::AuthFailed);
    }
    Ok(())
}

/// 发送 CONNECT，返回服务端绑定的地址。
pub async fn connect<S>(stream: &mut S, target: &TargetAddr) -> Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    request(stream, CMD_CONNECT, target).await
}

/// 发送 UDP ASSOCIATE，返回服务端用于收发 UDP 数据报的地址。
///
/// `client` 是本端将要发送数据报的地址；未知时传 `0.0.0.0:0`。
pub async fn udp_associate<S>(stream: &mut S, client: SocketAddr) -> Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    request(stream, CMD_UDP_ASSOCIATE, &TargetAddr::Ip(client)).await
}

async fn request<S>(stream: &mut S, cmd: u8, target: &TargetAddr) -> Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 3 + MAX_UDP_HEADER];
    buf[..3].copy_from_slice(&[VERSION, cmd, 0]);
    let n = 3 + write_addr(target, &mut buf[3..])?;
    stream.write_all(&buf[..n]).await?;

    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Socks5Error::Protocol("unexpected version in reply"));
    }
    if head[1] != 0 {
        return Err(Socks5Error::Rejected(ReplyCode::from(head[1])));
    }
    read_addr(stream).await
}

/// 把地址按 SOCKS 格式（ATYP + 地址 + 端口）写入 `out`，返回写入的字节数。
fn write_addr(addr: &TargetAddr, out: &mut [u8]) -> Result<usize> {
    let short = || Socks5Error::Protocol("buffer too small for address");
    let n = match addr {
        TargetAddr::Ip(SocketAddr::V4(a)) => {
            let dst = out.get_mut(..7).ok_or_else(short)?;
            dst[0] = ATYP_V4;
            dst[1..5].copy_from_slice(&a.ip().octets());
            dst[5..7].copy_from_slice(&a.port().to_be_bytes());
            7
        }
        TargetAddr::Ip(SocketAddr::V6(a)) => {
            let dst = out.get_mut(..19).ok_or_else(short)?;
            dst[0] = ATYP_V6;
            dst[1..17].copy_from_slice(&a.ip().octets());
            dst[17..19].copy_from_slice(&a.port().to_be_bytes());
            19
        }
        TargetAddr::Domain(host, port) => {
            let len = u8::try_from(host.len()).map_err(|_| Socks5Error::FieldTooLong)?;
            let total = 1 + 1 + host.len() + 2;
            let dst = out.get_mut(..total).ok_or_else(short)?;
            dst[0] = ATYP_DOMAIN;
            dst[1] = len;
            dst[2..2 + host.len()].copy_from_slice(host.as_bytes());
            dst[2 + host.len()..].copy_from_slice(&port.to_be_bytes());
            total
        }
    };
    Ok(n)
}

async fn read_addr<S: AsyncRead + Unpin>(stream: &mut S) -> Result<TargetAddr> {
    let atyp = stream.read_u8().await?;
    match atyp {
        ATYP_V4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            let port = stream.read_u16().await?;
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(b)),
                port,
            )))
        }
        ATYP_V6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            let port = stream.read_u16().await?;
            Ok(TargetAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(b)),
                port,
            )))
        }
        ATYP_DOMAIN => {
            let len = usize::from(stream.read_u8().await?);
            let mut b = [0u8; 255];
            stream.read_exact(&mut b[..len]).await?;
            let port = stream.read_u16().await?;
            let host = std::str::from_utf8(&b[..len])
                .map_err(|_| Socks5Error::Protocol("domain is not UTF-8"))?;
            Ok(TargetAddr::Domain(host.to_owned(), port))
        }
        _ => Err(Socks5Error::Protocol("unknown address type")),
    }
}

/// 把 UDP 数据报头（RSV RSV FRAG ATYP ADDR PORT）写入 `out`，返回头部长度。
pub fn encode_udp_header(target: &TargetAddr, out: &mut [u8]) -> Result<usize> {
    let head = out
        .get_mut(..3)
        .ok_or(Socks5Error::Protocol("buffer too small for UDP header"))?;
    head.copy_from_slice(&[0, 0, 0]);
    Ok(3 + write_addr(target, &mut out[3..])?)
}

/// 解析 UDP 数据报，返回（来源 / 目标地址, 负载）。不支持分片（FRAG ≠ 0 视为错误）。
pub fn decode_udp(packet: &[u8]) -> Result<(TargetAddr, &[u8])> {
    let bad = Socks5Error::Protocol("truncated UDP datagram");
    let [0, 0, frag, atyp, rest @ ..] = packet else {
        return Err(bad);
    };
    if *frag != 0 {
        return Err(Socks5Error::Protocol(
            "fragmented UDP datagrams are not supported",
        ));
    }
    let port_at = |rest: &[u8], at: usize| -> Option<u16> {
        Some(u16::from_be_bytes([*rest.get(at)?, *rest.get(at + 1)?]))
    };
    let (addr, used) = match *atyp {
        ATYP_V4 => {
            let ip: [u8; 4] = rest.get(..4).and_then(|s| s.try_into().ok()).ok_or(bad)?;
            let port = port_at(rest, 4).ok_or(Socks5Error::Protocol("truncated"))?;
            (
                TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip.into()), port)),
                6,
            )
        }
        ATYP_V6 => {
            let ip: [u8; 16] = rest.get(..16).and_then(|s| s.try_into().ok()).ok_or(bad)?;
            let port = port_at(rest, 16).ok_or(Socks5Error::Protocol("truncated"))?;
            (
                TargetAddr::Ip(SocketAddr::new(IpAddr::V6(ip.into()), port)),
                18,
            )
        }
        ATYP_DOMAIN => {
            let len = usize::from(*rest.first().ok_or(bad)?);
            let host = rest
                .get(1..1 + len)
                .ok_or(Socks5Error::Protocol("truncated"))?;
            let host = std::str::from_utf8(host)
                .map_err(|_| Socks5Error::Protocol("domain is not UTF-8"))?;
            let port = port_at(rest, 1 + len).ok_or(Socks5Error::Protocol("truncated"))?;
            (TargetAddr::Domain(host.to_owned(), port), 1 + len + 2)
        }
        _ => return Err(Socks5Error::Protocol("unknown address type")),
    };
    Ok((addr, &rest[used..]))
}

#[cfg(test)]
mod tests {
    use tokio::io::duplex;

    use super::*;

    fn pw() -> Password {
        Password::new("s3cret-r4ndom")
    }

    #[test]
    fn password_debug_is_masked() {
        let dbg = format!("{:?}", pw());
        assert!(!dbg.contains("s3cret"), "{dbg}");
        let err = Socks5Error::AuthFailed.to_string();
        assert!(!err.contains("s3cret"));
    }

    #[test]
    fn udp_header_round_trips_for_every_address_type() {
        let cases = [
            TargetAddr::Ip("203.0.113.24:27015".parse().unwrap()),
            TargetAddr::Ip("[2001:db8::1]:443".parse().unwrap()),
            TargetAddr::Domain("example.com".into(), 53),
        ];
        for addr in cases {
            let mut buf = [0u8; MAX_UDP_HEADER + 4];
            let n = encode_udp_header(&addr, &mut buf).unwrap();
            buf[n..n + 4].copy_from_slice(b"ping");
            let (decoded, payload) = decode_udp(&buf[..n + 4]).unwrap();
            assert_eq!(decoded, addr);
            assert_eq!(payload, b"ping");
        }
    }

    #[test]
    fn decode_rejects_truncated_and_fragmented_datagrams() {
        assert!(decode_udp(&[]).is_err());
        assert!(decode_udp(&[0, 0, 0, ATYP_V4, 1, 2]).is_err());
        assert!(decode_udp(&[0, 0, 1, ATYP_V4, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(decode_udp(&[0, 0, 0, 9, 1, 2, 3, 4, 0, 80]).is_err());
        assert!(decode_udp(&[0, 0, 0, ATYP_DOMAIN, 5, b'a']).is_err());
    }

    #[test]
    fn overlong_domain_is_rejected() {
        let mut buf = [0u8; 600];
        let long = TargetAddr::Domain("a".repeat(256), 80);
        assert!(matches!(
            encode_udp_header(&long, &mut buf),
            Err(Socks5Error::FieldTooLong)
        ));
    }

    #[tokio::test]
    async fn handshake_and_connect_write_the_expected_bytes() {
        let (mut client, mut server) = duplex(1024);
        let srv = tokio::spawn(async move {
            let mut b = [0u8; 3];
            server.read_exact(&mut b).await.unwrap();
            assert_eq!(b, [5, 1, 2]);
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = vec![0u8; 2 + 4 + 1 + 13];
            server.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth[..6], &[1, 4, b'g', b'a', b'm', b'e']);
            assert_eq!(auth[6], 13);
            assert_eq!(&auth[7..], b"s3cret-r4ndom");
            server.write_all(&[1, 0]).await.unwrap();
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req, [5, 1, 0, 1, 203, 0, 113, 24, 1, 187]);
            server
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x30, 0x39])
                .await
                .unwrap();
        });
        handshake(&mut client, "game", &pw()).await.unwrap();
        let bound = connect(
            &mut client,
            &TargetAddr::Ip("203.0.113.24:443".parse().unwrap()),
        )
        .await
        .unwrap();
        assert_eq!(bound, TargetAddr::Ip("127.0.0.1:12345".parse().unwrap()));
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn rejected_method_and_failed_auth_are_errors() {
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut b = [0u8; 3];
            server.read_exact(&mut b).await.unwrap();
            server.write_all(&[5, 0xff]).await.unwrap();
        });
        assert!(matches!(
            handshake(&mut client, "game", &pw()).await,
            Err(Socks5Error::NoAcceptableMethod)
        ));

        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut b = [0u8; 3];
            server.read_exact(&mut b).await.unwrap();
            server.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0u8; 20];
            server.read_exact(&mut auth).await.unwrap();
            server.write_all(&[1, 1]).await.unwrap();
        });
        assert!(matches!(
            handshake(&mut client, "game", &pw()).await,
            Err(Socks5Error::AuthFailed)
        ));
    }

    #[tokio::test]
    async fn connect_failure_reply_is_surfaced() {
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            server
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let err = connect(
            &mut client,
            &TargetAddr::Ip("203.0.113.24:443".parse().unwrap()),
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            Socks5Error::Rejected(ReplyCode::ConnectionRefused)
        ));
    }

    #[tokio::test]
    async fn udp_associate_returns_relay_address_including_domain_form() {
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            let mut req = [0u8; 10];
            server.read_exact(&mut req).await.unwrap();
            assert_eq!(req[1], CMD_UDP_ASSOCIATE);
            let mut reply = vec![5, 0, 0, ATYP_DOMAIN, 9];
            reply.extend_from_slice(b"localhost");
            reply.extend_from_slice(&5353u16.to_be_bytes());
            server.write_all(&reply).await.unwrap();
        });
        let relay = udp_associate(&mut client, "0.0.0.0:0".parse().unwrap())
            .await
            .unwrap();
        assert_eq!(relay, TargetAddr::Domain("localhost".into(), 5353));
    }
}
