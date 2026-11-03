// SPDX-License-Identifier: GPL-3.0-or-later
//! IP 数据包的解析与地址改写（T-075），纯函数，不依赖驱动。
//!
//! 只处理不分片、不带扩展头的 IPv4 / IPv6 上的 TCP 与 UDP。其余（IPv4 分片、IPv6 扩展头、其他协议、
//! 截断的包）解析为错误，由调用方对目标进程按 fail_policy 处理（C-NET-07），对非目标进程原样放行。
//!
//! 改写只改地址与端口，不碰校验和：改写后由 `WinDivert::calc_checksums` 统一重算。
//! 全部在调用方的缓冲区上原地进行，不分配内存（C-CODE-04）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use procroute_proto::event::Network;
use thiserror::Error;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const TCP_MIN_HEADER: usize = 20;
const UDP_HEADER: usize = 8;

/// TCP 标志位。
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum PacketError {
    #[error("packet is truncated")]
    Truncated,
    #[error("not an IPv4 or IPv6 packet")]
    NotIp,
    #[error("IPv4 fragment")]
    Fragment,
    #[error("IPv6 extension headers are not supported")]
    Ipv6Extension,
    #[error("unsupported transport protocol {0}")]
    Protocol(u8),
    #[error("address family does not match the packet")]
    Family,
}

/// 解析过的数据包：记下各层的偏移，读写都在原缓冲区上进行。
#[derive(Debug)]
pub struct Packet<'a> {
    buf: &'a mut [u8],
    v6: bool,
    network: Network,
    /// 传输层头的偏移。
    l4: usize,
}

/// 解析 IP 数据包。
pub fn parse(buf: &mut [u8]) -> Result<Packet<'_>, PacketError> {
    let first = *buf.first().ok_or(PacketError::Truncated)?;
    let (v6, proto, l4) = match first >> 4 {
        4 => {
            let ihl = usize::from(first & 0x0f) * 4;
            if ihl < IPV4_MIN_HEADER || buf.len() < ihl {
                return Err(PacketError::Truncated);
            }
            // 标志 MF 或片偏移非零即分片
            let frag = u16::from_be_bytes([buf[6], buf[7]]);
            if frag & 0x3fff != 0 {
                return Err(PacketError::Fragment);
            }
            (false, buf[9], ihl)
        }
        6 => {
            if buf.len() < IPV6_HEADER {
                return Err(PacketError::Truncated);
            }
            match buf[6] {
                PROTO_TCP | PROTO_UDP => (true, buf[6], IPV6_HEADER),
                // 逐跳选项、路由、分片、目的选项、认证、ESP 等扩展头
                0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 => {
                    return Err(PacketError::Ipv6Extension);
                }
                other => return Err(PacketError::Protocol(other)),
            }
        }
        _ => return Err(PacketError::NotIp),
    };
    let network = match proto {
        PROTO_TCP => {
            if buf.len() < l4 + TCP_MIN_HEADER {
                return Err(PacketError::Truncated);
            }
            Network::Tcp
        }
        PROTO_UDP => {
            if buf.len() < l4 + UDP_HEADER {
                return Err(PacketError::Truncated);
            }
            Network::Udp
        }
        other => return Err(PacketError::Protocol(other)),
    };
    Ok(Packet {
        buf,
        v6,
        network,
        l4,
    })
}

impl Packet<'_> {
    pub fn network(&self) -> Network {
        self.network
    }

    pub fn is_ipv6(&self) -> bool {
        self.v6
    }

    fn ip_at(&self, off: usize) -> IpAddr {
        if self.v6 {
            let mut b = [0u8; 16];
            b.copy_from_slice(&self.buf[off..off + 16]);
            IpAddr::V6(Ipv6Addr::from(b))
        } else {
            let b = &self.buf[off..off + 4];
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
        }
    }

    fn put_ip(&mut self, off: usize, ip: IpAddr) -> Result<(), PacketError> {
        match (ip, self.v6) {
            (IpAddr::V4(v4), false) => self.buf[off..off + 4].copy_from_slice(&v4.octets()),
            (IpAddr::V6(v6), true) => self.buf[off..off + 16].copy_from_slice(&v6.octets()),
            _ => return Err(PacketError::Family),
        }
        Ok(())
    }

    fn src_ip_offset(&self) -> usize {
        if self.v6 { 8 } else { 12 }
    }

    fn dst_ip_offset(&self) -> usize {
        if self.v6 { 24 } else { 16 }
    }

    fn port_at(&self, off: usize) -> u16 {
        u16::from_be_bytes([self.buf[self.l4 + off], self.buf[self.l4 + off + 1]])
    }

    fn put_port(&mut self, off: usize, port: u16) {
        self.buf[self.l4 + off..self.l4 + off + 2].copy_from_slice(&port.to_be_bytes());
    }

    pub fn src(&self) -> SocketAddr {
        SocketAddr::new(self.ip_at(self.src_ip_offset()), self.port_at(0))
    }

    pub fn dst(&self) -> SocketAddr {
        SocketAddr::new(self.ip_at(self.dst_ip_offset()), self.port_at(2))
    }

    /// 改写源地址与端口。地址族必须与包一致。
    pub fn set_src(&mut self, addr: SocketAddr) -> Result<(), PacketError> {
        self.put_ip(self.src_ip_offset(), addr.ip())?;
        self.put_port(0, addr.port());
        Ok(())
    }

    /// 改写目的地址与端口。地址族必须与包一致。
    pub fn set_dst(&mut self, addr: SocketAddr) -> Result<(), PacketError> {
        self.put_ip(self.dst_ip_offset(), addr.ip())?;
        self.put_port(2, addr.port());
        Ok(())
    }

    /// TCP 标志位；UDP 包返回 0。
    pub fn tcp_flags(&self) -> u8 {
        match self.network {
            Network::Tcp => self.buf[self.l4 + 13],
            Network::Udp => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 拼一个最小的 IPv4 包：20 字节 IP 头 + 传输层头（+ 负载）。
    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], ports: (u16, u16), flags: u8) -> Vec<u8> {
        let l4_len = if proto == PROTO_TCP { 20 } else { 8 };
        let mut p = vec![0u8; 20 + l4_len + 4];
        p[0] = 0x45;
        let total = u16::try_from(p.len()).unwrap();
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[6] = 0x40; // DF
        p[8] = 128;
        p[9] = proto;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&ports.0.to_be_bytes());
        p[22..24].copy_from_slice(&ports.1.to_be_bytes());
        if proto == PROTO_TCP {
            p[32] = 5 << 4;
            p[33] = flags;
        }
        p
    }

    fn ipv6(next: u8, src: Ipv6Addr, dst: Ipv6Addr, ports: (u16, u16)) -> Vec<u8> {
        let mut p = vec![0u8; 40 + 20];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = next;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40..42].copy_from_slice(&ports.0.to_be_bytes());
        p[42..44].copy_from_slice(&ports.1.to_be_bytes());
        p
    }

    fn sock(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn reads_ipv4_tcp_addresses_and_flags() {
        let mut buf = ipv4(
            PROTO_TCP,
            [192, 168, 1, 5],
            [203, 0, 113, 24],
            (50001, 443),
            tcp_flags::SYN,
        );
        let p = parse(&mut buf).expect("parse");
        assert_eq!(p.network(), Network::Tcp);
        assert!(!p.is_ipv6());
        assert_eq!(p.src(), sock("192.168.1.5:50001"));
        assert_eq!(p.dst(), sock("203.0.113.24:443"));
        assert_eq!(p.tcp_flags(), tcp_flags::SYN);
    }

    #[test]
    fn rewrites_ipv4_in_place_and_keeps_the_rest() {
        let mut buf = ipv4(
            PROTO_TCP,
            [192, 168, 1, 5],
            [203, 0, 113, 24],
            (50001, 443),
            tcp_flags::SYN | tcp_flags::ACK,
        );
        let before = buf.clone();
        let mut p = parse(&mut buf).expect("parse");
        p.set_src(sock("127.0.0.1:50001")).expect("src");
        p.set_dst(sock("127.0.0.1:7000")).expect("dst");
        assert_eq!(p.src(), sock("127.0.0.1:50001"));
        assert_eq!(p.dst(), sock("127.0.0.1:7000"));
        assert_eq!(p.tcp_flags(), tcp_flags::SYN | tcp_flags::ACK);
        // 只有地址与端口变了
        let changed: Vec<usize> = (0..buf.len()).filter(|&i| buf[i] != before[i]).collect();
        assert!(
            changed
                .iter()
                .all(|&i| (12..20).contains(&i) || (20..24).contains(&i)),
            "{changed:?}"
        );
    }

    #[test]
    fn reads_and_rewrites_ipv4_udp() {
        let mut buf = ipv4(PROTO_UDP, [10, 0, 0, 2], [8, 8, 8, 8], (6000, 53), 0);
        let mut p = parse(&mut buf).expect("parse");
        assert_eq!(p.network(), Network::Udp);
        assert_eq!(p.tcp_flags(), 0);
        p.set_dst(sock("127.0.0.1:5353")).expect("dst");
        assert_eq!(p.dst(), sock("127.0.0.1:5353"));
        assert_eq!(p.src(), sock("10.0.0.2:6000"));
    }

    #[test]
    fn reads_and_rewrites_ipv6_tcp() {
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut buf = ipv6(PROTO_TCP, src, dst, (50001, 443));
        let mut p = parse(&mut buf).expect("parse");
        assert!(p.is_ipv6());
        assert_eq!(p.src(), sock("[2001:db8::5]:50001"));
        assert_eq!(p.dst(), sock("[2001:db8::1]:443"));
        p.set_src(sock("[::1]:50001")).expect("src");
        p.set_dst(sock("[::1]:7000")).expect("dst");
        assert_eq!(p.src(), sock("[::1]:50001"));
        assert_eq!(p.dst(), sock("[::1]:7000"));
    }

    #[test]
    fn refuses_to_mix_address_families() {
        let mut buf = ipv4(PROTO_TCP, [10, 0, 0, 2], [10, 0, 0, 3], (1, 2), 0);
        let mut p = parse(&mut buf).expect("parse");
        assert_eq!(p.set_dst(sock("[::1]:7000")), Err(PacketError::Family));
        // 失败时什么也没改
        assert_eq!(p.dst(), sock("10.0.0.3:2"));
    }

    #[test]
    fn rejects_what_it_cannot_handle() {
        // 分片：MF 置位，或片偏移非零
        let mut mf = ipv4(PROTO_UDP, [10, 0, 0, 2], [10, 0, 0, 3], (1, 2), 0);
        mf[6] = 0x20;
        assert_eq!(parse(&mut mf).unwrap_err(), PacketError::Fragment);
        let mut later = ipv4(PROTO_UDP, [10, 0, 0, 2], [10, 0, 0, 3], (1, 2), 0);
        later[7] = 0x10;
        assert_eq!(parse(&mut later).unwrap_err(), PacketError::Fragment);
        // IPv6 分片扩展头
        let v6 = Ipv6Addr::LOCALHOST;
        assert_eq!(
            parse(&mut ipv6(44, v6, v6, (1, 2))).unwrap_err(),
            PacketError::Ipv6Extension
        );
        // ICMP
        let mut icmp = ipv4(PROTO_UDP, [10, 0, 0, 2], [10, 0, 0, 3], (1, 2), 0);
        icmp[9] = 1;
        assert_eq!(parse(&mut icmp).unwrap_err(), PacketError::Protocol(1));
        // 截断与非 IP
        assert_eq!(parse(&mut []).unwrap_err(), PacketError::Truncated);
        let mut short = ipv4(PROTO_TCP, [10, 0, 0, 2], [10, 0, 0, 3], (1, 2), 0);
        short.truncate(30);
        assert_eq!(parse(&mut short).unwrap_err(), PacketError::Truncated);
        let mut bad_ihl = ipv4(PROTO_TCP, [10, 0, 0, 2], [10, 0, 0, 3], (1, 2), 0);
        bad_ihl[0] = 0x44;
        assert_eq!(parse(&mut bad_ihl).unwrap_err(), PacketError::Truncated);
        assert_eq!(parse(&mut [0x50u8; 40]).unwrap_err(), PacketError::NotIp);
    }

    #[test]
    fn honours_ipv4_options() {
        // IHL = 6：带 4 字节选项，传输层头往后挪
        let mut buf = ipv4(PROTO_TCP, [10, 0, 0, 2], [10, 0, 0, 3], (1111, 2222), 0);
        buf.splice(20..20, [1u8, 1, 1, 0]);
        buf[0] = 0x46;
        let p = parse(&mut buf).expect("parse");
        assert_eq!(p.src().port(), 1111);
        assert_eq!(p.dst().port(), 2222);
    }
}
