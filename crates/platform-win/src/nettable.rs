// SPDX-License-Identifier: GPL-3.0-or-later
//! 按连接查所属进程：IP Helper 的 `GetExtendedTcpTable` 与 `GetExtendedUdpTable`（T-076）。
//!
//! 精确模式的首包竞态兜底（C-NET-04）：新流的第一个包先于 SOCKET 层事件到达、暂存后仍没有归属时，
//! 在系统的连接表里反查 PID：TCP 按「本地端口 + 远端」，UDP 没有连接、按本地地址与端口。每次调用都拍一份
//! 完整的表，开销与连接数成正比，只用在这条慢路径上，不用在逐包处理里。
#![allow(unsafe_code)] // 调用 GetExtended*Table；unsafe 块都有 SAFETY 注释

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

// 下面按字节解析的偏移以这两个布局为准
const V4_ROW: usize = size_of::<MIB_TCPROW_OWNER_PID>();
const V6_ROW: usize = size_of::<MIB_TCP6ROW_OWNER_PID>();
const _: () = assert!(V4_ROW == 24);
const _: () = assert!(V6_ROW == 56);
const UDP4_ROW: usize = size_of::<MIB_UDPROW_OWNER_PID>();
const UDP6_ROW: usize = size_of::<MIB_UDP6ROW_OWNER_PID>();
const _: () = assert!(UDP4_ROW == 12);
const _: () = assert!(UDP6_ROW == 28);

/// 本地端口为 `local_port`、远端为 `remote` 的 TCP 连接所属的 PID；表里没有时返回 `None`。
///
/// 本地地址不参与比较（与 SOCKET 层登记表一致）。
pub fn tcp_owner_pid(local_port: u16, remote: SocketAddr) -> io::Result<Option<u32>> {
    let (family, row_len) = match remote.ip() {
        IpAddr::V4(_) => (AF_INET, V4_ROW),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            // IPv4 映射地址的连接在 IPv4 表里
            Some(_) => (AF_INET, V4_ROW),
            None => (AF_INET6, V6_ROW),
        },
    };
    let table = tcp_table(family)?;
    Ok(find_owner(&table, row_len, local_port, remote))
}

/// 本地地址与端口为 `local` 的 UDP 套接字所属的 PID；表里没有时返回 `None`。
///
/// 完全相同的本地地址优先，其次是绑定在通配地址上的套接字。IPv4 包也可能来自绑定在 `::` 上的双栈套接字，
/// 它只出现在 IPv6 表里。
pub fn udp_owner_pid(local: SocketAddr) -> io::Result<Option<u32>> {
    let ip = canonical(local.ip());
    if ip.is_ipv4()
        && let Some(pid) = find_udp_owner(&udp_table(AF_INET)?, UDP4_ROW, ip, local.port())
    {
        return Ok(Some(pid));
    }
    Ok(find_udp_owner(
        &udp_table(AF_INET6)?,
        UDP6_ROW,
        ip,
        local.port(),
    ))
}

/// 取一份 `TCP_TABLE_OWNER_PID_ALL` 的原始字节。
fn tcp_table(family: u32) -> io::Result<Vec<u8>> {
    fetch_table(|buf, len| {
        // SAFETY: `buf` 可写 `*len` 字节（`fetch_table` 保证）；表的类别与地址族决定写入的结构，调用方按同样的
        // 布局解析；不排序（bOrder = 0），保留参数为 0。
        unsafe { GetExtendedTcpTable(buf.cast(), len, 0, family, TCP_TABLE_OWNER_PID_ALL, 0) }
    })
}

/// 取一份 `UDP_TABLE_OWNER_PID` 的原始字节。
fn udp_table(family: u32) -> io::Result<Vec<u8>> {
    fetch_table(|buf, len| {
        // SAFETY: 同 `tcp_table`。
        unsafe { GetExtendedUdpTable(buf.cast(), len, 0, family, UDP_TABLE_OWNER_PID, 0) }
    })
}

/// 调用 `query` 取一份表的原始字节。表在两次调用之间可能变大，最多重试几次。
fn fetch_table(mut query: impl FnMut(*mut u32, &mut u32) -> u32) -> io::Result<Vec<u8>> {
    let mut size = 0u32;
    for _ in 0..4 {
        // 以 u32 为单位分配，保证表头与各行按 4 字节对齐
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 1];
        let mut len = u32::try_from(buf.len() * 4).unwrap_or(u32::MAX);
        let rc = query(buf.as_mut_ptr(), &mut len);
        match rc {
            NO_ERROR => {
                let bytes: Vec<u8> = buf.iter().flat_map(|w| w.to_ne_bytes()).collect();
                return Ok(bytes[..(len as usize).min(bytes.len())].to_vec());
            }
            ERROR_INSUFFICIENT_BUFFER => size = len.saturating_add(1024),
            other => return Err(io::Error::from_raw_os_error(other as i32)),
        }
    }
    Err(io::Error::other("the connection table kept growing"))
}

/// 在原始表里找连接。表头是 4 字节的条数，后面是定长的行。
fn find_owner(table: &[u8], row_len: usize, local_port: u16, remote: SocketAddr) -> Option<u32> {
    let count = u32::from_ne_bytes(table.get(..4)?.try_into().ok()?) as usize;
    let remote_ip = canonical(remote.ip());
    table
        .get(4..)?
        .chunks_exact(row_len)
        .take(count)
        .find_map(|row| {
            let (lport, rip, rport, pid) = if row_len == V4_ROW {
                // dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid
                (
                    port_at(row, 8),
                    IpAddr::V4(Ipv4Addr::new(row[12], row[13], row[14], row[15])),
                    port_at(row, 16),
                    u32_at(row, 20),
                )
            } else {
                // ucLocalAddr[16], dwLocalScopeId, dwLocalPort, ucRemoteAddr[16], dwRemoteScopeId,
                // dwRemotePort, dwState, dwOwningPid
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&row[24..40]);
                (
                    port_at(row, 20),
                    canonical(IpAddr::V6(Ipv6Addr::from(ip))),
                    port_at(row, 44),
                    u32_at(row, 52),
                )
            };
            (lport == local_port && rip == remote_ip && rport == remote.port()).then_some(pid)
        })
}

/// 在原始的 UDP 表里找套接字，见 [`udp_owner_pid`]。`ip` 已规范化。
fn find_udp_owner(table: &[u8], row_len: usize, ip: IpAddr, local_port: u16) -> Option<u32> {
    let count = u32::from_ne_bytes(table.get(..4)?.try_into().ok()?) as usize;
    let mut wildcard = None;
    for row in table.get(4..)?.chunks_exact(row_len).take(count) {
        let (addr, port, pid) = if row_len == UDP4_ROW {
            // dwLocalAddr, dwLocalPort, dwOwningPid
            (
                IpAddr::V4(Ipv4Addr::new(row[0], row[1], row[2], row[3])),
                port_at(row, 4),
                u32_at(row, 8),
            )
        } else {
            // ucLocalAddr[16], dwLocalScopeId, dwLocalPort, dwOwningPid
            let mut b = [0u8; 16];
            b.copy_from_slice(&row[..16]);
            (
                canonical(IpAddr::V6(Ipv6Addr::from(b))),
                port_at(row, 20),
                u32_at(row, 24),
            )
        };
        if port != local_port {
            continue;
        }
        if addr == ip {
            return Some(pid);
        }
        if addr.is_unspecified() && wildcard.is_none() {
            wildcard = Some(pid);
        }
    }
    wildcard
}

fn u32_at(row: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([row[off], row[off + 1], row[off + 2], row[off + 3]])
}

/// 端口存在 DWORD 的低 16 位里，网络字节序：内存里的前两个字节就是大端的端口号。
fn port_at(row: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([row[off], row[off + 1]])
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream, UdpSocket};

    use super::*;

    #[test]
    fn finds_the_owner_of_this_process_connections() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let server = listener.local_addr().expect("addr");
        let client = TcpStream::connect(server).expect("connect");
        let local = client.local_addr().expect("local");
        let me = std::process::id();
        assert_eq!(
            tcp_owner_pid(local.port(), server).expect("query"),
            Some(me)
        );
        // 反方向（服务端那一侧的连接）同样属于本进程
        let (accepted, peer) = listener.accept().expect("accept");
        assert_eq!(tcp_owner_pid(server.port(), peer).expect("query"), Some(me));
        drop(accepted);
        // 换一个远端端口就查不到
        let other = SocketAddr::new(server.ip(), server.port().wrapping_add(1));
        assert_eq!(tcp_owner_pid(local.port(), other).expect("query"), None);
    }

    #[test]
    fn finds_ipv6_connections() {
        let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
            // 没有 IPv6 回环的机器上没有可查的连接
            return;
        };
        let server = listener.local_addr().expect("addr");
        let client = TcpStream::connect(server).expect("connect");
        let local = client.local_addr().expect("local");
        assert_eq!(
            tcp_owner_pid(local.port(), server).expect("query"),
            Some(std::process::id())
        );
    }

    #[test]
    fn finds_the_owner_of_this_process_udp_sockets() {
        let me = std::process::id();
        // 绑定在通配地址：发包时的本地地址是网卡地址，表里记的是 0.0.0.0
        let any = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("bind");
        let port = any.local_addr().expect("addr").port();
        let nic = SocketAddr::from(([192, 0, 2, 5], port));
        assert_eq!(udp_owner_pid(nic).expect("query"), Some(me));
        // 绑定在具体地址：别的本地地址上同一端口不是它
        let lo = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind");
        let local = lo.local_addr().expect("addr");
        assert_eq!(udp_owner_pid(local).expect("query"), Some(me));
        let elsewhere = SocketAddr::from(([192, 0, 2, 5], local.port()));
        assert_eq!(udp_owner_pid(elsewhere).expect("query"), None);
        // 关闭之后查不到
        drop(any);
        assert_eq!(udp_owner_pid(nic).expect("query"), None);
    }

    #[test]
    fn finds_dual_stack_udp_sockets_from_ipv4_addresses() {
        let Ok(v6) = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)) else {
            return; // 没有 IPv6 的机器
        };
        let port = v6.local_addr().expect("addr").port();
        let me = Some(std::process::id());
        let v6_local: SocketAddr = format!("[2001:db8::5]:{port}").parse().expect("addr");
        assert_eq!(udp_owner_pid(v6_local).expect("query"), me);
        assert_eq!(
            udp_owner_pid(SocketAddr::from(([192, 0, 2, 5], port))).expect("query"),
            me
        );
    }

    #[test]
    fn parses_udp_rows_and_prefers_the_exact_address() {
        let mut t = vec![0u8; 4 + UDP4_ROW * 2];
        t[..4].copy_from_slice(&2u32.to_ne_bytes());
        // 第一行：0.0.0.0:6000，PID 100；第二行：192.0.2.5:6000，PID 200
        let wildcard = &mut t[4..4 + UDP4_ROW];
        wildcard[4..6].copy_from_slice(&6000u16.to_be_bytes());
        wildcard[8..12].copy_from_slice(&100u32.to_ne_bytes());
        let exact = &mut t[4 + UDP4_ROW..];
        exact[..4].copy_from_slice(&[192, 0, 2, 5]);
        exact[4..6].copy_from_slice(&6000u16.to_be_bytes());
        exact[8..12].copy_from_slice(&200u32.to_ne_bytes());
        let ip = |s: &str| s.parse::<IpAddr>().expect("ip");
        assert_eq!(
            find_udp_owner(&t, UDP4_ROW, ip("192.0.2.5"), 6000),
            Some(200)
        );
        assert_eq!(
            find_udp_owner(&t, UDP4_ROW, ip("192.0.2.9"), 6000),
            Some(100)
        );
        assert_eq!(find_udp_owner(&t, UDP4_ROW, ip("192.0.2.5"), 6001), None);
        assert_eq!(find_udp_owner(&[], UDP4_ROW, ip("192.0.2.5"), 6000), None);

        let mut t6 = vec![0u8; 4 + UDP6_ROW];
        t6[..4].copy_from_slice(&1u32.to_ne_bytes());
        let row = &mut t6[4..];
        row[..16].copy_from_slice(&ip_octets("2001:db8::5"));
        row[20..22].copy_from_slice(&6000u16.to_be_bytes());
        row[24..28].copy_from_slice(&300u32.to_ne_bytes());
        assert_eq!(
            find_udp_owner(&t6, UDP6_ROW, ip("2001:db8::5"), 6000),
            Some(300)
        );
    }

    fn ip_octets(s: &str) -> [u8; 16] {
        s.parse::<Ipv6Addr>().expect("ipv6").octets()
    }

    #[test]
    fn parses_rows_at_the_documented_offsets() {
        let mut t = vec![0u8; 4 + V4_ROW * 2];
        t[..4].copy_from_slice(&2u32.to_ne_bytes());
        // 第二行：本地端口 50001，远端 203.0.113.24:443，PID 4120
        let row = &mut t[4 + V4_ROW..];
        row[8..10].copy_from_slice(&50001u16.to_be_bytes());
        row[12..16].copy_from_slice(&[203, 0, 113, 24]);
        row[16..18].copy_from_slice(&443u16.to_be_bytes());
        row[20..24].copy_from_slice(&4120u32.to_ne_bytes());
        let remote: SocketAddr = "203.0.113.24:443".parse().expect("addr");
        assert_eq!(find_owner(&t, V4_ROW, 50001, remote), Some(4120));
        assert_eq!(find_owner(&t, V4_ROW, 50002, remote), None);
        // 条数之外的行不看
        t[..4].copy_from_slice(&1u32.to_ne_bytes());
        assert_eq!(find_owner(&t, V4_ROW, 50001, remote), None);
        assert_eq!(find_owner(&[], V4_ROW, 50001, remote), None);
    }
}
