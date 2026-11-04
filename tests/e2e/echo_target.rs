// SPDX-License-Identifier: GPL-3.0-or-later
//! 回显目标进程（T-080）：一启动就连接，把数据发给远端、核对回显，退出码表示是否全部成功。
//!
//! ```text
//! echo_target <tcp|udp> <远端 ip:端口> <轮数> <每轮字节数> <超时毫秒>
//! ```
//!
//! 连接紧跟在进程启动之后，正好落在「进程追踪还没报到、SOCKET 事件可能晚于第一个包」的窗口里（C-NET-04）。
//! 标准输出第一行是 `pid=<进程号>`，经启动器拉起时测试靠它认出这个进程；最后一行是结果。

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::process::ExitCode;
use std::time::Duration;

struct Options {
    remote: SocketAddr,
    rounds: u32,
    bytes: usize,
    timeout: Duration,
}

fn main() -> ExitCode {
    println!("pid={}", std::process::id());
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [proto, remote, rounds, bytes, timeout] => {
            parse(remote, rounds, bytes, timeout).and_then(|o| match proto.as_str() {
                "tcp" => echo_tcp(&o).map_err(|e| e.to_string()),
                "udp" => echo_udp(&o).map_err(|e| e.to_string()),
                other => Err(format!("unknown protocol {other}")),
            })
        }
        _ => Err("usage: echo_target <tcp|udp> <ip:port> <rounds> <bytes> <timeout-ms>".to_owned()),
    };
    match result {
        Ok(()) => {
            println!("ok");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn parse(remote: &str, rounds: &str, bytes: &str, timeout: &str) -> Result<Options, String> {
    Ok(Options {
        remote: remote.parse().map_err(|e| format!("remote: {e}"))?,
        rounds: rounds.parse().map_err(|e| format!("rounds: {e}"))?,
        bytes: bytes.parse().map_err(|e| format!("bytes: {e}"))?,
        timeout: Duration::from_millis(timeout.parse().map_err(|e| format!("timeout: {e}"))?),
    })
}

/// 每轮内容不同，串包或收到旧数据都能看出来。
fn payload(round: u32, bytes: usize) -> Vec<u8> {
    (0..bytes)
        .map(|i| (i as u32).wrapping_mul(31).wrapping_add(round) as u8)
        .collect()
}

fn echo_tcp(o: &Options) -> std::io::Result<()> {
    let mut s = TcpStream::connect_timeout(&o.remote, o.timeout)?;
    s.set_read_timeout(Some(o.timeout))?;
    s.set_write_timeout(Some(o.timeout))?;
    for round in 0..o.rounds {
        let sent = payload(round, o.bytes);
        s.write_all(&sent)?;
        let mut got = vec![0u8; o.bytes];
        s.read_exact(&mut got)?;
        check(round, &sent, &got)?;
    }
    Ok(())
}

fn echo_udp(o: &Options) -> std::io::Result<()> {
    let bind = match o.remote {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };
    let s = UdpSocket::bind(bind)?;
    s.set_read_timeout(Some(o.timeout))?;
    let mut buf = vec![0u8; 65_535];
    for round in 0..o.rounds {
        let sent = payload(round, o.bytes);
        s.send_to(&sent, o.remote)?;
        let (n, from) = s.recv_from(&mut buf)?;
        if from != o.remote {
            return Err(std::io::Error::other(format!(
                "reply came from {from}, expected {}",
                o.remote
            )));
        }
        check(round, &sent, &buf[..n])?;
    }
    Ok(())
}

fn check(round: u32, sent: &[u8], got: &[u8]) -> std::io::Result<()> {
    if sent == got {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "round {round}: echo differs ({} bytes sent, {} received)",
            sent.len(),
            got.len()
        )))
    }
}
