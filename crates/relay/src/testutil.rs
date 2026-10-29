// SPDX-License-Identifier: GPL-3.0-or-later
//! 组件测试用的假 SOCKS5 服务器与回显目标（AGENTS 第 6 节）。

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

use crate::socks5::{MAX_UDP_HEADER, TargetAddr, decode_udp, encode_udp_header};

pub const PASSWORD: &str = "per-launch-random";

/// TCP 回显服务器；返回地址与已接受的连接数（用于证明没有直连）。
pub async fn spawn_tcp_echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (addr, hits)
}

/// UDP 回显服务器；回包前加上 `tag` 前缀，便于区分多个远端。
pub async fn spawn_udp_echo(tag: &'static [u8]) -> (SocketAddr, Arc<AtomicUsize>) {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = s.recv_from(&mut buf).await {
            h.fetch_add(1, Ordering::SeqCst);
            let mut out = tag.to_vec();
            out.extend_from_slice(&buf[..n]);
            let _ = s.send_to(&out, from).await;
        }
    });
    (addr, hits)
}

#[derive(Default)]
struct Log {
    usernames: Vec<String>,
    /// CONNECT 请求里的目标（IP 或域名）。
    connect_requests: Vec<TargetAddr>,
    /// 实际连接的地址（域名按测试给的表解析）。
    connect_targets: Vec<SocketAddr>,
    associates: usize,
    /// 域名 → 地址，代替真实的 DNS。
    domains: HashMap<String, SocketAddr>,
}

/// 假 SOCKS5 服务器：只接受用户名/密码认证（密码为 [`PASSWORD`]），支持 CONNECT（IPv4 或域名）与
/// UDP ASSOCIATE，并把真实请求转发到本机的回显目标。
pub struct FakeSocks {
    pub addr: SocketAddr,
    log: Arc<Mutex<Log>>,
}

impl FakeSocks {
    pub async fn spawn() -> Self {
        Self::spawn_resolving(HashMap::new()).await
    }

    /// CONNECT 到域名时按 `domains` 解析；表里没有的域名回「主机不可达」。
    pub async fn spawn_resolving(domains: HashMap<String, SocketAddr>) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        let log = Arc::new(Mutex::new(Log {
            domains,
            ..Log::default()
        }));
        let shared = Arc::clone(&log);
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(serve(s, Arc::clone(&shared)));
            }
        });
        Self { addr, log }
    }

    pub fn usernames(&self) -> Vec<String> {
        self.log.lock().unwrap().usernames.clone()
    }

    pub fn connect_targets(&self) -> Vec<SocketAddr> {
        self.log.lock().unwrap().connect_targets.clone()
    }

    pub fn connect_requests(&self) -> Vec<TargetAddr> {
        self.log.lock().unwrap().connect_requests.clone()
    }

    pub fn associates(&self) -> usize {
        self.log.lock().unwrap().associates
    }
}

async fn serve(mut s: TcpStream, log: Arc<Mutex<Log>>) {
    let mut greet = [0u8; 2];
    if s.read_exact(&mut greet).await.is_err() {
        return;
    }
    let mut methods = vec![0u8; usize::from(greet[1])];
    s.read_exact(&mut methods).await.unwrap();
    if !methods.contains(&2) {
        let _ = s.write_all(&[5, 0xff]).await;
        return;
    }
    s.write_all(&[5, 2]).await.unwrap();
    let mut v = [0u8; 2];
    s.read_exact(&mut v).await.unwrap();
    let mut user = vec![0u8; usize::from(v[1])];
    s.read_exact(&mut user).await.unwrap();
    let plen = s.read_u8().await.unwrap();
    let mut pass = vec![0u8; usize::from(plen)];
    s.read_exact(&mut pass).await.unwrap();
    if pass != PASSWORD.as_bytes() {
        let _ = s.write_all(&[1, 1]).await;
        return;
    }
    s.write_all(&[1, 0]).await.unwrap();
    log.lock()
        .unwrap()
        .usernames
        .push(String::from_utf8(user).unwrap());

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.unwrap();
    let request = match head[3] {
        1 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip).await.unwrap();
            TargetAddr::Ip(SocketAddr::from((ip, s.read_u16().await.unwrap())))
        }
        3 => {
            let len = s.read_u8().await.unwrap();
            let mut name = vec![0u8; usize::from(len)];
            s.read_exact(&mut name).await.unwrap();
            TargetAddr::Domain(
                String::from_utf8(name).unwrap(),
                s.read_u16().await.unwrap(),
            )
        }
        other => panic!("fake server does not handle address type {other}"),
    };
    let resolved = match &request {
        TargetAddr::Ip(a) => Some(*a),
        TargetAddr::Domain(name, _) => log.lock().unwrap().domains.get(name).copied(),
    };
    match head[1] {
        1 => {
            log.lock().unwrap().connect_requests.push(request);
            let Some(target) = resolved else {
                let _ = s.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            };
            log.lock().unwrap().connect_targets.push(target);
            let Ok(mut up) = TcpStream::connect(target).await else {
                let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                return;
            };
            s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
        }
        3 => {
            log.lock().unwrap().associates += 1;
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = udp.local_addr().unwrap();
            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
            reply.extend_from_slice(&relay.port().to_be_bytes());
            s.write_all(&reply).await.unwrap();
            let mut client: Option<SocketAddr> = None;
            let mut buf = [0u8; 4096];
            let mut out = [0u8; 4096 + MAX_UDP_HEADER];
            let mut ctl = [0u8; 1];
            loop {
                tokio::select! {
                    // 控制连接关闭即结束关联
                    r = s.read(&mut ctl) => if matches!(r, Ok(0) | Err(_)) { return },
                    r = udp.recv_from(&mut buf) => {
                        let Ok((n, from)) = r else { return };
                        if client.is_none_or(|c| c == from) {
                            client = Some(from);
                            let Ok((TargetAddr::Ip(dst), payload)) = decode_udp(&buf[..n]) else { continue };
                            let _ = udp.send_to(payload, dst).await;
                        } else if let Some(c) = client {
                            let h = encode_udp_header(&TargetAddr::Ip(from), &mut out).unwrap();
                            out[h..h + n].copy_from_slice(&buf[..n]);
                            let _ = udp.send_to(&out[..h + n], c).await;
                        }
                    }
                }
            }
        }
        _ => {
            let _ = s.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        }
    }
}
