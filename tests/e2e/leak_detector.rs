// SPDX-License-Identifier: GPL-3.0-or-later
//! 泄漏检测器（T-080，C-TEST-02，设计文档第 12 节）：统计目标进程发往代理服务器以外的地址、真正离开本机的包。
//!
//! - **观察点**：NETWORK 层优先级最低的只嗅探句柄。WinDivert 按优先级从高到低把包交给各个句柄，拦截层
//!   （优先级 0）改写或丢弃之后还能走到这里的，才是真正发出去的。过滤器不限协议，也不排除其他驱动注入的包，
//!   分片与非 TCP / UDP 的包同样看得到。
//! - **归属**：SOCKET 层的 BIND、CONNECT、ACCEPT 事件给出（协议，本地端口）→ PID。事件可能晚于第一个包
//!   （C-NET-04），所以不在收包时判断，而是结束后按驱动打的时间戳统一配对（[`Ledger::report`]）；
//!   目标进程由用例在事后指定。没有端口的分片跟随同一数据报的第一片，没有端口的协议（ICMP 等）按对端地址配对。
//!   配不上的包归入 `owner: None`，不算进
//!   任何进程，用例要另外确认发往观察地址的包都有归属。拦截层放回一个包时，WFP 会为这次注入再报一个 PID 4
//!   （System）的 CONNECT，所以有用户进程的事件时不看 System 的，否则放回去的包都会算到 System 头上。
//! - **独立性**：不用产品的 `packet::parse`、`ExclusionSet` 和判定逻辑，否则产品的错误也会蒙住检测器。只共用
//!   `divert::ffi`（`unsafe` 只能出现在那里，C-CODE-01）。放行的地址只有回环、链路本地、组播、广播、
//!   未指定地址（C-NET-05）和用例给出的代理服务器地址。
//! - **不会空跑**：停止的句柄读出来的计数也是 0。`Detector::finish` 先从本测试进程发一个标记数据报，只有
//!   NETWORK 层看到了它、SOCKET 层把它归属到本进程，才交出报告；记录溢出或有解析不了的包同样报错。
//!   标记也是一道冲刷：队列先进先出，看到标记说明它之前的包都已经收到。
//!
//! 只记包头里的元数据，不留负载。

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

pub const TCP: u8 = 6;
pub const UDP: u8 = 17;

/// 记录的包数上限。经代理的流量走回环、不进记录，正常情况下只有非目标进程的少量直连包。
const MAX_PACKETS: usize = 1 << 20;
const MAX_SOCKETS: usize = 1 << 20;

/// 线上看到的一个包的元数据。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WirePacket {
    /// 驱动打的时间戳，与 SOCKET 事件同一个时钟。
    pub at: i64,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: u8,
    /// （源端口，目的端口）。非首片分片和没有端口的协议为 `None`。
    pub ports: Option<(u16, u16)>,
    /// 分片时的数据报标识（IPv4 的 16 位 Identification，IPv6 分片头的 32 位）。
    pub fragment: Option<u32>,
    pub len: u32,
}

/// 解析 IP 包头。不是 IPv4 / IPv6 或 IP 头不完整时返回 `None`。
pub fn parse_ip(at: i64, pkt: &[u8]) -> Option<WirePacket> {
    match pkt.first()? >> 4 {
        4 => parse_v4(at, pkt),
        6 => parse_v6(at, pkt),
        _ => None,
    }
}

fn be16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

fn ports_at(pkt: &[u8], protocol: u8, l4: usize) -> Option<(u16, u16)> {
    matches!(protocol, TCP | UDP).then_some(())?;
    Some((be16(pkt, l4)?, be16(pkt, l4 + 2)?))
}

fn parse_v4(at: i64, pkt: &[u8]) -> Option<WirePacket> {
    let ihl = usize::from(pkt.first()? & 0x0f) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return None;
    }
    let id = be16(pkt, 4)?;
    let flags_offset = be16(pkt, 6)?;
    let more_fragments = flags_offset & 0x2000 != 0;
    let offset = flags_offset & 0x1fff;
    let protocol = pkt[9];
    let addr = |o: usize| IpAddr::from([pkt[o], pkt[o + 1], pkt[o + 2], pkt[o + 3]]);
    Some(WirePacket {
        at,
        src: addr(12),
        dst: addr(16),
        protocol,
        ports: if offset == 0 {
            ports_at(pkt, protocol, ihl)
        } else {
            None
        },
        fragment: (more_fragments || offset != 0).then_some(u32::from(id)),
        len: pkt.len() as u32,
    })
}

fn parse_v6(at: i64, pkt: &[u8]) -> Option<WirePacket> {
    if pkt.len() < 40 {
        return None;
    }
    let addr = |o: usize| {
        let mut b = [0u8; 16];
        b.copy_from_slice(&pkt[o..o + 16]);
        IpAddr::from(b)
    };
    let mut next = pkt[6];
    let mut off = 40;
    let mut fragment = None;
    let mut first_fragment = true;
    // 沿扩展头走到传输层；截断时停在那里，这个包照样记录，只是没有端口
    while first_fragment {
        let (Some(&inner), Some(&ext_len)) = (pkt.get(off), pkt.get(off + 1)) else {
            break;
        };
        match next {
            // 逐跳选项、路由、目的选项、移动、HIP、Shim6：长度以 8 字节为单位，不含前 8 字节
            0 | 43 | 60 | 135 | 139 | 140 => off += (usize::from(ext_len) + 1) * 8,
            // 认证头：长度以 4 字节为单位，不含前 8 字节
            51 => off += (usize::from(ext_len) + 2) * 4,
            44 => {
                let (Some(offset), Some(id)) = (be16(pkt, off + 2), pkt.get(off + 4..off + 8))
                else {
                    break;
                };
                fragment = Some(u32::from_be_bytes([id[0], id[1], id[2], id[3]]));
                first_fragment = offset >> 3 == 0;
                off += 8;
            }
            _ => break,
        }
        next = inner;
    }
    Some(WirePacket {
        at,
        src: addr(8),
        dst: addr(24),
        protocol: next,
        ports: if first_fragment {
            ports_at(pkt, next, off)
        } else {
            None
        },
        fragment,
        len: pkt.len() as u32,
    })
}

/// 回环、链路本地、组播、广播与未指定地址：不离开本链路，也不该进代理（C-NET-05）。
pub fn is_local_scope(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            a == 127
                || (a == 169 && b == 254)
                || (224..=239).contains(&a)
                || a == 0
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_local_scope(IpAddr::V4(v4));
            }
            let first = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || first & 0xffc0 == 0xfe80
                || first >> 8 == 0xff
        }
    }
}

/// SOCKET 层的一个事件：哪个进程占用了（协议，本地端口）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketRecord {
    pub at: i64,
    pub pid: u32,
    pub protocol: u8,
    pub local_port: u16,
    /// 对端。BIND 事件没有对端，为未指定地址和端口 0。
    pub remote: IpAddr,
    pub remote_port: u16,
}

/// 同一归属、同一方向的包的合计。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    /// 发送进程；配不上任何 SOCKET 事件时为 `None`。
    pub owner: Option<u32>,
    pub protocol: u8,
    pub local_port: Option<u16>,
    pub remote: IpAddr,
    pub remote_port: Option<u16>,
    pub packets: u64,
    pub bytes: u64,
    /// 其中分片的个数。
    pub fragments: u64,
}

/// 一次观察的结果。
#[derive(Debug, Clone, Default)]
pub struct Report {
    pub flows: Vec<Flow>,
    /// 因为目的地址被放行而没有记录的包数。
    pub allowed: u64,
}

impl Report {
    /// 这些进程发往被放行地址以外的流。
    pub fn leaks(&self, targets: &[u32]) -> Vec<Flow> {
        self.flows
            .iter()
            .filter(|f| f.owner.is_some_and(|o| targets.contains(&o)))
            .copied()
            .collect()
    }

    /// 泄漏计数：这些进程发往被放行地址以外的包数。
    pub fn leaked_packets(&self, targets: &[u32]) -> u64 {
        self.leaks(targets).iter().map(|f| f.packets).sum()
    }

    /// 发往某个地址的全部流，不管是谁发的。
    pub fn flows_to(&self, remote: IpAddr) -> Vec<Flow> {
        self.flows
            .iter()
            .filter(|f| f.remote == remote)
            .copied()
            .collect()
    }
}

/// 收集到的原始记录。收的时候只追加，结束后统一配对。
#[derive(Debug, Default)]
pub struct Ledger {
    proxies: Vec<IpAddr>,
    packets: Vec<WirePacket>,
    sockets: Vec<SocketRecord>,
    allowed: u64,
    overflow: u64,
    unparsed: u64,
}

impl Ledger {
    /// `proxies`：代理服务器地址，发往它们的不算泄漏。
    pub fn new(proxies: &[IpAddr]) -> Self {
        Self {
            proxies: proxies.to_vec(),
            ..Self::default()
        }
    }

    /// 记一个收到的包。
    pub fn add_packet(&mut self, at: i64, pkt: &[u8]) {
        let Some(p) = parse_ip(at, pkt) else {
            self.unparsed += 1;
            return;
        };
        if is_local_scope(p.dst) || self.proxies.contains(&p.dst) {
            self.allowed += 1;
        } else if self.packets.len() < MAX_PACKETS {
            self.packets.push(p);
        } else {
            self.overflow += 1;
        }
    }

    pub fn add_socket(&mut self, record: SocketRecord) {
        if self.sockets.len() < MAX_SOCKETS {
            self.sockets.push(record);
        } else {
            self.overflow += 1;
        }
    }

    /// 是否已经看到发往这里的包。
    pub fn saw_packet_to(&self, remote: IpAddr) -> bool {
        self.packets.iter().any(|p| p.dst == remote)
    }

    /// 配对并合计。记录不完整（溢出、有解析不了的包）时报错：那样的计数可能偏小，不能当作判据。
    pub fn report(&self) -> Result<Report, String> {
        if self.overflow != 0 {
            return Err(format!("{} records did not fit", self.overflow));
        }
        if self.unparsed != 0 {
            return Err(format!("{} packets could not be parsed", self.unparsed));
        }
        let mut sorted: Vec<SocketRecord> = self.sockets.clone();
        sorted.sort_by_key(|s| s.at);
        let mut by_port: HashMap<(u8, u16), Vec<SocketRecord>> = HashMap::new();
        let mut by_remote: HashMap<(u8, IpAddr), Vec<SocketRecord>> = HashMap::new();
        for s in sorted {
            by_port
                .entry((s.protocol, s.local_port))
                .or_default()
                .push(s);
            by_remote.entry((s.protocol, s.remote)).or_default().push(s);
        }

        // 先走一遍首片：后面的分片可能先于首片发出（发送顺序由协议栈决定）
        let mut first_fragments = HashMap::new();
        for p in &self.packets {
            if let (Some(id), Some(ports)) = (p.fragment, p.ports) {
                first_fragments.insert(
                    (p.src, p.dst, p.protocol, id),
                    (owner_of(&by_port, p, ports), ports),
                );
            }
        }

        type Key = (Option<u32>, u8, Option<u16>, IpAddr, Option<u16>);
        let mut flows: BTreeMap<Key, Flow> = BTreeMap::new();
        for p in &self.packets {
            let (owner, ports) = match (p.ports, p.fragment) {
                (Some(ports), _) => (owner_of(&by_port, p, ports), Some(ports)),
                (None, Some(id)) => first_fragments
                    .get(&(p.src, p.dst, p.protocol, id))
                    .map_or((None, None), |&(owner, ports)| (owner, Some(ports))),
                (None, None) => (owner_without_ports(&by_remote, p), None),
            };
            let (local_port, remote_port) = ports.unzip();
            let flow = flows
                .entry((owner, p.protocol, local_port, p.dst, remote_port))
                .or_insert(Flow {
                    owner,
                    protocol: p.protocol,
                    local_port,
                    remote: p.dst,
                    remote_port,
                    packets: 0,
                    bytes: 0,
                    fragments: 0,
                });
            flow.packets += 1;
            flow.bytes += u64::from(p.len);
            flow.fragments += u64::from(p.fragment.is_some());
        }
        Ok(Report {
            flows: flows.into_values().collect(),
            allowed: self.allowed,
        })
    }
}

/// Idle（0）与 System（4）：不是用户进程，见模块文档。
fn is_user_process(pid: u32) -> bool {
    pid > 4
}

/// 包的发送进程：优先看对端也相同的事件，其次只看本地端口（未连接的 UDP 套接字可能只有 BIND）；
/// 都先看用户进程的事件，没有才算 System 自己的连接。
fn owner_of(
    by_port: &HashMap<(u8, u16), Vec<SocketRecord>>,
    p: &WirePacket,
    (local_port, remote_port): (u16, u16),
) -> Option<u32> {
    let candidates = by_port.get(&(p.protocol, local_port))?;
    let same_remote = || {
        candidates
            .iter()
            .filter(|s| s.remote == p.dst && s.remote_port == remote_port)
    };
    let user = |s: &&SocketRecord| is_user_process(s.pid);
    nearest(same_remote().filter(user), p.at)
        .or_else(|| nearest(candidates.iter().filter(user), p.at))
        .or_else(|| nearest(same_remote(), p.at))
        .or_else(|| nearest(candidates.iter(), p.at))
        .map(|s| s.pid)
}

/// 没有端口的协议（ICMP 等）：只能看协议与对端地址。系统 ping 接口发的包事件里是 System，原始套接字发的是进程
/// 自己，所以这里不优先用户进程，只按时间配对。拦截层不处理这些协议，也就没有放回时的 System 回声。
fn owner_without_ports(
    by_remote: &HashMap<(u8, IpAddr), Vec<SocketRecord>>,
    p: &WirePacket,
) -> Option<u32> {
    let candidates = by_remote.get(&(p.protocol, p.dst))?;
    nearest(candidates.iter(), p.at).map(|s| s.pid)
}

/// 按时间排好序的事件里，不晚于这个包的最后一个；都晚于它（首包竞态）时取最早的一个。
fn nearest<'a>(
    events: impl Iterator<Item = &'a SocketRecord>,
    at: i64,
) -> Option<&'a SocketRecord> {
    let mut before = None;
    let mut after = None;
    for s in events {
        if s.at <= at {
            before = Some(s);
        } else if after.is_none() {
            after = Some(s);
        }
    }
    before.or(after)
}

#[cfg(windows)]
pub use capture::Detector;

#[cfg(windows)]
mod capture {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use procroute_intercept::divert::ffi::{
        Address, Handle, Layer, MTU_MAX, Param, Shutdown, WinDivert, event, flags,
    };

    use super::{Ledger, Report, SocketRecord};

    /// `WINDIVERT_PRIORITY_LOWEST`：排在拦截层（优先级 0）之后。
    const LOWEST_PRIORITY: i16 = -30_000;
    const NETWORK_FILTER: &str = "outbound and !loopback";
    const SOCKET_FILTER: &str =
        "(event == BIND or event == CONNECT or event == ACCEPT) and !loopback";

    // 队列都取上限（`WINDIVERT_PARAM_*_MAX`）：只嗅探的句柄来不及收就会丢包，计数会偏小
    const QUEUE_LENGTH: u64 = 16_384;
    const QUEUE_TIME_MS: u64 = 16_000;
    const QUEUE_SIZE: u64 = 32 * 1024 * 1024;

    /// 标记数据报的去向（TEST-NET-3，RFC 5737）。用例不要用这个地址。
    const MARKER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 99);
    const MARKER_PORT: u16 = 9;
    const MARKER_TIMEOUT: Duration = Duration::from_secs(5);
    const MARKER_INTERVAL: Duration = Duration::from_millis(100);
    /// 看到标记之后再等一会儿，让走另一个队列的 SOCKET 事件到齐。
    const DRAIN: Duration = Duration::from_millis(300);

    type Receive = fn(&Handle, &Mutex<Ledger>) -> std::io::Result<()>;

    /// 运行中的检测器。见模块文档。
    pub struct Detector {
        network: Arc<Handle>,
        socket: Arc<Handle>,
        ledger: Arc<Mutex<Ledger>>,
        stopping: Arc<AtomicBool>,
        failure: Arc<Mutex<Option<String>>>,
        threads: Vec<JoinHandle<()>>,
    }

    impl std::fmt::Debug for Detector {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Detector").finish_non_exhaustive()
        }
    }

    impl Detector {
        /// 开始观察。`windivert_dir` 是放着锁定版本 WinDivert 的目录；`proxies` 见 [`Ledger::new`]。
        pub fn start(windivert_dir: &Path, proxies: &[IpAddr]) -> Result<Self, String> {
            let api = WinDivert::load(windivert_dir).map_err(|e| e.to_string())?;
            let open = |filter: &str, layer: Layer| {
                api.open(
                    filter,
                    layer,
                    LOWEST_PRIORITY,
                    flags::SNIFF | flags::RECV_ONLY,
                )
                .map(Arc::new)
                .map_err(|e| format!("open the {layer:?} layer: {e}"))
            };
            let socket = open(SOCKET_FILTER, Layer::Socket)?;
            let network = open(NETWORK_FILTER, Layer::Network)?;
            for (param, value) in [
                (Param::QueueLength, QUEUE_LENGTH),
                (Param::QueueTime, QUEUE_TIME_MS),
                (Param::QueueSize, QUEUE_SIZE),
            ] {
                network
                    .set_param(param, value)
                    .map_err(|e| format!("set {param:?}: {e}"))?;
            }
            socket
                .set_param(Param::QueueLength, QUEUE_LENGTH)
                .map_err(|e| format!("set the socket queue: {e}"))?;

            let ledger = Arc::new(Mutex::new(Ledger::new(proxies)));
            let stopping = Arc::new(AtomicBool::new(false));
            let failure = Arc::new(Mutex::new(None));
            let spawn = |name: &str, handle: &Arc<Handle>, receive: Receive| {
                let (handle, ledger, stopping, failure) = (
                    Arc::clone(handle),
                    Arc::clone(&ledger),
                    Arc::clone(&stopping),
                    Arc::clone(&failure),
                );
                std::thread::Builder::new()
                    .name(format!("leak-detector-{name}"))
                    .spawn(move || {
                        if let Err(e) = receive(&handle, &ledger)
                            && !stopping.load(Ordering::Acquire)
                        {
                            *failure.lock().unwrap_or_else(PoisonError::into_inner) =
                                Some(e.to_string());
                        }
                    })
                    .map_err(|e| format!("spawn a capture thread: {e}"))
            };
            let threads = vec![
                spawn("network", &network, receive_packets)?,
                spawn("socket", &socket, receive_sockets)?,
            ];
            Ok(Self {
                network,
                socket,
                ledger,
                stopping,
                failure,
                threads,
            })
        }

        /// 确认检测器一直在工作，然后停止并交出报告。见模块文档的「不会空跑」。
        pub fn finish(mut self) -> Result<Report, String> {
            let marker = self.send_marker();
            std::thread::sleep(DRAIN);
            self.stop();
            if let Some(e) = self
                .failure
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return Err(format!("capture stopped early: {e}"));
            }
            marker?;
            let report = self
                .ledger
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .report()?;
            let me = std::process::id();
            let flows = report.flows_to(MARKER_IP.into());
            if !flows.iter().any(|f| f.owner == Some(me)) {
                return Err(format!(
                    "the SOCKET layer did not attribute the marker to this process ({me}): {flows:?}"
                ));
            }
            Ok(report)
        }

        fn send_marker(&self) -> Result<(), String> {
            let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
                .map_err(|e| format!("bind the marker socket: {e}"))?;
            let to = SocketAddr::from((MARKER_IP, MARKER_PORT));
            let deadline = Instant::now() + MARKER_TIMEOUT;
            loop {
                socket
                    .send_to(b"procroute leak detector marker", to)
                    .map_err(|e| format!("send the marker: {e}"))?;
                std::thread::sleep(MARKER_INTERVAL);
                let seen = self
                    .ledger
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .saw_packet_to(MARKER_IP.into());
                if seen {
                    return Ok(());
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "the NETWORK layer never saw the marker within {MARKER_TIMEOUT:?}"
                    ));
                }
            }
        }

        fn stop(&mut self) {
            self.stopping.store(true, Ordering::Release);
            // 让阻塞在 recv 上的线程返回；失败说明句柄已不可用，线程也会因 recv 出错而退出
            let _ = self.network.shutdown(Shutdown::Recv);
            let _ = self.socket.shutdown(Shutdown::Recv);
            for t in self.threads.drain(..) {
                let _ = t.join();
            }
        }
    }

    impl Drop for Detector {
        fn drop(&mut self) {
            self.stop();
        }
    }

    fn receive_packets(handle: &Handle, ledger: &Mutex<Ledger>) -> std::io::Result<()> {
        let mut buf = vec![0u8; MTU_MAX];
        let mut addr = Address::default();
        loop {
            let n = handle.recv(&mut buf, &mut addr)?;
            ledger
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .add_packet(addr.timestamp, &buf[..n]);
        }
    }

    fn receive_sockets(handle: &Handle, ledger: &Mutex<Ledger>) -> std::io::Result<()> {
        let mut addr = Address::default();
        loop {
            handle.recv_event(&mut addr)?;
            if !matches!(
                addr.event(),
                event::SOCKET_BIND | event::SOCKET_CONNECT | event::SOCKET_ACCEPT
            ) {
                continue;
            }
            let e = addr.endpoint();
            ledger
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .add_socket(SocketRecord {
                    at: addr.timestamp,
                    pid: e.process_id,
                    protocol: e.protocol,
                    local_port: e.local_port,
                    remote: e.remote_addr,
                    remote_port: e.remote_port,
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    const APP: [u8; 4] = [10, 0, 0, 5];
    const REMOTE: [u8; 4] = [192, 0, 2, 1];
    const PROXY: [u8; 4] = [198, 51, 100, 7];
    const REMOTE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    const PORT: u16 = 50_000;

    /// IPv4 包：`flags_offset` 是标志与片偏移那 16 位，`l4` 紧跟在 IP 头后面。
    fn v4(dst: [u8; 4], protocol: u8, id: u16, flags_offset: u16, l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[4..6].copy_from_slice(&id.to_be_bytes());
        p[6..8].copy_from_slice(&flags_offset.to_be_bytes());
        p[9] = protocol;
        p[12..16].copy_from_slice(&APP);
        p[16..20].copy_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    fn ports(src: u16, dst: u16) -> Vec<u8> {
        let mut b = src.to_be_bytes().to_vec();
        b.extend_from_slice(&dst.to_be_bytes());
        b.extend_from_slice(&[0; 16]);
        b
    }

    fn v6(next: u8, ext_and_l4: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = next;
        p[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        p[24..40].copy_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().expect("v6").octets());
        p.extend_from_slice(ext_and_l4);
        p
    }

    fn socket(at: i64, pid: u32, port: u16) -> SocketRecord {
        SocketRecord {
            at,
            pid,
            protocol: TCP,
            local_port: port,
            remote: REMOTE_IP,
            remote_port: 80,
        }
    }

    fn ledger() -> Ledger {
        Ledger::new(&[IpAddr::from(PROXY)])
    }

    #[test]
    fn ipv4_tcp_and_udp_expose_their_ports() {
        let p = parse_ip(7, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80))).expect("parse");
        assert_eq!(p.at, 7);
        assert_eq!(p.src, IpAddr::from(APP));
        assert_eq!(p.dst, REMOTE_IP);
        assert_eq!(p.protocol, TCP);
        assert_eq!(p.ports, Some((PORT, 80)));
        assert_eq!(p.fragment, None);
        let u = parse_ip(0, &v4(REMOTE, UDP, 1, 0, &ports(PORT, 53))).expect("parse");
        assert_eq!(u.ports, Some((PORT, 53)));
    }

    #[test]
    fn ipv4_df_is_not_a_fragment_but_mf_and_offsets_are() {
        let df = parse_ip(0, &v4(REMOTE, UDP, 9, 0x4000, &ports(PORT, 53))).expect("parse");
        assert_eq!(df.fragment, None);
        let first = parse_ip(0, &v4(REMOTE, UDP, 9, 0x2000, &ports(PORT, 53))).expect("parse");
        assert_eq!(first.fragment, Some(9));
        assert_eq!(first.ports, Some((PORT, 53)));
        let last = parse_ip(0, &v4(REMOTE, UDP, 9, 185, &[0xaa; 8])).expect("parse");
        assert_eq!(last.fragment, Some(9));
        assert_eq!(last.ports, None, "payload bytes must not be read as ports");
    }

    #[test]
    fn protocols_without_ports_and_short_transport_headers_have_no_ports() {
        let icmp = parse_ip(0, &v4(REMOTE, 1, 1, 0, &[8, 0, 0, 0])).expect("parse");
        assert_eq!((icmp.protocol, icmp.ports), (1, None));
        let short = parse_ip(0, &v4(REMOTE, TCP, 1, 0, &[0, 80])).expect("parse");
        assert_eq!(short.ports, None);
    }

    #[test]
    fn malformed_ip_headers_are_rejected() {
        assert_eq!(parse_ip(0, &[]), None);
        assert_eq!(parse_ip(0, &[0x15; 40]), None, "version 1");
        assert_eq!(parse_ip(0, &[0x45; 10]), None, "short IPv4");
        assert_eq!(parse_ip(0, &[0x41; 40]), None, "IHL below 20 bytes");
        assert_eq!(parse_ip(0, &[0x60; 20]), None, "short IPv6");
    }

    #[test]
    fn ipv6_walks_extension_headers_to_the_ports() {
        let plain = parse_ip(0, &v6(UDP, &ports(PORT, 53))).expect("parse");
        assert_eq!((plain.protocol, plain.ports), (UDP, Some((PORT, 53))));

        // 逐跳选项（8 字节）→ UDP
        let mut ext = vec![UDP, 0, 0, 0, 0, 0, 0, 0];
        ext.extend(ports(PORT, 53));
        let hop = parse_ip(0, &v6(0, &ext)).expect("parse");
        assert_eq!((hop.protocol, hop.ports), (UDP, Some((PORT, 53))));

        // 认证头（长度字段 1 → 12 字节）→ TCP
        let mut ah = vec![TCP, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        ah.extend(ports(PORT, 443));
        let auth = parse_ip(0, &v6(51, &ah)).expect("parse");
        assert_eq!((auth.protocol, auth.ports), (TCP, Some((PORT, 443))));
    }

    #[test]
    fn ipv6_fragments_carry_their_id_and_only_the_first_has_ports() {
        let fragment = |offset: u16, more: bool, l4: &[u8]| {
            let mut ext = vec![UDP, 0];
            ext.extend_from_slice(&((offset << 3) | u16::from(more)).to_be_bytes());
            ext.extend_from_slice(&0xdead_beef_u32.to_be_bytes());
            ext.extend_from_slice(l4);
            v6(44, &ext)
        };
        let first = parse_ip(0, &fragment(0, true, &ports(PORT, 53))).expect("parse");
        assert_eq!(first.fragment, Some(0xdead_beef));
        assert_eq!((first.protocol, first.ports), (UDP, Some((PORT, 53))));
        let rest = parse_ip(0, &fragment(185, false, &[0xaa; 24])).expect("parse");
        assert_eq!(rest.fragment, Some(0xdead_beef));
        assert_eq!((rest.protocol, rest.ports), (UDP, None));
    }

    #[test]
    fn truncated_ipv6_extension_chains_are_kept_without_ports() {
        let p = parse_ip(0, &v6(0, &[UDP])).expect("parse");
        assert_eq!(p.ports, None);
        // 分片头被截断：记录下来，没有端口，也不当成分片
        let f = parse_ip(0, &v6(44, &[UDP, 0, 0, 0])).expect("parse");
        assert_eq!((f.ports, f.fragment), (None, None));
    }

    #[test]
    fn local_scope_addresses_are_allowed_and_public_ones_are_not() {
        for ip in [
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "239.255.255.250",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "::",
            "fe80::1",
            "ff02::fb",
            "::ffff:127.0.0.1",
        ] {
            assert!(is_local_scope(ip.parse().expect("ip")), "{ip}");
        }
        for ip in [
            "192.0.2.1",
            "10.0.0.1",
            "8.8.8.8",
            "240.0.0.1",
            "2001:db8::1",
            "fec0::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!is_local_scope(ip.parse().expect("ip")), "{ip}");
        }
    }

    #[test]
    fn a_target_packet_to_a_public_address_is_a_leak() {
        let mut l = ledger();
        l.add_socket(socket(10, 100, PORT));
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 1);
        let leak = r.leaks(&[100])[0];
        assert_eq!(leak.owner, Some(100));
        assert_eq!(leak.remote, REMOTE_IP);
        assert_eq!(leak.remote_port, Some(80));
        assert_eq!(leak.local_port, Some(PORT));
        assert_eq!(leak.bytes, 40);
    }

    #[test]
    fn other_processes_are_seen_but_not_counted_for_the_target() {
        let mut l = ledger();
        l.add_socket(socket(10, 200, PORT));
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 0);
        assert_eq!(r.flows_to(REMOTE_IP).len(), 1, "still visible");
        assert_eq!(r.leaked_packets(&[200]), 1);
    }

    #[test]
    fn proxy_and_local_destinations_are_not_leaks() {
        let mut l = ledger();
        l.add_socket(socket(10, 100, PORT));
        l.add_packet(20, &v4(PROXY, TCP, 1, 0, &ports(PORT, 443)));
        l.add_packet(21, &v4([127, 0, 0, 1], TCP, 2, 0, &ports(PORT, 9000)));
        l.add_packet(22, &v4([224, 0, 0, 251], UDP, 3, 0, &ports(PORT, 5353)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 0);
        assert_eq!(r.allowed, 3);
        assert!(r.flows.is_empty());
    }

    #[test]
    fn a_packet_before_its_socket_event_still_counts() {
        // 首包竞态（C-NET-04）：第一个 SYN 的时间戳早于 CONNECT 事件
        let mut l = ledger();
        l.add_packet(10, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        l.add_socket(socket(20, 100, PORT));
        assert_eq!(l.report().expect("report").leaked_packets(&[100]), 1);
    }

    #[test]
    fn a_reused_port_belongs_to_whoever_held_it_at_the_time() {
        let mut l = ledger();
        l.add_socket(socket(10, 200, PORT));
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        l.add_socket(socket(30, 100, PORT));
        l.add_packet(40, &v4(REMOTE, TCP, 2, 0, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[200]), 1);
        assert_eq!(r.leaked_packets(&[100]), 1);
    }

    #[test]
    fn an_event_with_the_same_remote_wins_over_an_older_one_on_the_port() {
        // 非目标先占用过这个端口；目标的 CONNECT 事件晚于它的第一个包，只看时间会误判给非目标
        let mut l = ledger();
        let mut earlier = socket(10, 200, PORT);
        earlier.remote = "192.0.2.77".parse().expect("ip");
        l.add_socket(earlier);
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        l.add_socket(socket(30, 100, PORT));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 1);
        assert_eq!(r.leaked_packets(&[200]), 0);
    }

    #[test]
    fn the_system_event_of_a_reinjected_packet_does_not_take_over_the_flow() {
        // 拦截层放回目标进程的包：WFP 再报一个 PID 4 的 CONNECT，时间上更接近这个包
        let mut l = ledger();
        l.add_socket(socket(10, 100, PORT));
        l.add_socket(socket(15, 4, PORT));
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 1);
        assert_eq!(r.leaked_packets(&[4]), 0);
    }

    #[test]
    fn system_connections_without_a_user_process_stay_with_system() {
        let mut l = ledger();
        l.add_socket(socket(10, 4, PORT));
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        assert_eq!(l.report().expect("report").leaked_packets(&[4]), 1);
    }

    #[test]
    fn a_udp_socket_with_only_a_bind_event_is_attributed_by_its_port() {
        let mut l = ledger();
        l.add_socket(SocketRecord {
            at: 10,
            pid: 100,
            protocol: UDP,
            local_port: PORT,
            remote: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            remote_port: 0,
        });
        l.add_packet(20, &v4(REMOTE, UDP, 1, 0, &ports(PORT, 5353)));
        assert_eq!(l.report().expect("report").leaked_packets(&[100]), 1);
    }

    #[test]
    fn the_same_port_on_another_protocol_is_someone_else() {
        let mut l = ledger();
        l.add_socket(socket(10, 200, PORT)); // TCP
        l.add_packet(20, &v4(REMOTE, UDP, 1, 0, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[200]), 0);
        assert_eq!(r.flows[0].owner, None);
    }

    #[test]
    fn fragments_follow_the_first_fragment_of_their_datagram() {
        let mut l = ledger();
        l.add_socket(SocketRecord {
            protocol: UDP,
            ..socket(10, 100, PORT)
        });
        // 协议栈可能先发后面的分片
        l.add_packet(20, &v4(REMOTE, UDP, 9, 185, &[0xaa; 100]));
        l.add_packet(21, &v4(REMOTE, UDP, 9, 0x2000, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 2);
        let flow = r.leaks(&[100])[0];
        assert_eq!(flow.fragments, 2);
        assert_eq!(flow.local_port, Some(PORT));
        assert_eq!(r.flows.len(), 1);
    }

    #[test]
    fn fragments_without_a_first_fragment_stay_unattributed_and_visible() {
        let mut l = ledger();
        l.add_socket(SocketRecord {
            protocol: UDP,
            ..socket(10, 100, PORT)
        });
        l.add_packet(20, &v4(REMOTE, UDP, 9, 185, &[0xaa; 100]));
        // 同一地址的另一个数据报，不能把它认成这一片的首片
        l.add_packet(21, &v4(REMOTE, UDP, 10, 0x2000, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 1);
        let orphan: Vec<Flow> = r
            .flows_to(REMOTE_IP)
            .into_iter()
            .filter(|f| f.owner.is_none())
            .collect();
        assert_eq!(orphan.len(), 1, "{r:?}");
        assert_eq!(orphan[0].fragments, 1);
    }

    #[test]
    fn packets_with_no_matching_socket_are_unattributed_not_dropped() {
        let mut l = ledger();
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        l.add_packet(21, &v4(REMOTE, 1, 2, 0, &[8, 0, 0, 0]));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 0);
        assert_eq!(r.flows.len(), 2);
        assert!(r.flows.iter().all(|f| f.owner.is_none()));
    }

    #[test]
    fn protocols_without_ports_are_attributed_by_their_remote() {
        const ICMP: u8 = 1;
        let echo = |dst: [u8; 4]| v4(dst, ICMP, 1, 0, &[8, 0, 0, 0]);
        let icmp_socket = |at: i64, pid: u32, remote: IpAddr| SocketRecord {
            at,
            pid,
            protocol: ICMP,
            local_port: 8,
            remote,
            remote_port: 0,
        };
        let mut l = ledger();
        // 原始套接字：事件带进程自己的 PID
        l.add_socket(icmp_socket(10, 100, REMOTE_IP));
        l.add_packet(20, &echo(REMOTE));
        // 系统 ping 接口：事件是 System
        let other: IpAddr = "192.0.2.9".parse().expect("ip");
        l.add_socket(icmp_socket(30, 4, other));
        l.add_packet(40, &echo([192, 0, 2, 9]));
        // 同一地址先后有两种发送方式：各归各的，不把 System 发的包算给后来的进程
        let both: IpAddr = "192.0.2.10".parse().expect("ip");
        l.add_socket(icmp_socket(41, 4, both));
        l.add_packet(42, &echo([192, 0, 2, 10]));
        l.add_socket(icmp_socket(43, 200, both));
        l.add_packet(44, &echo([192, 0, 2, 10]));
        // 没有事件的地址：不算在任何进程头上
        l.add_packet(50, &echo([192, 0, 2, 77]));
        // 同一地址的 TCP 事件不能用来归属 ICMP
        l.add_socket(socket(60, 300, PORT));
        let r = l.report().expect("report");
        assert_eq!(r.leaked_packets(&[100]), 1);
        assert_eq!(r.leaked_packets(&[4]), 2);
        assert_eq!(r.leaked_packets(&[200]), 1);
        assert_eq!(r.leaked_packets(&[300]), 0);
        assert_eq!(r.flows.iter().filter(|f| f.owner.is_none()).count(), 1);
    }

    #[test]
    fn flows_add_up_packets_and_bytes() {
        let mut l = ledger();
        l.add_socket(socket(10, 100, PORT));
        l.add_packet(20, &v4(REMOTE, TCP, 1, 0, &ports(PORT, 80)));
        l.add_packet(30, &v4(REMOTE, TCP, 2, 0, &ports(PORT, 80)));
        let r = l.report().expect("report");
        assert_eq!(r.flows.len(), 1);
        assert_eq!(r.flows[0].packets, 2);
        assert_eq!(r.flows[0].bytes, 80);
        assert_eq!(r.flows[0].fragments, 0);
    }

    #[test]
    fn an_incomplete_ledger_is_an_error_not_a_low_count() {
        let mut l = ledger();
        l.add_packet(0, &[0x15; 40]);
        assert!(l.report().is_err(), "unparsable packet");

        let mut full = ledger();
        full.overflow = 1;
        assert!(full.report().is_err(), "overflow");
    }

    #[test]
    fn saw_packet_to_ignores_packets_to_other_addresses() {
        let mut l = ledger();
        l.add_packet(0, &v4(REMOTE, UDP, 1, 0, &ports(PORT, 9)));
        assert!(l.saw_packet_to(REMOTE_IP));
        assert!(!l.saw_packet_to("203.0.113.99".parse().expect("ip")));
    }
}
