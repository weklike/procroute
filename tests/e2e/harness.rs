// SPDX-License-Identifier: GPL-3.0-or-later
//! 端到端用例的测试框架：以控制台模式运行的真实服务、控制管道客户端、测试自己起的 SOCKS5 节点与回显目标进程。
//!
//! 沙盒上不了外网，所以「远端代理」是测试自己起的 SOCKS5 服务器，不管被要求连到哪里都由它应答。
//! 安装目录由 `cargo xtask sandbox-test` 准备（`PROCROUTE_INSTALL_DIR`：服务、sing-box、WinDivert）。

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use procroute_proto::IPC_PROTOCOL_VERSION;
use procroute_proto::profile::{
    FailPolicy, Group, MatchRule, MatchType, Mode, PROFILE_SCHEMA_VERSION, Profile,
};
use serde_json::{Value, json};

const PIPE: &str = r"\\.\pipe\ProcRoute.Control";
const SVC_LOG: &str = "svc-e2e.log";
/// 文档用地址（TEST-NET-1）：目标进程的连接在离开本机前就被改道，发出去也没有人应答。
pub const TEST_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

/// 放着服务、sing-box 与锁定版本 WinDivert 的目录（`cargo xtask sandbox-test` 准备）。
pub fn install_dir() -> PathBuf {
    PathBuf::from(
        std::env::var_os("PROCROUTE_INSTALL_DIR").expect("PROCROUTE_INSTALL_DIR (sandbox-test)"),
    )
}

fn out_dir() -> Option<PathBuf> {
    std::env::var_os("PROCROUTE_OUT_DIR").map(PathBuf::from)
}

/// 把一段观察结果追加到输出目录的 `leak-report.log`。通过的用例不打印标准输出，这里留下实测的数字。
pub fn record(scenario: &str, text: &str) {
    let file = out_dir().and_then(|out| {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(out.join("leak-report.log"))
            .ok()
    });
    if let Some(mut f) = file {
        let _ = writeln!(f, "== {scenario}\n{text}");
    }
}

/// 以控制台模式运行的服务，丢弃即结束（WinDivert 句柄随进程关闭，sing-box 随作业对象结束）。
#[derive(Debug)]
pub struct Service(Child);

impl Service {
    pub fn start() -> Self {
        // 追加写：一次运行里的各个用例都留下日志，失败时能对照
        let log: Stdio = out_dir()
            .and_then(|out| {
                OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(out.join(SVC_LOG))
                    .ok()
            })
            .map_or_else(Stdio::null, Stdio::from);
        let child = Command::new(install_dir().join("procroute-svc.exe"))
            .arg("--console")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start procroute-svc --console");
        Self(child)
    }

    /// 最近一次会话停止时拦截层记下的 `attribution_miss`（C-TEST-02）。调用前先停止会话。
    pub fn attribution_miss(&self) -> u64 {
        let out = out_dir().expect("PROCROUTE_OUT_DIR (sandbox-test)");
        let log = std::fs::read_to_string(out.join(SVC_LOG)).expect("read the service log");
        attribution_miss_in(&log).expect("the service logged its interception counters")
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 日志里最后一个 `attribution_miss=<数字>`。
fn attribution_miss_in(log: &str) -> Option<u64> {
    let (_, tail) = log.rsplit_once("attribution_miss=")?;
    let digits = tail.split(|c: char| !c.is_ascii_digit()).next()?;
    digits.parse().ok()
}

/// 控制管道客户端：一行一条 JSON-RPC 消息，跳过服务推送的通知。
#[derive(Debug)]
pub struct Client {
    writer: File,
    reader: BufReader<File>,
    next_id: u64,
}

impl Client {
    pub fn connect() -> Self {
        let deadline = Instant::now() + Duration::from_secs(30);
        let pipe = loop {
            match OpenOptions::new().read(true).write(true).open(PIPE) {
                Ok(f) => break f,
                Err(e) => {
                    assert!(
                        Instant::now() < deadline,
                        "the control pipe never came up: {e}"
                    );
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        };
        let mut c = Self {
            writer: pipe.try_clone().expect("clone pipe"),
            reader: BufReader::new(pipe),
            next_id: 0,
        };
        let hello = c.call(
            "ipc.hello",
            json!({ "protocol_version": IPC_PROTOCOL_VERSION, "client_version": "e2e" }),
        );
        assert_eq!(hello["protocol_version"], IPC_PROTOCOL_VERSION);
        c
    }

    /// 调用一个方法；出错时返回错误对象。
    pub fn try_call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
        self.next_id += 1;
        let id = self.next_id;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.writer, "{line}").expect("write request");
        loop {
            let mut buf = String::new();
            let n = self.reader.read_line(&mut buf).expect("read response");
            assert_ne!(n, 0, "the service closed the pipe");
            let msg: Value = serde_json::from_str(&buf).expect("JSON");
            if msg["id"] != id {
                continue;
            }
            return match msg.get("error") {
                Some(e) => Err(e.clone()),
                None => Ok(msg["result"].clone()),
            };
        }
    }

    pub fn call(&mut self, method: &str, params: Value) -> Value {
        let r = self.try_call(method, params);
        assert!(r.is_ok(), "{method} failed: {:?}", r.as_ref().err());
        r.unwrap_or_default()
    }

    /// 停止会话并确认已经停下。
    pub fn stop_session(&mut self) {
        let stopped = self.call("session.stop", json!({}));
        assert_eq!(stopped["state"], "stopped", "{stopped}");
    }
}

/// 节点怎么应答。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// TCP 回一段写明目标的 HTTP 响应（给 curl），UDP 回 `pong udp <目标>`。
    Describe,
    /// TCP 与 UDP 都原样回显（给 echo_target）。
    Echo,
}

/// 「远端代理」：无认证的 SOCKS5，接受任何 CONNECT 与 UDP ASSOCIATE。记下每个目标。
#[derive(Debug)]
pub struct Node {
    pub addr: SocketAddr,
    targets: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Node {
    pub fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind the node");
        listener.set_nonblocking(true).expect("nonblocking");
        let addr = listener.local_addr().expect("node address");
        let targets = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let targets = Arc::clone(&targets);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((s, _)) => {
                            let targets = Arc::clone(&targets);
                            std::thread::spawn(move || {
                                let _ = serve_socks(s, &targets, reply);
                            });
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        Self {
            addr,
            targets,
            stop,
            thread: Some(thread),
        }
    }

    /// 节点见过的目标：TCP 是 `地址:端口`，UDP 是 `udp 地址:端口`。
    pub fn targets(&self) -> Vec<String> {
        self.targets.lock().expect("targets").clone()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn serve_socks(
    mut s: TcpStream,
    targets: &Mutex<Vec<String>>,
    reply: Reply,
) -> std::io::Result<()> {
    s.set_nonblocking(false)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    // 问候：版本 5，方法列表；选「无需认证」
    let mut head = [0u8; 2];
    s.read_exact(&mut head)?;
    let mut methods = vec![0u8; usize::from(head[1])];
    s.read_exact(&mut methods)?;
    s.write_all(&[5, 0])?;
    // 请求：VER CMD RSV ATYP ...
    let mut req = [0u8; 4];
    s.read_exact(&mut req)?;
    let Some(host) = read_host(&mut s, req[3])? else {
        return Ok(());
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port)?;
    if req[1] == 3 {
        return serve_udp_associate(s, targets, reply);
    }
    let target = format!("{host}:{}", u16::from_be_bytes(port));
    targets.lock().expect("targets").push(target.clone());
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    match reply {
        Reply::Describe => describe_over_http(s, &target),
        Reply::Echo => echo_until_closed(s),
    }
}

fn describe_over_http(mut s: TcpStream, target: &str) -> std::io::Result<()> {
    // 读完 HTTP 请求头再回响应
    let mut reader = BufReader::new(s.try_clone()?);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" {
            break;
        }
    }
    let body = format!("procroute-e2e {target}");
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn echo_until_closed(mut s: TcpStream) -> std::io::Result<()> {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = s.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        s.write_all(&buf[..n])?;
    }
}

/// SOCKS5 地址（ATYP 之后的部分，不含端口）。
fn read_host(r: &mut impl Read, atyp: u8) -> std::io::Result<Option<String>> {
    Ok(Some(match atyp {
        1 => {
            let mut ip = [0u8; 4];
            r.read_exact(&mut ip)?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            r.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut ip = [0u8; 16];
            r.read_exact(&mut ip)?;
            format!("[{}]", Ipv6Addr::from(ip))
        }
        _ => return Ok(None),
    }))
}

/// UDP ASSOCIATE：在回环上开一个 UDP 端口，收到的每个数据报回一个，「来自」它要去的那个目标。
/// 控制连接关闭即结束。
fn serve_udp_associate(
    control: TcpStream,
    targets: &Mutex<Vec<String>>,
    reply: Reply,
) -> std::io::Result<()> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    udp.set_read_timeout(Some(Duration::from_millis(200)))?;
    let port = udp.local_addr()?.port().to_be_bytes();
    let mut control = control;
    control.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])?;
    control.set_nonblocking(true)?;
    let mut buf = vec![0u8; 65_535];
    loop {
        // 控制连接被对方关闭：关联结束
        match control.peek(&mut [0u8; 1]) {
            Ok(0) => return Ok(()),
            Err(e) if e.kind() != ErrorKind::WouldBlock => return Ok(()),
            _ => {}
        }
        let (n, from) = match udp.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => return Err(e),
        };
        // RSV(2) FRAG(1) ATYP ADDR PORT DATA
        if n < 4 {
            continue;
        }
        let mut r = &buf[4..n];
        let Some(host) = read_host(&mut r, buf[3])? else {
            continue;
        };
        let mut port = [0u8; 2];
        r.read_exact(&mut port)?;
        let target = format!("{host}:{}", u16::from_be_bytes(port));
        targets
            .lock()
            .expect("targets")
            .push(format!("udp {target}"));
        // 回包的头与请求相同：地址字段就是回包的来源（那个目标）
        let header_len = n - r.len();
        let mut answer = buf[..header_len].to_vec();
        match reply {
            Reply::Describe => answer.extend_from_slice(format!("pong udp {target}").as_bytes()),
            Reply::Echo => answer.extend_from_slice(r),
        }
        udp.send_to(&answer, from)?;
    }
}

/// 按 `exe` 的完整路径命中的精确模式方案，`fail_policy` 取默认的 `block`，包含子进程。
pub fn profile(node_id: &str, exe: &str) -> Profile {
    Profile {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: "e2e-precise".into(),
        name: "e2e".into(),
        mode: Mode::Precise,
        fail_policy: FailPolicy::Block,
        dns: Default::default(),
        udp: Default::default(),
        icmp: Default::default(),
        groups: vec![Group {
            tag: "e2e".into(),
            outbound: node_id.into(),
            include_children: true,
            matchers: vec![MatchRule {
                kind: MatchType::Path,
                value: exe.into(),
                recursive: false,
            }],
        }],
        exclude: vec![],
    }
}

/// 起服务、导入指向 `node` 的节点、保存按 `exe` 命中的方案并启动会话。
pub fn start_session(node: &Node, exe: &str) -> (Service, Client) {
    start_session_with(node, exe, |_| {})
}

/// 同 [`start_session`]，存盘前再改一改方案。
pub fn start_session_with(
    node: &Node,
    exe: &str,
    change: impl FnOnce(&mut Profile),
) -> (Service, Client) {
    let service = Service::start();
    let mut c = Client::connect();
    c.call(
        "node.import",
        json!({ "kind": "share_links", "text": format!("socks5://{}#e2e-node", node.addr) }),
    );
    // 配置目录在多个测试之间保留：按地址找这次的节点
    let nodes = c.call("node.list", json!({}));
    let node_id = nodes["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|n| n["server"] == node.addr.to_string())
        .and_then(|n| n["id"].as_str())
        .expect("the imported node")
        .to_owned();
    let mut p = profile(&node_id, exe);
    change(&mut p);
    c.call("profile.save", serde_json::to_value(&p).expect("profile"));
    let started = c.try_call("session.start", json!({ "profile_id": p.id }));
    assert!(
        started.is_ok(),
        "session.start failed: {:?} (see {SVC_LOG})",
        started.as_ref().err()
    );
    let status = started.unwrap_or_default();
    assert_eq!(status["state"], "running", "{status}");
    if p.mode == Mode::Precise {
        assert_eq!(status["components"]["driver"], "active", "{status}");
    }
    (service, c)
}

/// 「启动器」：复制一份 cmd.exe。测试程序本身经 run.ps1 的 `cmd.exe /c` 启动，是系统 cmd.exe 的后代，
/// 方案若命中系统 cmd.exe，测试进程也会继承成目标；换个路径的副本就只有它拉起的进程是后代。
pub fn launcher_exe() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let launcher = std::env::temp_dir().join("procroute-e2e-launcher.exe");
    std::fs::copy(format!(r"{root}\System32\cmd.exe"), &launcher).expect("copy cmd.exe");
    launcher
}

/// 回显目标进程，由 `cargo xtask sandbox-test` 放在测试程序旁边。
pub fn echo_target_exe() -> PathBuf {
    std::env::current_exe()
        .expect("test executable")
        .with_file_name("echo_target.exe")
}

/// 回显目标进程的一次运行。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EchoRun {
    /// `echo_target` 自己报告的进程号。
    pub pid: u32,
    /// 全部轮次都收到了正确的回显。
    pub ok: bool,
    pub output: String,
}

/// 一次回显：协议、远端、轮数、每轮字节数与超时。
#[derive(Debug, Clone, Copy)]
pub struct Echo {
    pub protocol: &'static str,
    pub remote: SocketAddr,
    pub rounds: u32,
    pub bytes: usize,
    pub timeout: Duration,
}

impl Echo {
    fn args(&self) -> Vec<String> {
        vec![
            self.protocol.to_owned(),
            self.remote.to_string(),
            self.rounds.to_string(),
            self.bytes.to_string(),
            self.timeout.as_millis().to_string(),
        ]
    }

    /// 直接启动，不等它结束。
    pub fn spawn(&self) -> Child {
        Command::new(echo_target_exe())
            .args(self.args())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start echo_target")
    }

    /// 运行放在别处的一份回显目标进程。
    pub fn run_exe(&self, exe: &std::path::Path) -> EchoRun {
        let child = Command::new(exe)
            .args(self.args())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the copy of echo_target");
        finish_echo(child)
    }

    /// 经启动器（cmd.exe 的副本）拉起，不等它结束。
    pub fn spawn_via(&self, launcher: &std::path::Path) -> Child {
        Command::new(launcher)
            .arg("/c")
            .arg(echo_target_exe())
            .args(self.args())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the launcher")
    }

    pub fn run(&self) -> EchoRun {
        finish_echo(self.spawn())
    }
}

/// 等一次回显结束，读出结果。
pub fn finish_echo(child: Child) -> EchoRun {
    let out = child.wait_with_output().expect("wait for echo_target");
    let output = String::from_utf8_lossy(&out.stdout).into_owned();
    let pid = output
        .lines()
        .find_map(|l| l.strip_prefix("pid="))
        .and_then(|p| p.trim().parse().ok())
        .expect("echo_target reports its pid on the first line");
    EchoRun {
        pid,
        ok: out.status.success() && output.lines().any(|l| l.trim() == "ok"),
        output,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_last_attribution_miss_in_the_log_wins() {
        let log = "a attribution_miss=7 b\nc attribution_miss=12\nd";
        assert_eq!(attribution_miss_in(log), Some(12));
        assert_eq!(attribution_miss_in("no counters here"), None);
    }
}
