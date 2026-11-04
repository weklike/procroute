// SPDX-License-Identifier: GPL-3.0-or-later
//! 精确进程模式的端到端测试（T-078）：真实的服务、sing-box 与 WinDivert，**只在测试虚拟机里、以管理员
//! 身份运行**（C-TEST-04），经 `cargo xtask sandbox-test --only precise_e2e`。
//!
//! 沙盒上不了外网，所以「远端代理」是测试自己起的 SOCKS5 服务器：不管被要求连到哪里，都回一段写明
//! 目标地址的 HTTP 响应。测试经控制管道导入指向它的 `socks5://` 节点、保存按 `curl.exe` 命中的精确模式
//! 方案、启动会话，然后：
//!
//! - `curl` 访问一个文档用地址，必须经 拦截 → 回环中继 → sing-box → 节点 拿到桩的响应；
//! - 本测试进程（非目标）访问同一地址不经过节点；
//! - 停止会话后 `curl` 不再经过节点；
//! - UDP（T-091）：`powershell.exe` 发往文档用地址的数据报经 UDP 中继 → sing-box → 节点的 UDP ASSOCIATE，
//!   节点的回包注入回应用；
//! - 子进程（F7）：方案只命中一个启动器（cmd.exe 的副本），它拉起后立即连接的 `curl` 同样经过节点。
#![cfg(all(windows, feature = "vm-tests"))]

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
/// 文档用地址（TEST-NET-1）：目标进程的连接在离开本机前就被改道。
const TEST_NET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TARGET_PORT: u16 = 8080;
const UDP_PORT: u16 = 5353;

fn curl_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\curl.exe")
}

/// 以控制台模式运行的服务，丢弃即结束（WinDivert 句柄随进程关闭，sing-box 随作业对象结束）。
struct Service(Child);

impl Service {
    fn start() -> Self {
        let dir = PathBuf::from(
            std::env::var_os("PROCROUTE_INSTALL_DIR")
                .expect("PROCROUTE_INSTALL_DIR (sandbox-test)"),
        );
        let log: Stdio = std::env::var_os("PROCROUTE_OUT_DIR")
            .and_then(|out| File::create(PathBuf::from(out).join("svc-e2e.log")).ok())
            .map_or_else(Stdio::null, Stdio::from);
        let child = Command::new(dir.join("procroute-svc.exe"))
            .arg("--console")
            .env("NO_COLOR", "1")
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("start procroute-svc --console");
        Self(child)
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 控制管道客户端：一行一条 JSON-RPC 消息，跳过服务推送的通知。
struct Client {
    writer: File,
    reader: BufReader<File>,
    next_id: u64,
}

impl Client {
    fn connect() -> Self {
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
    fn try_call(&mut self, method: &str, params: Value) -> Result<Value, Value> {
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

    fn call(&mut self, method: &str, params: Value) -> Value {
        let r = self.try_call(method, params);
        assert!(r.is_ok(), "{method} failed: {:?}", r.as_ref().err());
        r.unwrap_or_default()
    }
}

/// 「远端代理」：无认证的 SOCKS5，接受任何 CONNECT，回一段写明目标的 HTTP 响应。记下每个目标。
struct Node {
    addr: SocketAddr,
    targets: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Node {
    fn start() -> Self {
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
                                let _ = serve_socks(s, &targets);
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

    fn targets(&self) -> Vec<String> {
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

fn serve_socks(mut s: TcpStream, targets: &Mutex<Vec<String>>) -> std::io::Result<()> {
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
        return serve_udp_associate(s, targets);
    }
    let target = format!("{host}:{}", u16::from_be_bytes(port));
    targets.lock().expect("targets").push(target.clone());
    s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
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
    )?;
    Ok(())
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

/// UDP ASSOCIATE：在回环上开一个 UDP 端口，收到的每个数据报回一个 `pong udp <目标>`，「来自」那个目标。
/// 控制连接关闭即结束。
fn serve_udp_associate(control: TcpStream, targets: &Mutex<Vec<String>>) -> std::io::Result<()> {
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?;
    udp.set_read_timeout(Some(Duration::from_millis(200)))?;
    let port = udp.local_addr()?.port().to_be_bytes();
    let mut control = control;
    control.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]])?;
    control.set_nonblocking(true)?;
    let mut buf = [0u8; 2048];
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
        let mut reply = buf[..header_len].to_vec();
        reply.extend_from_slice(format!("pong udp {target}").as_bytes());
        udp.send_to(&reply, from)?;
    }
}

/// 用 curl 访问文档用地址，返回响应体（失败时为空）。
fn curl() -> String {
    let out = Command::new(curl_exe())
        .args([
            "-s",
            "-m",
            "10",
            &format!("http://{TEST_NET}:{TARGET_PORT}/hello"),
        ])
        .output()
        .expect("run curl.exe");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn powershell_exe() -> String {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!(r"{root}\System32\WindowsPowerShell\v1.0\powershell.exe")
}

/// 用 PowerShell 发一个 UDP 数据报到文档用地址并等回包，返回回包内容（超时为空）。
fn powershell_udp() -> String {
    let script = format!(
        "$u = New-Object System.Net.Sockets.UdpClient; $u.Client.ReceiveTimeout = 10000; \
         $b = [Text.Encoding]::ASCII.GetBytes('ping'); [void]$u.Send($b, $b.Length, '{TEST_NET}', {UDP_PORT}); \
         $ep = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0); \
         try {{ $r = $u.Receive([ref]$ep); [Text.Encoding]::ASCII.GetString($r) + ' from ' + $ep }} catch {{ 'timeout' }}"
    );
    let out = Command::new(powershell_exe())
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .expect("run powershell.exe");
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn profile(node_id: &str, exe: &str) -> Profile {
    Profile {
        schema_version: PROFILE_SCHEMA_VERSION,
        id: "e2e-precise".into(),
        name: "e2e".into(),
        mode: Mode::Precise,
        fail_policy: FailPolicy::Block,
        dns: Default::default(),
        udp: Default::default(),
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
fn start_session(node: &Node, exe: &str) -> (Service, Client) {
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
    let p = profile(&node_id, exe);
    c.call("profile.save", serde_json::to_value(&p).expect("profile"));
    let started = c.try_call("session.start", json!({ "profile_id": p.id }));
    assert!(
        started.is_ok(),
        "session.start failed: {:?} (see svc-e2e.log)",
        started.as_ref().err()
    );
    let status = started.unwrap_or_default();
    assert_eq!(status["state"], "running", "{status}");
    assert_eq!(status["components"]["driver"], "active", "{status}");
    (service, c)
}

#[test]
fn a_target_process_reaches_the_node_through_the_whole_path() {
    let node = Node::start();
    let (_service, mut c) = start_session(&node, &curl_exe());

    // 目标进程：经整条链路到达节点
    let target = format!("{TEST_NET}:{TARGET_PORT}");
    let body = curl();
    assert_eq!(
        body,
        format!("procroute-e2e {target}"),
        "curl through the session"
    );
    assert_eq!(node.targets(), vec![target.clone()]);

    // 非目标进程（本测试进程）：不经过节点
    let _ = TcpStream::connect_timeout(
        &SocketAddr::from((TEST_NET, TARGET_PORT)),
        Duration::from_secs(2),
    );
    assert_eq!(node.targets().len(), 1, "{:?}", node.targets());

    // 停止会话：撤下拦截，curl 不再经过节点
    let stopped = c.call("session.stop", json!({}));
    assert_eq!(stopped["state"], "stopped");
    let after = curl();
    assert!(!after.starts_with("procroute-e2e"), "{after}");
    assert_eq!(node.targets().len(), 1, "{:?}", node.targets());
}

#[test]
fn target_udp_reaches_the_node_and_the_reply_comes_back() {
    let node = Node::start();
    let (_service, mut c) = start_session(&node, &powershell_exe());

    // 目标进程的 UDP：拦截 → UDP 中继 → sing-box → 节点的 UDP ASSOCIATE，回包注入回应用
    let target = format!("{TEST_NET}:{UDP_PORT}");
    let reply = powershell_udp();
    assert!(
        reply.starts_with(&format!("pong udp {target} from {target}")),
        "reply seen by the app: {reply:?}; node saw {:?}",
        node.targets()
    );
    assert!(node.targets().contains(&format!("udp {target}")));

    let stopped = c.call("session.stop", json!({}));
    assert_eq!(stopped["state"], "stopped");
    // 停止之后不再经过节点
    let before = node.targets().len();
    let after = powershell_udp();
    assert!(!after.starts_with("pong"), "{after}");
    assert_eq!(
        node.targets()
            .iter()
            .filter(|t| t.starts_with("udp "))
            .count(),
        node.targets()[..before]
            .iter()
            .filter(|t| t.starts_with("udp "))
            .count()
    );
}

/// 「启动器」：复制一份 cmd.exe。测试程序本身经 run.ps1 的 `cmd.exe /c` 启动，是系统 cmd.exe 的后代，
/// 方案若命中系统 cmd.exe，测试进程也会继承成目标；换个路径的副本就只有它拉起的进程是后代。
fn launcher_exe() -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let launcher = std::env::temp_dir().join("procroute-e2e-launcher.exe");
    std::fs::copy(format!(r"{root}\System32\cmd.exe"), &launcher).expect("copy cmd.exe");
    launcher
}

#[test]
fn a_child_connecting_right_after_start_inherits_the_target() {
    // F7：方案只命中启动器；它拉起的 curl 一启动就连接，进程追踪（ETW）还没报到，靠当场的继承判定
    let node = Node::start();
    let launcher = launcher_exe();
    let (_service, mut c) = start_session(&node, &launcher.to_string_lossy());
    let url = format!("http://{TEST_NET}:{TARGET_PORT}/child");
    let out = Command::new(&launcher)
        .args(["/c", &curl_exe(), "-s", "-m", "10", &url])
        .output()
        .expect("run the launcher");
    let body = String::from_utf8_lossy(&out.stdout).into_owned();
    assert_eq!(
        body,
        format!("procroute-e2e {TEST_NET}:{TARGET_PORT}"),
        "the child went through the node"
    );
    // 测试进程直接运行的 curl 不是启动器的后代：不经过节点
    let direct = curl();
    assert!(!direct.starts_with("procroute-e2e"), "{direct}");
    assert_eq!(node.targets().len(), 1, "{:?}", node.targets());
    let stopped = c.call("session.stop", json!({}));
    assert_eq!(stopped["state"], "stopped");
}
