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
//! - 停止会话后 `curl` 不再经过节点。
#![cfg(all(windows, feature = "vm-tests"))]

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
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
    let host = match req[3] {
        1 => {
            let mut ip = [0u8; 4];
            s.read_exact(&mut ip)?;
            Ipv4Addr::from(ip).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            s.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        4 => {
            let mut ip = [0u8; 16];
            s.read_exact(&mut ip)?;
            format!("[{}]", std::net::Ipv6Addr::from(ip))
        }
        _ => return Ok(()),
    };
    let mut port = [0u8; 2];
    s.read_exact(&mut port)?;
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

fn profile(node_id: &str) -> Profile {
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
                value: curl_exe(),
                recursive: false,
            }],
        }],
        exclude: vec![],
    }
}

#[test]
fn a_target_process_reaches_the_node_through_the_whole_path() {
    let node = Node::start();
    let _service = Service::start();
    let mut c = Client::connect();

    c.call(
        "node.import",
        json!({ "kind": "share_links", "text": format!("socks5://{}#e2e-node", node.addr) }),
    );
    let nodes = c.call("node.list", json!({}));
    let node_id = nodes["nodes"][0]["id"]
        .as_str()
        .expect("node id")
        .to_owned();
    let p = profile(&node_id);
    c.call("profile.save", serde_json::to_value(&p).expect("profile"));
    let status = c
        .try_call("session.start", json!({ "profile_id": p.id }))
        .unwrap_or_else(|e| panic!("session.start failed: {e} (see svc-e2e.log)"));
    assert_eq!(status["state"], "running", "{status}");
    assert_eq!(status["components"]["driver"], "active", "{status}");

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
