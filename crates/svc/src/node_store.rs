// SPDX-License-Identifier: GPL-3.0-or-later
//! 节点的落盘存储：`<配置根>\nodes.json`。
//!
//! 协议参数明文保存（不含凭据）；每个节点的凭据序列化后用机器范围 DPAPI 加密，以十六进制存放
//! （C-SEC-04）。配置根目录的 DACL 只允许 SYSTEM 与 Administrators 写入（C-SEC-05）。
//! 读改写由一把互斥锁串行化；写入先写临时文件再改名。
//!
//! 这里全是阻塞 IO，异步代码必须经 `spawn_blocking` 调用（C-CODE-05）。

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use procroute_core_mgr::node::{Credentials, Node};
use procroute_platform_win::dpapi::{self, DpapiError};
use procroute_platform_win::hash::to_hex;
use procroute_platform_win::secret::Secret;
use serde::{Deserialize, Serialize};

/// 落盘格式版本。结构变更时加一并提供迁移。
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum NodeStoreError {
    #[error("node storage IO error: {0}")]
    Io(#[from] io::Error),
    /// 文件内容无法解析。不带文件内容，避免把凭据密文或节点地址写进日志。
    #[error("nodes.json is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("nodes.json has unsupported format version {0}")]
    UnsupportedVersion(u32),
    #[error("credential encryption failed: {0}")]
    Dpapi(#[from] DpapiError),
}

/// 一个已保存的节点。
#[derive(Debug, Clone)]
pub struct StoredNode {
    pub id: String,
    pub name: String,
    pub subscription_id: Option<String>,
    pub node: Node,
    pub credentials: Credentials,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    nodes: Vec<Record>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    id: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subscription_id: Option<String>,
    node: Node,
    /// DPAPI 密文的十六进制。
    credentials: String,
}

/// 节点存储。可以廉价克隆后交给阻塞线程；克隆共享同一把锁。
#[derive(Debug, Clone)]
pub struct NodeStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl NodeStore {
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Ok(Self {
            path,
            lock: Arc::new(Mutex::new(())),
        })
    }

    /// 读出全部节点（凭据已解密）。
    pub fn load(&self) -> Result<Vec<StoredNode>, NodeStoreError> {
        let _guard = self.guard();
        self.read()
    }

    /// 在锁内读出、修改、写回。`f` 返回的值原样带出；读取失败时不会写入，避免覆盖已有数据。
    pub fn update<T>(
        &self,
        f: impl FnOnce(&mut Vec<StoredNode>) -> T,
    ) -> Result<T, NodeStoreError> {
        let _guard = self.guard();
        let mut nodes = self.read()?;
        let out = f(&mut nodes);
        self.write(&nodes)?;
        Ok(out)
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        // 持锁线程 panic 过也不影响文件本身的一致性（写入是原子改名）。
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn read(&self) -> Result<Vec<StoredNode>, NodeStoreError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let file: File =
            serde_json::from_str(&text).map_err(|_| NodeStoreError::Corrupt("invalid JSON"))?;
        if file.version != FORMAT_VERSION {
            return Err(NodeStoreError::UnsupportedVersion(file.version));
        }
        file.nodes
            .into_iter()
            .map(|r| {
                Ok(StoredNode {
                    credentials: decrypt(&r.credentials)?,
                    id: r.id,
                    name: r.name,
                    subscription_id: r.subscription_id,
                    node: r.node,
                })
            })
            .collect()
    }

    fn write(&self, nodes: &[StoredNode]) -> Result<(), NodeStoreError> {
        let records = nodes
            .iter()
            .map(|n| {
                Ok(Record {
                    id: n.id.clone(),
                    name: n.name.clone(),
                    subscription_id: n.subscription_id.clone(),
                    node: n.node.clone(),
                    credentials: encrypt(&n.credentials)?,
                })
            })
            .collect::<Result<Vec<_>, NodeStoreError>>()?;
        let text = serde_json::to_string_pretty(&File {
            version: FORMAT_VERSION,
            nodes: records,
        })
        .map_err(io::Error::other)?;
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, text)?;
        std::fs::rename(&tmp, &self.path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        Ok(())
    }
}

/// 凭据 → JSON 明文（只在 `Secret` 里出现）→ DPAPI → 十六进制。
fn encrypt(c: &Credentials) -> Result<String, NodeStoreError> {
    let mut map = BTreeMap::new();
    for (key, value) in [
        ("username", &c.username),
        ("password", &c.password),
        ("uuid", &c.uuid),
        ("obfs_password", &c.obfs_password),
    ] {
        if let Some(v) = value {
            map.insert(key, v.expose().as_str());
        }
    }
    let plain = Secret::new(serde_json::to_vec(&map).map_err(io::Error::other)?);
    Ok(to_hex(&dpapi::protect(plain.expose())?))
}

fn decrypt(hex: &str) -> Result<Credentials, NodeStoreError> {
    let cipher = from_hex(hex).ok_or(NodeStoreError::Corrupt("credential blob is not hex"))?;
    let plain = dpapi::unprotect(&cipher)?;
    let map: BTreeMap<String, String> = serde_json::from_slice(plain.expose())
        .map_err(|_| NodeStoreError::Corrupt("credential blob is not a string map"))?;
    let mut c = Credentials::default();
    for (key, value) in map {
        let slot = match key.as_str() {
            "username" => &mut c.username,
            "password" => &mut c.password,
            "uuid" => &mut c.uuid,
            "obfs_password" => &mut c.obfs_password,
            _ => return Err(NodeStoreError::Corrupt("unknown credential field")),
        };
        *slot = Some(Secret::new(value));
    }
    Ok(c)
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let digit = |c: u8| (c as char).to_digit(16);
            Some((digit(pair[0])? * 16 + digit(pair[1])?) as u8)
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use procroute_core_mgr::node::{Settings, Tls};

    use super::*;

    pub(crate) fn trojan(id: &str, password: &str) -> StoredNode {
        StoredNode {
            id: id.into(),
            name: format!("节点 {id}"),
            subscription_id: None,
            node: Node {
                server: "tj.example.com".into(),
                server_port: 443,
                settings: Settings::Trojan {
                    tls: Tls::default(),
                    transport: None,
                },
            },
            credentials: Credentials {
                password: Some(Secret::new(password.into())),
                ..Default::default()
            },
        }
    }

    fn store(tag: &str) -> (NodeStore, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("procroute-nodes-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (NodeStore::open(dir.join("nodes.json")).expect("open"), dir)
    }

    #[test]
    fn round_trips_and_encrypts_credentials() {
        let (s, dir) = store("rt");
        assert!(s.load().expect("empty").is_empty());
        s.update(|n| n.push(trojan("n1", "hunter2-very-secret")))
            .expect("update");
        let loaded = s.load().expect("load");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].node, trojan("n1", "x").node);
        assert_eq!(
            loaded[0]
                .credentials
                .password
                .as_ref()
                .map(|p| p.expose().as_str()),
            Some("hunter2-very-secret")
        );
        let on_disk = std::fs::read_to_string(dir.join("nodes.json")).expect("read");
        assert!(
            !on_disk.contains("hunter2"),
            "credentials must be encrypted on disk"
        );
        assert!(on_disk.contains("tj.example.com"));
        assert!(!dir.join("nodes.json.tmp").exists());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn corrupt_files_are_not_overwritten() {
        let (s, dir) = store("corrupt");
        std::fs::write(dir.join("nodes.json"), "{oops").expect("write");
        assert!(matches!(s.load(), Err(NodeStoreError::Corrupt(_))));
        assert!(s.update(|n| n.push(trojan("n1", "p"))).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("nodes.json")).expect("read"),
            "{oops"
        );
        std::fs::write(dir.join("nodes.json"), r#"{"version":9,"nodes":[]}"#).expect("write");
        assert!(matches!(
            s.load(),
            Err(NodeStoreError::UnsupportedVersion(9))
        ));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn hex_round_trips() {
        let data = [0u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(from_hex(&to_hex(&data)).as_deref(), Some(&data[..]));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
    }
}
