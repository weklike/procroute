// SPDX-License-Identifier: GPL-3.0-or-later
//! 节点与订阅的落盘存储：`<配置根>\nodes.json`。
//!
//! 协议参数明文保存（不含凭据）；每个节点的凭据序列化后用机器范围 DPAPI 加密，以十六进制存放
//! （C-SEC-04）。订阅地址常含访问令牌，同样加密存放。配置根目录的 DACL 只允许 SYSTEM 与
//! Administrators 写入（C-SEC-05）。
//!
//! 格式版本：1 只有节点；2 增加订阅。读到版本 1 时按「没有订阅」处理，下次写入即升级为版本 2。
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

/// 落盘格式版本。结构变更时加一并提供迁移（见模块文档）。
const FORMAT_VERSION: u32 = 2;

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

/// 一个已保存的订阅。
#[derive(Debug, Clone)]
pub struct StoredSubscription {
    pub id: String,
    pub name: String,
    /// 完整地址，可能含令牌；只用于拉取，不返回给界面。
    pub url: Secret<String>,
    pub updated_at_ms: Option<u64>,
}

/// 文件里的全部内容。
#[derive(Debug, Clone, Default)]
pub struct NodeData {
    pub nodes: Vec<StoredNode>,
    pub subscriptions: Vec<StoredSubscription>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    nodes: Vec<Record>,
    /// 版本 1 没有这个字段。
    #[serde(default)]
    subscriptions: Vec<SubscriptionRecord>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubscriptionRecord {
    id: String,
    name: String,
    /// 地址的 DPAPI 密文十六进制。
    url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    updated_at_ms: Option<u64>,
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
        Ok(self.load_all()?.nodes)
    }

    /// 读出节点与订阅。
    pub fn load_all(&self) -> Result<NodeData, NodeStoreError> {
        let _guard = self.guard();
        self.read()
    }

    /// 在锁内读出、修改节点、写回。`f` 返回的值原样带出；读取失败时不会写入，避免覆盖已有数据。
    pub fn update<T>(
        &self,
        f: impl FnOnce(&mut Vec<StoredNode>) -> T,
    ) -> Result<T, NodeStoreError> {
        self.update_all(|data| f(&mut data.nodes))
    }

    /// 同 [`NodeStore::update`]，可以同时修改订阅。
    pub fn update_all<T>(&self, f: impl FnOnce(&mut NodeData) -> T) -> Result<T, NodeStoreError> {
        let _guard = self.guard();
        let mut data = self.read()?;
        let out = f(&mut data);
        self.write(&data)?;
        Ok(out)
    }

    fn guard(&self) -> std::sync::MutexGuard<'_, ()> {
        // 持锁线程 panic 过也不影响文件本身的一致性（写入是原子改名）。
        self.lock.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn read(&self) -> Result<NodeData, NodeStoreError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(NodeData::default()),
            Err(e) => return Err(e.into()),
        };
        let file: File =
            serde_json::from_str(&text).map_err(|_| NodeStoreError::Corrupt("invalid JSON"))?;
        if !(1..=FORMAT_VERSION).contains(&file.version) {
            return Err(NodeStoreError::UnsupportedVersion(file.version));
        }
        let nodes = file
            .nodes
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
            .collect::<Result<_, NodeStoreError>>()?;
        let subscriptions = file
            .subscriptions
            .into_iter()
            .map(|r| {
                Ok(StoredSubscription {
                    url: decrypt_text(&r.url)?,
                    id: r.id,
                    name: r.name,
                    updated_at_ms: r.updated_at_ms,
                })
            })
            .collect::<Result<_, NodeStoreError>>()?;
        Ok(NodeData {
            nodes,
            subscriptions,
        })
    }

    fn write(&self, data: &NodeData) -> Result<(), NodeStoreError> {
        let subscriptions = data
            .subscriptions
            .iter()
            .map(|s| {
                Ok(SubscriptionRecord {
                    id: s.id.clone(),
                    name: s.name.clone(),
                    url: to_hex(&dpapi::protect(s.url.expose().as_bytes())?),
                    updated_at_ms: s.updated_at_ms,
                })
            })
            .collect::<Result<Vec<_>, NodeStoreError>>()?;
        let records = data
            .nodes
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
            subscriptions,
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

/// 十六进制 DPAPI 密文 → UTF-8 文本。
fn decrypt_text(hex: &str) -> Result<Secret<String>, NodeStoreError> {
    let cipher = from_hex(hex).ok_or(NodeStoreError::Corrupt("encrypted text is not hex"))?;
    let plain = dpapi::unprotect(&cipher)?;
    String::from_utf8(plain.expose().clone())
        .map(Secret::new)
        .map_err(|_| NodeStoreError::Corrupt("encrypted text is not UTF-8"))
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
    fn subscriptions_round_trip_with_encrypted_urls() {
        let (s, dir) = store("subs");
        s.update_all(|d| {
            d.subscriptions.push(StoredSubscription {
                id: "s1".into(),
                name: "我的订阅".into(),
                url: Secret::new("https://sub.example.com/s?token=hunter2-token".into()),
                updated_at_ms: Some(42),
            });
            let mut n = trojan("n1", "p");
            n.subscription_id = Some("s1".into());
            d.nodes.push(n);
        })
        .expect("update");
        let data = s.load_all().expect("load");
        assert_eq!(data.subscriptions.len(), 1);
        assert_eq!(
            data.subscriptions[0].url.expose(),
            "https://sub.example.com/s?token=hunter2-token"
        );
        assert_eq!(data.subscriptions[0].updated_at_ms, Some(42));
        assert_eq!(data.nodes[0].subscription_id.as_deref(), Some("s1"));
        let on_disk = std::fs::read_to_string(dir.join("nodes.json")).expect("read");
        assert!(
            !on_disk.contains("hunter2"),
            "subscription URLs are encrypted"
        );
        assert!(!on_disk.contains("sub.example.com"));
        // 只改节点的旧接口不会丢订阅
        s.update(|n| n.clear()).expect("update");
        assert_eq!(s.load_all().expect("load").subscriptions.len(), 1);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn version_1_files_load_and_upgrade_on_write() {
        let (s, dir) = store("v1");
        let blob = to_hex(&dpapi::protect(br#"{"password":"p"}"#).expect("protect"));
        let node = serde_json::to_value(trojan("n1", "p").node).expect("node");
        let v1 = serde_json::json!({
            "version": 1,
            "nodes": [ { "id": "n1", "name": "旧节点", "node": node, "credentials": blob } ],
        });
        std::fs::write(dir.join("nodes.json"), v1.to_string()).expect("write");
        let data = s.load_all().expect("v1 loads");
        assert_eq!(data.nodes.len(), 1);
        assert!(data.subscriptions.is_empty());
        s.update(|_| {}).expect("rewrite");
        let on_disk: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join("nodes.json")).expect("read"))
                .expect("json");
        assert_eq!(on_disk["version"], 2);
        assert_eq!(on_disk["subscriptions"], serde_json::json!([]));
        assert_eq!(s.load().expect("load")[0].name, "旧节点");
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
