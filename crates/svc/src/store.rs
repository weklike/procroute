// SPDX-License-Identifier: GPL-3.0-or-later
//! 方案的落盘存储：`<配置根>\profiles\<id>.json`，一个方案一个文件。
//!
//! 配置根目录由 main 用受保护的 DACL 创建（C-SEC-05），这里只做读写。读取时走
//! `procroute-config` 的「解析 → 迁移 → 校验」，旧版本文件读出即是当前版本（C-ARCH-06）；
//! 写入先写临时文件再改名，避免断电留下半个文件。
//!
//! 这里全是阻塞 IO，异步代码必须经 `spawn_blocking` 调用（C-CODE-05）。

use std::io;
use std::path::{Path, PathBuf};

use procroute_config::migrate::{ConfigError, load_profile};
use procroute_config::validate::MAX_ID_LEN;
use procroute_proto::profile::Profile;

const EXTENSION: &str = "json";

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("profile not found")]
    NotFound,
    /// IPC 传入的 id 不是合法的方案 id（也防止路径穿越）。
    #[error("invalid profile id")]
    InvalidId,
    #[error("stored profile {id} cannot be loaded: {source}")]
    Corrupt {
        id: String,
        #[source]
        source: ConfigError,
    },
    #[error("profile storage IO error: {0}")]
    Io(#[from] io::Error),
}

/// 方案存储。只保存目录路径，可以廉价克隆后交给阻塞线程。
#[derive(Debug, Clone)]
pub struct ProfileStore {
    dir: PathBuf,
}

impl ProfileStore {
    /// 打开（必要时创建）方案目录。
    pub fn open(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// 读出全部方案。无法加载的文件记日志后跳过，不影响其他方案。
    pub fn list(&self) -> Result<Vec<Profile>, StoreError> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let path = entry?.path();
            let Some(id) = profile_id_of(&path) else {
                continue;
            };
            match self.get(id) {
                Ok(p) => out.push(p),
                Err(e) => tracing::warn!(error = %e, "skipping unreadable profile"),
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Result<Profile, StoreError> {
        let path = self.path_for(id)?;
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(StoreError::NotFound),
            Err(e) => return Err(e.into()),
        };
        let profile = load_profile(&text).map_err(|source| StoreError::Corrupt {
            id: id.to_owned(),
            source,
        })?;
        if profile.id != id {
            // 文件名与内容不一致：多半是被手工改过，拒绝而不是猜。
            return Err(StoreError::Corrupt {
                id: id.to_owned(),
                source: ConfigError::Shape("id does not match the file name".into()),
            });
        }
        Ok(profile)
    }

    /// 保存（新建或覆盖）。调用方负责先校验方案。
    pub fn save(&self, profile: &Profile) -> Result<(), StoreError> {
        let path = self.path_for(&profile.id)?;
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(profile).map_err(io::Error::other)?;
        std::fs::write(&tmp, text)?;
        // Windows 上 rename 会替换已存在的目标文件。
        std::fs::rename(&tmp, &path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<(), StoreError> {
        match std::fs::remove_file(self.path_for(id)?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(StoreError::NotFound),
            Err(e) => Err(e.into()),
        }
    }

    fn path_for(&self, id: &str) -> Result<PathBuf, StoreError> {
        if !is_valid_id(id) {
            return Err(StoreError::InvalidId);
        }
        Ok(self.dir.join(format!("{id}.{EXTENSION}")))
    }
}

/// 与 `procroute-config` 的方案 id 规则一致：1–64 个字母、数字、`-`、`_`。
fn is_valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn profile_id_of(path: &Path) -> Option<&str> {
    if path.extension()? != EXTENSION {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    is_valid_id(stem).then_some(stem)
}

#[cfg(test)]
pub(crate) mod tests {
    use procroute_proto::profile::{Group, MatchRule, MatchType, PROFILE_SCHEMA_VERSION};

    use super::*;

    pub(crate) fn sample(id: &str, name: &str) -> Profile {
        Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: id.into(),
            name: name.into(),
            mode: Default::default(),
            fail_policy: Default::default(),
            dns: Default::default(),
            udp: Default::default(),
            groups: vec![Group {
                tag: "game".into(),
                outbound: "hk-auto".into(),
                include_children: true,
                matchers: vec![MatchRule {
                    kind: MatchType::Name,
                    value: "launcher.exe".into(),
                    recursive: false,
                }],
            }],
            exclude: vec![],
        }
    }

    fn store(tag: &str) -> (ProfileStore, PathBuf) {
        let dir =
            std::env::temp_dir().join(format!("procroute-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        (ProfileStore::open(&dir).expect("open"), dir)
    }

    #[test]
    fn save_get_list_delete_round_trip() {
        let (s, dir) = store("crud");
        let b = sample("B1", "beta");
        let a = sample("A1", "alpha");
        s.save(&b).expect("save");
        s.save(&a).expect("save");
        assert_eq!(s.get("A1").expect("get"), a);
        let names: Vec<_> = s.list().expect("list").into_iter().map(|p| p.id).collect();
        assert_eq!(names, ["A1", "B1"], "sorted by name");

        let mut a2 = a.clone();
        a2.name = "甲二".into();
        s.save(&a2).expect("overwrite");
        assert_eq!(s.get("A1").expect("get").name, "甲二");

        s.delete("A1").expect("delete");
        assert!(matches!(s.get("A1"), Err(StoreError::NotFound)));
        assert!(matches!(s.delete("A1"), Err(StoreError::NotFound)));
        assert!(!dir.join("A1.json.tmp").exists());
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn ids_cannot_escape_the_directory() {
        let (s, dir) = store("ids");
        for bad in ["", "..", r"..\x", "a/b", "a.b", "C:", &"x".repeat(65)] {
            assert!(matches!(s.get(bad), Err(StoreError::InvalidId)), "{bad:?}");
            assert!(
                matches!(s.delete(bad), Err(StoreError::InvalidId)),
                "{bad:?}"
            );
        }
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn corrupt_or_mismatched_files_are_skipped_by_list() {
        let (s, dir) = store("corrupt");
        s.save(&sample("ok", "好")).expect("save");
        std::fs::write(dir.join("broken.json"), "{not json").expect("write");
        let mut other = sample("other", "x");
        other.id = "elsewhere".into();
        std::fs::write(
            dir.join("other.json"),
            serde_json::to_string(&other).expect("json"),
        )
        .expect("write");
        std::fs::write(dir.join("notes.txt"), "ignored").expect("write");

        let ids: Vec<_> = s.list().expect("list").into_iter().map(|p| p.id).collect();
        assert_eq!(ids, ["ok"]);
        assert!(matches!(s.get("broken"), Err(StoreError::Corrupt { .. })));
        assert!(matches!(s.get("other"), Err(StoreError::Corrupt { .. })));
        std::fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn v1_fixture_loads_through_the_migration_pipeline() {
        let (s, dir) = store("fixture");
        let fixture =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/config/v1.json");
        let text = std::fs::read_to_string(fixture).expect("fixture");
        let id = load_profile(&text).expect("valid fixture").id;
        std::fs::write(dir.join(format!("{id}.json")), text).expect("write");
        assert_eq!(s.get(&id).expect("get").id, id);
        std::fs::remove_dir_all(dir).expect("cleanup");
    }
}
