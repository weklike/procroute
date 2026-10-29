// SPDX-License-Identifier: GPL-3.0-or-later
//! 进程树与目标集合。
//!
//! 每个运行中的进程按 PID 存一项，身份是「PID + 创建时间」：同一个 PID 出现了更晚创建的进程，
//! 说明旧进程已经退出（退出事件可能丢了），先按退出处理再登记新进程；更早的创建时间是过时的事件，忽略。
//!
//! 判定见 `procroute_rules::inherit::decide_child`：自身命中按自身（排除最优先）；否则父进程在某组、
//! 该组开启 `include_children`、且父进程早于子进程创建时继承。父进程之后退出不影响已经继承的子进程。

use std::collections::{HashMap, HashSet};

use procroute_rules::engine::{Decision, RuleEngine};
use procroute_rules::inherit::{ParentInfo, decide_child};
use procroute_rules::matcher::NormalizedProcess;

/// 进程身份：PID + 创建时间（C-DRV-04）。Windows 上 `created_at` 是 FILETIME，只要求单调可比。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProcessKey {
    pub pid: u32,
    pub created_at: u64,
}

/// 登记一个进程所需的信息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub key: ProcessKey,
    pub parent_pid: u32,
    /// 可执行文件名（不含路径）；为空时取路径的最后一段。
    pub name: String,
    /// Win32 完整路径；进程已退出或无权查询时为空，此时只能按名称与继承判定。
    pub path: Option<String>,
}

/// 目标集合的变化。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// 进程进入目标集合，或换了组 / 继承状态。
    Targeted {
        key: ProcessKey,
        /// 方案里的组下标。
        group: usize,
        /// 自身没有命中规则，是从父进程继承的。
        inherited: bool,
        name: String,
        path: Option<String>,
    },
    /// 进程离开目标集合：退出，或换方案后不再命中。
    Released { key: ProcessKey },
}

#[derive(Debug)]
struct Entry {
    info: ProcessInfo,
    decision: Decision,
    inherited: bool,
}

/// 进程树。不做 IO，事件与快照由调用方喂进来。
#[derive(Debug)]
pub struct ProcessTree {
    engine: RuleEngine,
    by_pid: HashMap<u32, Entry>,
}

impl ProcessTree {
    pub fn new(engine: RuleEngine) -> Self {
        Self {
            engine,
            by_pid: HashMap::new(),
        }
    }

    /// 已登记的进程数。
    pub fn len(&self) -> usize {
        self.by_pid.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_pid.is_empty()
    }

    /// 这个进程是否已登记。
    pub fn contains(&self, key: &ProcessKey) -> bool {
        self.entry(key).is_some()
    }

    /// 进程的判定；未登记的进程视为 `Direct`。
    pub fn decision(&self, key: &ProcessKey) -> Decision {
        self.entry(key).map_or(Decision::Direct, |e| e.decision)
    }

    /// 目标集合：进程与所属组下标。
    pub fn targets(&self) -> impl Iterator<Item = (ProcessKey, usize)> + '_ {
        self.by_pid
            .values()
            .filter_map(|e| e.decision.group().map(|g| (e.info.key, g)))
    }

    /// 进程启动（或在快照里第一次见到）。
    pub fn started(&mut self, info: ProcessInfo, out: &mut Vec<Change>) {
        if let Some(existing) = self.by_pid.get(&info.key.pid) {
            let known = existing.info.key;
            if known.created_at >= info.key.created_at {
                // 同一个进程（快照与事件重复），或过时的事件
                return;
            }
            // PID 被复用：旧进程的退出没有收到
            self.stopped(known, out);
        }
        let (decision, inherited) = self.decide(&info);
        if let Some(group) = decision.group() {
            out.push(targeted(&info, group, inherited));
        }
        self.by_pid.insert(
            info.key.pid,
            Entry {
                info,
                decision,
                inherited,
            },
        );
    }

    /// 进程退出。创建时间对不上（旧进程的迟到事件）时忽略。
    pub fn stopped(&mut self, key: ProcessKey, out: &mut Vec<Change>) {
        if self.entry(&key).is_none() {
            return;
        }
        if let Some(e) = self.by_pid.remove(&key.pid)
            && e.decision.group().is_some()
        {
            out.push(Change::Released { key });
        }
    }

    /// 用完整快照校正：快照里没有的进程按退出处理，新出现的按创建时间顺序登记（父进程先于子进程）。
    pub fn reconcile(&mut self, mut snapshot: Vec<ProcessInfo>, out: &mut Vec<Change>) {
        let alive: HashSet<ProcessKey> = snapshot.iter().map(|p| p.key).collect();
        let mut gone: Vec<ProcessKey> = self
            .by_pid
            .values()
            .map(|e| e.info.key)
            .filter(|k| !alive.contains(k))
            .collect();
        gone.sort();
        for key in gone {
            self.stopped(key, out);
        }
        snapshot.sort_by_key(|p| (p.key.created_at, p.key.pid));
        for p in snapshot {
            self.started(p, out);
        }
    }

    /// 换方案：按创建时间顺序重新判定全部进程，只报告有变化的。
    pub fn set_engine(&mut self, engine: RuleEngine, out: &mut Vec<Change>) {
        self.engine = engine;
        let mut keys: Vec<ProcessKey> = self.by_pid.values().map(|e| e.info.key).collect();
        keys.sort_by_key(|k| (k.created_at, k.pid));
        for key in keys {
            let Some(info) = self.entry(&key).map(|e| e.info.clone()) else {
                continue;
            };
            let (decision, inherited) = self.decide(&info);
            let Some(entry) = self.by_pid.get_mut(&key.pid) else {
                continue;
            };
            let before = (entry.decision.group(), entry.inherited);
            entry.decision = decision;
            entry.inherited = inherited;
            match (before, decision.group()) {
                ((Some(old), was_inherited), Some(new))
                    if old == new && was_inherited == inherited => {}
                (_, Some(group)) => out.push(targeted(&info, group, inherited)),
                ((Some(_), _), None) => out.push(Change::Released { key }),
                ((None, _), None) => {}
            }
        }
    }

    fn entry(&self, key: &ProcessKey) -> Option<&Entry> {
        self.by_pid.get(&key.pid).filter(|e| e.info.key == *key)
    }

    /// 判定结果，以及是否来自继承。
    fn decide(&self, info: &ProcessInfo) -> (Decision, bool) {
        let process = NormalizedProcess::new(&info.name, info.path.as_deref().unwrap_or(""));
        let parent = self
            .by_pid
            .get(&info.parent_pid)
            .filter(|p| p.info.key != info.key)
            .map(|p| ParentInfo {
                decision: p.decision,
                created_at: p.info.key.created_at,
            });
        let own = self.engine.decide(&process);
        let decision = decide_child(&self.engine, &process, info.key.created_at, parent);
        (
            decision,
            own == Decision::Direct && decision.group().is_some(),
        )
    }
}

fn targeted(info: &ProcessInfo, group: usize, inherited: bool) -> Change {
    Change::Targeted {
        key: info.key,
        group,
        inherited,
        name: info.name.clone(),
        path: info.path.clone(),
    }
}

#[cfg(test)]
mod tests;
