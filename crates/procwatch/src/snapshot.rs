// SPDX-License-Identifier: GPL-3.0-or-later
//! Toolhelp 进程快照，附「PID + 创建时间」身份与完整路径（设计文档 6.4：启动与切换方案时补登）。

use std::io;

use procroute_platform_win::path::expand_short_names;
use procroute_platform_win::process::{
    list_processes, process_creation_time, process_image_path_checked,
};

use crate::tree::{ProcessInfo, ProcessKey};

/// 当前运行的全部进程。`known` 返回 `true` 的进程（已登记过）不再查路径，省掉每轮的路径查询。
/// 查不到创建时间的进程（Idle 等打不开的系统进程，或刚好已经退出）跳过。
pub fn take(known: impl Fn(&ProcessKey) -> bool) -> io::Result<Vec<ProcessInfo>> {
    let entries = list_processes()?;
    Ok(entries
        .into_iter()
        .filter_map(|e| {
            let created_at = process_creation_time(e.pid).ok()?;
            let key = ProcessKey {
                pid: e.pid,
                created_at,
            };
            let path = if known(&key) { None } else { image_path(key) };
            Some(ProcessInfo {
                key,
                parent_pid: e.parent_pid,
                name: e.name,
                path,
            })
        })
        .collect())
}

/// 进程的完整 Win32 路径，8.3 短名已展开（C-DRV-04）。PID 已被复用或进程已退出时为 `None`。
pub fn image_path(key: ProcessKey) -> Option<String> {
    let path = process_image_path_checked(key.pid, key.created_at).ok()?;
    Some(if path.contains('~') {
        expand_short_names(&path)
    } else {
        path
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_process_is_listed_with_its_identity_and_path() {
        let me = std::process::id();
        let all = take(|_| false).expect("snapshot");
        let entry = all.iter().find(|p| p.key.pid == me).expect("this process");
        assert_eq!(
            entry.key.created_at,
            process_creation_time(me).expect("creation time")
        );
        let exe = std::env::current_exe().expect("current exe");
        assert_eq!(
            entry.path.as_deref().map(str::to_lowercase),
            Some(exe.to_string_lossy().to_lowercase())
        );
        // 已登记的进程不再查路径
        let again = take(|k| k.pid == me).expect("snapshot");
        let entry = again
            .iter()
            .find(|p| p.key.pid == me)
            .expect("this process");
        assert_eq!(entry.path, None);
    }
}
