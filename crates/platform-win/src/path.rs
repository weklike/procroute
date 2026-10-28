// SPDX-License-Identifier: GPL-3.0-or-later
//! NT 设备路径转 DOS 路径、8.3 短名展开（T-052，C-DRV-04）。
//!
//! 内核侧（ETW、WinDivert）给出的进程映像路径是 `\Device\HarddiskVolume3\…` 形式，
//! 用户在方案里写的是 `C:\…`，有的路径还带 `PROGRA~1` 这样的 8.3 短名。比较之前先在这里
//! 统一成 DOS 长路径，再交给 `procroute-rules` 做与平台无关的规范化（大小写、分隔符等）：
//! [`normalize_process_path`] 是两步合起来的入口。
#![allow(unsafe_code)] // 需要调用 QueryDosDeviceW / GetLongPathNameW；每处都有 SAFETY 注释

use windows_sys::Win32::Storage::FileSystem::{GetLongPathNameW, QueryDosDeviceW};

use crate::wide::{from_wide, to_wide};

/// 一个盘符对应的内核设备名，例如 `C:` → `\Device\HarddiskVolume3`。
#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceEntry {
    /// 小写的设备名，用于前缀比较。
    device_lower: String,
    /// 盘符，例如 `C:`。
    drive: String,
}

/// 盘符与内核设备名的对照表。
///
/// 盘符映射很少变化（插拔 U 盘、挂载卷时才变），调用方持有一份快照，
/// 收到卷变化通知或定期调用 [`DosDeviceMap::query`] 重建。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DosDeviceMap {
    entries: Vec<DeviceEntry>,
}

const NT_UNC_PREFIXES: [&str; 2] = [r"\device\mup\", r"\device\lanmanredirector\"];

impl DosDeviceMap {
    /// 查询 `A:` 到 `Z:` 当前对应的设备名。
    ///
    /// `subst` 出来的盘符指向 `\??\D:\dir` 这样的另一条 DOS 路径而不是设备，跳过它们：
    /// 内核给出的路径总是落在真实卷上，映射回真实卷的盘符才能和用户写的路径对上。
    pub fn query() -> Self {
        let mut map = Self::default();
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:", char::from(letter));
            if let Some(device) = query_dos_device(&drive)
                && device.starts_with(r"\Device\")
            {
                map.insert(&drive, &device);
            }
        }
        map
    }

    /// 由给定的（盘符, 设备名）构造，供测试与调用方注入。
    pub fn from_entries<'a>(entries: impl IntoIterator<Item = (&'a str, &'a str)>) -> Self {
        let mut map = Self::default();
        for (drive, device) in entries {
            map.insert(drive, device);
        }
        map
    }

    fn insert(&mut self, drive: &str, device: &str) {
        let device_lower = device.trim_end_matches('\\').to_lowercase();
        // 长的设备名优先匹配，避免 `\Device\HarddiskVolume1` 吃掉 `\Device\HarddiskVolume10`
        // 的前缀（匹配时还要求设备名后面是分隔符，这里排序只是让行为确定）。
        let at = self
            .entries
            .iter()
            .position(|e| e.device_lower.len() < device_lower.len())
            .unwrap_or(self.entries.len());
        self.entries.insert(
            at,
            DeviceEntry {
                device_lower,
                drive: drive.to_owned(),
            },
        );
    }

    /// 把 NT 路径转成 DOS 路径；本来就是 DOS 路径或无法识别的输入原样返回。
    ///
    /// 处理的形式：
    /// - `\Device\HarddiskVolumeN\…` → `C:\…`（按对照表）；
    /// - `\Device\Mup\server\share\…`、`\Device\LanmanRedirector\;Z:…\server\share\…` → `\\server\share\…`；
    /// - `\??\C:\…`、`\\?\C:\…` → `C:\…`；`\??\UNC\…`、`\\?\UNC\…` → `\\…`；
    /// - `\SystemRoot\…` → Windows 目录下的对应路径。
    pub fn to_dos_path(&self, raw: &str) -> String {
        let path = raw.trim();
        for prefix in [r"\??\", r"\\?\"] {
            if let Some(rest) = strip_prefix_ci(path, prefix) {
                return match strip_prefix_ci(rest, r"UNC\") {
                    Some(unc) => format!(r"\\{unc}"),
                    None => rest.to_owned(),
                };
            }
        }
        if let Some(rest) = strip_prefix_ci(path, r"\SystemRoot\")
            && let Some(windir) = windows_dir()
        {
            return format!(r"{}\{rest}", windir.trim_end_matches('\\'));
        }
        for prefix in NT_UNC_PREFIXES {
            if let Some(rest) = strip_prefix_ci(path, prefix) {
                // LanmanRedirector 的第一段是 `;Z:0000000000012345` 这样的会话标记，丢掉。
                let rest = match rest.strip_prefix(';') {
                    Some(tagged) => tagged.split_once('\\').map_or("", |(_, r)| r),
                    None => rest,
                };
                return format!(r"\\{rest}");
            }
        }
        let lower = path.to_lowercase();
        for e in &self.entries {
            if let Some(tail) = lower.strip_prefix(&e.device_lower)
                && (tail.is_empty() || tail.starts_with('\\'))
            {
                // 小写只用于比较；尾部保留原始大小写。设备名都是 ASCII，字节偏移一致。
                let tail = &path[e.device_lower.len()..];
                return if tail.is_empty() {
                    format!(r"{}\", e.drive)
                } else {
                    format!("{}{tail}", e.drive)
                };
            }
        }
        path.to_owned()
    }
}

/// 展开路径中的 8.3 短名，例如 `C:\PROGRA~1\x.exe` → `C:\Program Files\x.exe`。
///
/// 需要文件仍然存在；文件已删除、无权访问或卷关闭了 8.3 名称时原样返回。
pub fn expand_short_names(path: &str) -> String {
    // 没有 `~` 就不可能含短名，省一次系统调用。
    if !path.contains('~') {
        return path.to_owned();
    }
    let wide = to_wide(path);
    let mut buf = vec![0u16; 260];
    for _ in 0..2 {
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `wide` 以 NUL 结尾且在调用期间存活；`buf` 可写 `cap` 个 u16。
        let n = unsafe { GetLongPathNameW(wide.as_ptr(), buf.as_mut_ptr(), cap) } as usize;
        if n == 0 {
            return path.to_owned();
        }
        if n < buf.len() {
            return from_wide(&buf[..n]);
        }
        // 缓冲区不够时返回值是所需长度（含 NUL），扩容后再试一次。
        buf = vec![0u16; n];
    }
    path.to_owned()
}

/// 进程映像路径的完整规范化：NT→DOS、展开 8.3 短名，再做 `procroute-rules` 的规范化。
///
/// 结果可以直接和方案里经 `normalize_path` 处理过的路径比较。
pub fn normalize_process_path(map: &DosDeviceMap, raw: &str) -> String {
    let dos = map.to_dos_path(raw);
    procroute_rules::path::normalize_path(&expand_short_names(&dos))
}

fn query_dos_device(drive: &str) -> Option<String> {
    let name = to_wide(drive);
    let mut buf = vec![0u16; 1024];
    let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    // SAFETY: `name` 以 NUL 结尾；`buf` 可写 `cap` 个 u16。返回 0 表示失败（盘符未映射）。
    let n = unsafe { QueryDosDeviceW(name.as_ptr(), buf.as_mut_ptr(), cap) } as usize;
    if n == 0 {
        return None;
    }
    // 结果是以双 NUL 结尾的字符串列表，第一项是当前生效的映射。
    let first = buf[..n].split(|&c| c == 0).next()?;
    (!first.is_empty()).then(|| from_wide(first))
}

fn windows_dir() -> Option<String> {
    std::env::var("SystemRoot")
        .ok()
        .or_else(|| std::env::var("windir").ok())
}

/// ASCII 大小写不敏感地去掉前缀。前缀都是 ASCII，按字节切分不会落在字符中间。
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

#[cfg(test)]
mod tests {
    use windows_sys::Win32::Storage::FileSystem::GetShortPathNameW;

    use super::*;

    fn system_drive_and_windir() -> (String, String) {
        let windir = windows_dir().expect("SystemRoot is always set on Windows");
        (windir[..2].to_owned(), windir)
    }

    fn short_path(long: &str) -> String {
        let wide = to_wide(long);
        let mut buf = vec![0u16; 1024];
        // SAFETY: `wide` 以 NUL 结尾；`buf` 可写 1024 个 u16。
        let n = unsafe { GetShortPathNameW(wide.as_ptr(), buf.as_mut_ptr(), 1024) } as usize;
        assert!(
            n > 0 && n < buf.len(),
            "GetShortPathNameW failed for {long}"
        );
        from_wide(&buf[..n])
    }

    #[test]
    fn maps_volume_devices_with_separator_boundary() {
        let map = DosDeviceMap::from_entries([
            ("C:", r"\Device\HarddiskVolume1"),
            ("D:", r"\Device\HarddiskVolume10"),
        ]);
        assert_eq!(
            map.to_dos_path(r"\Device\HarddiskVolume1\Program Files\App.exe"),
            r"C:\Program Files\App.exe"
        );
        assert_eq!(
            map.to_dos_path(r"\device\harddiskvolume10\Games\x.exe"),
            r"D:\Games\x.exe"
        );
        assert_eq!(map.to_dos_path(r"\Device\HarddiskVolume1"), r"C:\");
        // 没有映射的卷原样返回，不会被错配到前缀相同的卷上。
        assert_eq!(
            map.to_dos_path(r"\Device\HarddiskVolume11\x.exe"),
            r"\Device\HarddiskVolume11\x.exe"
        );
    }

    #[test]
    fn maps_prefixed_and_network_forms() {
        let map = DosDeviceMap::default();
        let cases = [
            (r"\??\C:\Games\x.exe", r"C:\Games\x.exe"),
            (r"\\?\C:\Games\x.exe", r"C:\Games\x.exe"),
            (r"\??\UNC\srv\share\x.exe", r"\\srv\share\x.exe"),
            (r"\\?\unc\srv\share\x.exe", r"\\srv\share\x.exe"),
            (r"\Device\Mup\srv\share\x.exe", r"\\srv\share\x.exe"),
            (
                r"\Device\LanmanRedirector\;Z:0000000000012345\srv\share\x.exe",
                r"\\srv\share\x.exe",
            ),
            (r"D:\Already\Dos.exe", r"D:\Already\Dos.exe"),
            ("launcher.exe", "launcher.exe"),
        ];
        for (raw, want) in cases {
            assert_eq!(map.to_dos_path(raw), want, "input {raw:?}");
        }
    }

    #[test]
    fn system_root_expands_to_windows_dir() {
        let (_, windir) = system_drive_and_windir();
        let map = DosDeviceMap::default();
        assert_eq!(
            map.to_dos_path(r"\SystemRoot\System32\ntdll.dll"),
            format!(r"{windir}\System32\ntdll.dll")
        );
    }

    #[test]
    fn real_system_drive_device_path_maps_back() {
        let (drive, windir) = system_drive_and_windir();
        let map = DosDeviceMap::query();
        let device = query_dos_device(&drive).expect("system drive has a device");
        let nt = format!(r"{device}{}\System32\kernel32.dll", &windir[2..]);
        let dos = map.to_dos_path(&nt);
        assert_eq!(dos, format!(r"{windir}\System32\kernel32.dll"));
        assert!(std::path::Path::new(&dos).exists(), "{dos}");
    }

    #[test]
    fn real_short_names_expand_to_long_names() {
        let dir = std::env::temp_dir().join("procroute long name test dir");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let file = dir.join("a rather long file name.txt");
        std::fs::write(&file, b"x").expect("create temp file");
        let long = expand_short_names(&short_path(&file.to_string_lossy()));
        // 卷关闭 8.3 名称时短名就是长名本身，两种情况结论都必须是同一个文件。
        assert_eq!(
            procroute_rules::path::normalize_path(&long),
            procroute_rules::path::normalize_path(&expand_short_names(&file.to_string_lossy()))
        );
        assert!(long.ends_with("a rather long file name.txt"), "{long}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn program_files_short_name_expands() {
        let pf = std::env::var("ProgramFiles").expect("ProgramFiles is set");
        let short = short_path(&pf);
        assert_eq!(expand_short_names(&short).to_lowercase(), pf.to_lowercase());
    }

    #[test]
    fn missing_files_are_left_untouched() {
        let p = r"C:\NO_SUCH~1\NOPE~1.EXE";
        assert_eq!(expand_short_names(p), p);
    }

    #[test]
    fn full_pipeline_matches_rules_normalization() {
        let (drive, windir) = system_drive_and_windir();
        let map = DosDeviceMap::query();
        let device = query_dos_device(&drive).expect("system drive has a device");
        let nt = format!(r"{device}{}\SYSTEM32\Notepad.EXE", &windir[2..]);
        assert_eq!(
            normalize_process_path(&map, &nt),
            procroute_rules::path::normalize_path(&format!(r"{windir}\System32\notepad.exe"))
        );
    }
}
