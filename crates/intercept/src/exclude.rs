// SPDX-License-Identifier: GPL-3.0-or-later
//! 永久排除表（C-NET-05，设计文档 6.5）。
//!
//! 命中排除表的流一律放行、永不改道，否则 sing-box 去往代理服务器的流量会被再次
//! 改道形成环路。排除表由 svc 维护：代理服务器地址变化后整体替换，替换是一次指针
//! 交换，后端在下一条新流上就能看到（满足「1 秒内更新」）。

use std::collections::HashSet;
use std::net::IpAddr;

use crate::flow::ProcessKey;

/// 排除表：ProcRoute 自身的进程与当前代理服务器地址。
///
/// 回环、链路本地、未指定地址不需要登记，[`ExclusionSet::excludes_ip`] 总是排除它们。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExclusionSet {
    /// sing-box、procroute-svc、procroute-ui 自身。
    self_processes: HashSet<ProcessKey>,
    /// 当前代理服务器解析出的全部地址。
    proxy_servers: HashSet<IpAddr>,
}

impl ExclusionSet {
    pub fn new(
        self_processes: impl IntoIterator<Item = ProcessKey>,
        proxy_servers: impl IntoIterator<Item = IpAddr>,
    ) -> Self {
        Self {
            self_processes: self_processes.into_iter().collect(),
            proxy_servers: proxy_servers.into_iter().map(canonical).collect(),
        }
    }

    /// 进程是否属于 ProcRoute 自身。
    pub fn excludes_process(&self, p: &ProcessKey) -> bool {
        self.self_processes.contains(p)
    }

    /// 去往该地址的流是否必须放行。
    pub fn excludes_ip(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        is_always_excluded(ip) || self.proxy_servers.contains(&ip)
    }
}

/// 回环、链路本地、未指定地址：无论配置如何都不改道。
pub fn is_always_excluded(ip: IpAddr) -> bool {
    match canonical(ip) {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unspecified(),
    }
}

/// IPv4 映射的 IPv6 地址（`::ffff:a.b.c.d`）按 IPv4 处理，避免同一地址两种写法绕过排除。
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn loopback_link_local_and_unspecified_are_always_excluded() {
        let empty = ExclusionSet::default();
        for ip in [
            "127.0.0.1",
            "127.8.9.10",
            "169.254.3.4",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "::",
            "::ffff:127.0.0.1",
        ] {
            assert!(empty.excludes_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["203.0.113.24", "10.0.0.1", "2001:db8::1"] {
            assert!(!empty.excludes_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn proxy_server_addresses_are_excluded_in_both_notations() {
        let set = ExclusionSet::new([], [IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7))]);
        assert!(set.excludes_ip("198.51.100.7".parse().unwrap()));
        assert!(set.excludes_ip("::ffff:198.51.100.7".parse().unwrap()));
        assert!(!set.excludes_ip("198.51.100.8".parse().unwrap()));

        let v6 = ExclusionSet::new([], ["::ffff:198.51.100.9".parse::<IpAddr>().unwrap()]);
        assert!(v6.excludes_ip("198.51.100.9".parse().unwrap()));
        let pure_v6 = ExclusionSet::new(
            [],
            [IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5))],
        );
        assert!(pure_v6.excludes_ip("2001:db8::5".parse().unwrap()));
    }

    #[test]
    fn self_processes_match_on_pid_and_creation_time() {
        let svc = ProcessKey {
            pid: 100,
            created_at: 5,
        };
        let set = ExclusionSet::new([svc], []);
        assert!(set.excludes_process(&svc));
        // 同一 PID 被复用给更晚创建的进程：不是自身
        assert!(!set.excludes_process(&ProcessKey {
            pid: 100,
            created_at: 9
        }));
    }
}
