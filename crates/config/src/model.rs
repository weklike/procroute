// SPDX-License-Identifier: GPL-3.0-or-later
//! 方案数据结构（重新导出自 `procroute-proto`）。

pub use procroute_proto::profile::{
    DnsSettings, DnsStrategy, FailPolicy, Group, MatchRule, MatchType, Mode,
    PROFILE_SCHEMA_VERSION, Profile, UdpSettings,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reexported_types_round_trip() {
        let p = Profile {
            schema_version: PROFILE_SCHEMA_VERSION,
            id: "p1".into(),
            name: "浏览器分流".into(),
            mode: Mode::Precise,
            fail_policy: FailPolicy::Block,
            dns: DnsSettings::default(),
            udp: UdpSettings::default(),
            groups: vec![Group {
                tag: "browser".into(),
                outbound: "us-01".into(),
                include_children: false,
                matchers: vec![MatchRule {
                    kind: MatchType::Path,
                    value: r"C:\Program Files\Mozilla Firefox\firefox.exe".into(),
                    recursive: false,
                }],
            }],
            exclude: vec![],
        };
        let json = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<Profile>(&json).unwrap(), p);
    }
}
