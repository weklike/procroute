// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, sync_channel};

use procroute_proto::event::Network;
use procroute_proto::profile::FailPolicy;

use super::*;
use crate::backend::{BypassReason, FlowPolicy, InterceptSettings};

const GAME: ProcessKey = ProcessKey {
    pid: 4120,
    created_at: 10,
};
const BROWSER: ProcessKey = ProcessKey {
    pid: 5000,
    created_at: 11,
};
const SING_BOX: ProcessKey = ProcessKey {
    pid: 900,
    created_at: 1,
};
const PROXY: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

struct Targets(HashMap<ProcessKey, u16>);

impl FlowPolicy for Targets {
    fn target_group(&self, p: &ProcessKey) -> Option<u16> {
        self.0.get(p).copied()
    }
}

fn key(network: Network, local_port: u16, remote: &str) -> FlowKey {
    FlowKey {
        network,
        local: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5)), local_port),
        remote: remote.parse().unwrap(),
    }
}

fn started(settings: InterceptSettings) -> (MockInterceptor, MockHandle, Receiver<FlowEvent>) {
    let (mut backend, handle) = MockInterceptor::new();
    let (tx, rx) = sync_channel(64);
    backend
        .start(StartContext {
            settings,
            exclusions: ExclusionSet::new([SING_BOX], [IpAddr::V4(PROXY)]),
            policy: Arc::new(Targets(HashMap::from([(GAME, 0)]))),
            events: tx,
        })
        .unwrap();
    (backend, handle, rx)
}

#[test]
fn target_flow_is_redirected_and_reported() {
    let (backend, handle, rx) = started(InterceptSettings::default());
    let k = key(Network::Tcp, 50000, "203.0.113.24:443");
    let v = handle
        .new_flow(NewFlow {
            key: k,
            process: Some(GAME),
        })
        .unwrap();
    assert_eq!(v, Verdict::Redirect { group: 0 });
    assert_eq!(
        rx.try_recv().unwrap(),
        FlowEvent::Redirected {
            key: k,
            process: GAME,
            group: 0
        }
    );
    assert_eq!(handle.redirected_flows(), 1);
    assert!(handle.close_flow(k).unwrap());
    assert_eq!(rx.try_recv().unwrap(), FlowEvent::Closed { key: k });
    assert_eq!(backend.stats().redirected, 1);
}

#[test]
fn non_target_and_self_traffic_produce_no_events() {
    let (backend, handle, rx) = started(InterceptSettings::default());
    let browser = NewFlow {
        key: key(Network::Tcp, 50001, "203.0.113.24:443"),
        process: Some(BROWSER),
    };
    assert_eq!(
        handle.new_flow(browser).unwrap(),
        Verdict::Bypass(BypassReason::NotTarget)
    );
    let sing_box_to_proxy = NewFlow {
        key: key(Network::Tcp, 50002, "198.51.100.7:8443"),
        process: Some(SING_BOX),
    };
    assert_eq!(
        handle.new_flow(sing_box_to_proxy).unwrap(),
        Verdict::Bypass(BypassReason::Excluded)
    );
    assert!(rx.try_recv().is_err());
    assert!(!handle.close_flow(browser.key).unwrap());
    assert_eq!(backend.stats().bypassed, 2);
}

#[test]
fn unattributed_flow_counts_attribution_miss() {
    let (backend, handle, _rx) = started(InterceptSettings::default());
    let v = handle
        .new_flow(NewFlow {
            key: key(Network::Tcp, 50003, "203.0.113.24:443"),
            process: None,
        })
        .unwrap();
    assert_eq!(v, Verdict::Bypass(BypassReason::Unattributed));
    assert_eq!(backend.stats().attribution_miss, 1);
}

#[test]
fn unprocessable_target_packets_are_blocked_by_default() {
    let (backend, handle, rx) = started(InterceptSettings::default());
    let k = key(Network::Udp, 50004, "[2001:db8::1]:27015");
    assert_eq!(handle.unprocessable(k, GAME).unwrap(), Some(Verdict::Block));
    assert_eq!(
        rx.try_recv().unwrap(),
        FlowEvent::Blocked {
            key: k,
            process: Some(GAME)
        }
    );
    // 非目标进程的包不归我们管
    assert_eq!(handle.unprocessable(k, BROWSER).unwrap(), None);
    assert_eq!(backend.stats().blocked, 1);
}

#[test]
fn unprocessable_target_packets_pass_only_with_explicit_allow() {
    let settings = InterceptSettings {
        fail_policy: FailPolicy::Allow,
        ..InterceptSettings::default()
    };
    let (_backend, handle, rx) = started(settings);
    let k = key(Network::Udp, 50005, "[2001:db8::1]:27015");
    assert_eq!(
        handle.unprocessable(k, GAME).unwrap(),
        Some(Verdict::Bypass(BypassReason::FailOpen))
    );
    assert!(rx.try_recv().is_err());
}

#[test]
fn exclusion_update_takes_effect_on_the_next_flow() {
    let (mut backend, handle, _rx) = started(InterceptSettings::default());
    let to_new_proxy = NewFlow {
        key: key(Network::Tcp, 50006, "192.0.2.50:443"),
        process: Some(GAME),
    };
    assert_eq!(
        handle.new_flow(to_new_proxy).unwrap(),
        Verdict::Redirect { group: 0 }
    );
    backend
        .update_exclusions(ExclusionSet::new(
            [SING_BOX],
            [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50))],
        ))
        .unwrap();
    assert_eq!(
        handle.new_flow(to_new_proxy).unwrap(),
        Verdict::Bypass(BypassReason::Excluded)
    );
}

#[test]
fn stop_withdraws_filters_and_rejects_further_flows() {
    let (mut backend, handle, _rx) = started(InterceptSettings::default());
    let k = key(Network::Tcp, 50007, "203.0.113.24:443");
    handle
        .new_flow(NewFlow {
            key: k,
            process: Some(GAME),
        })
        .unwrap();
    assert_eq!(handle.installed_filters(), 1);
    backend.stop().unwrap();
    assert!(!backend.is_active());
    assert_eq!(handle.installed_filters(), 0);
    assert_eq!(handle.redirected_flows(), 0);
    assert_eq!(
        handle.new_flow(NewFlow {
            key: k,
            process: Some(GAME)
        }),
        Err(InterceptError::NotRunning)
    );
    assert_eq!(backend.stop(), Err(InterceptError::NotRunning));
}

#[test]
fn drop_withdraws_filters() {
    let (backend, handle, _rx) = started(InterceptSettings::default());
    assert_eq!(handle.installed_filters(), 1);
    drop(backend);
    assert_eq!(handle.installed_filters(), 0);
}

#[test]
fn double_start_is_rejected() {
    let (mut backend, _handle, _rx) = started(InterceptSettings::default());
    let (tx, _rx2) = sync_channel(1);
    let err = backend
        .start(StartContext {
            settings: InterceptSettings::default(),
            exclusions: ExclusionSet::default(),
            policy: Arc::new(Targets(HashMap::new())),
            events: tx,
        })
        .unwrap_err();
    assert_eq!(err, InterceptError::AlreadyRunning);
}

#[test]
fn works_behind_a_trait_object() {
    let (backend, handle) = MockInterceptor::new();
    let mut boxed: Box<dyn Interceptor> = Box::new(backend);
    assert_eq!(boxed.name(), "mock");
    assert!(!boxed.is_active());
    let (tx, _rx) = sync_channel(1);
    boxed
        .start(StartContext {
            settings: InterceptSettings::default(),
            exclusions: ExclusionSet::default(),
            policy: Arc::new(Targets(HashMap::new())),
            events: tx,
        })
        .unwrap();
    assert_eq!(handle.installed_filters(), 1);
}
