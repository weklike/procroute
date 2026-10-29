// SPDX-License-Identifier: GPL-3.0-or-later
//! 不加载驱动的测试：地址布局与解码、加载已校验的 DLL、过滤器语法检查。
//! 打开句柄（会加载驱动）的测试在 `tests/divert_vm.rs`，只在虚拟机里跑（C-TEST-04）。

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use super::*;

/// `cargo xtask fetch-deps` 放好的锁定版本文件。
fn bin_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../third_party/windivert/bin")
}

fn load() -> Arc<WinDivert> {
    WinDivert::load(&bin_dir().canonicalize().unwrap_or_else(|e| {
        panic!("找不到锁定版本的 WinDivert（{e}），先运行 `cargo xtask fetch-deps`")
    }))
    .expect("load the locked WinDivert")
}

#[test]
fn bitfields_decode_like_msvc() {
    // Layer = 3（SOCKET），Event = 4（CONNECT），Sniffed，Outbound，IPv6
    let bits = 3 | (4 << 8) | (1 << 16) | (1 << 17) | (1 << 20);
    let mut a = Address::from_parts(bits, [0; 64]);
    assert_eq!(a.layer(), Layer::Socket as u8);
    assert_eq!(a.event(), event::SOCKET_CONNECT);
    assert!(a.sniffed() && a.outbound() && a.ipv6());
    assert!(!a.loopback() && !a.impostor());
    a.set_outbound(false);
    a.set_impostor(true);
    assert!(!a.outbound() && a.impostor());
    assert_eq!(a.layer(), 3, "other bits are untouched");
}

#[test]
fn endpoint_data_is_read_at_the_c_offsets() {
    let mut d = [0u8; 64];
    d[0..8].copy_from_slice(&0x1122_3344_5566_7788u64.to_ne_bytes());
    d[8..16].copy_from_slice(&7u64.to_ne_bytes());
    d[16..20].copy_from_slice(&4120u32.to_ne_bytes());
    // 本地 127.0.0.1（IPv4 映射）
    for (i, w) in [0x7f00_0001u32, 0x0000_ffff, 0, 0].iter().enumerate() {
        d[20 + 4 * i..24 + 4 * i].copy_from_slice(&w.to_ne_bytes());
    }
    // 远端 2001:db8::1
    let v6 = u128::from(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    for i in 0..4 {
        let w = (v6 >> (32 * i)) as u32;
        d[36 + 4 * i..40 + 4 * i].copy_from_slice(&w.to_ne_bytes());
    }
    d[52..54].copy_from_slice(&50_001u16.to_ne_bytes());
    d[54..56].copy_from_slice(&443u16.to_ne_bytes());
    d[56] = 6;
    let e = Address::from_parts(0, d).endpoint();
    assert_eq!(e.endpoint_id, 0x1122_3344_5566_7788);
    assert_eq!(e.parent_endpoint_id, 7);
    assert_eq!(e.process_id, 4120);
    assert_eq!(e.local_addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(
        e.remote_addr,
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    );
    assert_eq!((e.local_port, e.remote_port, e.protocol), (50_001, 443, 6));

    let mut n = [0u8; 64];
    n[0..4].copy_from_slice(&17u32.to_ne_bytes());
    n[4..8].copy_from_slice(&2u32.to_ne_bytes());
    assert_eq!(
        Address::from_parts(0, n).network(),
        NetworkData {
            if_idx: 17,
            sub_if_idx: 2
        }
    );
}

#[test]
fn the_locked_dll_loads_and_checks_filters() {
    let wd = load();
    assert_eq!(wd.version(), "2.2.2");
    wd.check_filter("outbound and tcp and tcp.DstPort == 443", Layer::Network)
        .expect("valid network filter");
    wd.check_filter("processId == 4120 and event == CONNECT", Layer::Socket)
        .expect("valid socket filter");
    let err = wd
        .check_filter("tcp and banana", Layer::Network)
        .expect_err("invalid");
    assert!(err.position > 0, "{err:?}");
    assert!(!err.message.is_empty());
    assert!(wd.check_filter("tcp\0", Layer::Network).is_err());
}

#[test]
fn tampered_files_are_refused() {
    let dir = std::env::temp_dir().join(format!("procroute-windivert-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let src = bin_dir();
    std::fs::copy(src.join(DLL_FILE_NAME), dir.join(DLL_FILE_NAME)).expect("copy dll");
    std::fs::write(dir.join(DRIVER_FILE_NAME), b"not the locked driver").expect("write sys");
    let err = WinDivert::load(&dir).expect_err("tampered driver");
    assert!(
        matches!(err, DivertError::Library(LibraryError::HashMismatch { .. })),
        "{err:?}"
    );
    std::fs::remove_dir_all(&dir).expect("cleanup");
}
