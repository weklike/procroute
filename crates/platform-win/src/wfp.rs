// SPDX-License-Identifier: GPL-3.0-or-later
//! TUN 模式的 fail-closed（C-NET-03）：服务持有的动态 WFP 过滤器。
//!
//! sing-box 一退出（崩溃、重启间隙、超出重启上限），TUN 网卡与路由随之撤销，目标进程会回落直连。
//! 这里为每个目标可执行文件在 `ALE_AUTH_CONNECT`（IPv4 / IPv6）层装三条过滤器：
//!
//! 1. 放行：本地地址在 TUN 网段内（连接正经 TUN 走，sing-box 在运行）；
//! 2. 放行：远端是回环、链路本地或组播（与 TUN 配置里的永久直连一致，C-NET-05）；
//! 3. 阻断：其余全部（sing-box 不在时连接从物理网卡发出）。
//!
//! 同一子层里权重高的匹配项决定结果，所以只需要「等于」匹配。按本地地址而不是网卡判断，TUN 网卡重建后
//! LUID 变了也不受影响。会话是动态的：服务关闭句柄或进程退出时，系统删除这里加的全部对象，不会留下
//! 持久的过滤器（C-NET-06）。只影响列出的可执行文件，其他进程不受影响（C-NET-02）。
//!
//! 加过滤器需要管理员权限，且会改变网络行为：相关测试只在虚拟机里跑（`--features vm-tests`，C-TEST-04）。
#![allow(unsafe_code)] // 需要调用 Fwpm* 系列函数；每处都有 SAFETY 注释

use std::ffi::c_void;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_CONDITION_VALUE0,
    FWP_CONDITION_VALUE0_0, FWP_MATCH_EQUAL, FWP_UINT8, FWP_V4_ADDR_AND_MASK, FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_AND_MASK, FWP_V6_ADDR_MASK, FWP_VALUE0, FWP_VALUE0_0, FWPM_ACTION0, FWPM_ACTION0_0,
    FWPM_CONDITION_ALE_APP_ID, FWPM_CONDITION_IP_LOCAL_ADDRESS, FWPM_CONDITION_IP_REMOTE_ADDRESS,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_NONE, FWPM_FILTER0,
    FWPM_FILTER0_0, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0, FwpmEngineClose0, FwpmEngineOpen0,
    FwpmFilterAdd0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmSubLayerAdd0,
    FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
};
use windows_sys::core::GUID;

use crate::wide::to_wide;

/// `RPC_C_AUTHN_WINNT`：本机引擎用 Windows 身份认证。
const RPC_C_AUTHN_WINNT: u32 = 10;

/// 本模块子层的标识（固定值，便于排查时识别）。
pub const SUBLAYER_KEY: GUID = GUID::from_u128(0x6f1c_2b84_5a0e_4c1d_9b7e_2d4a_0c6e_91f3);

/// 子层权重：高于大多数第三方子层，确保阻断被评估到。
const SUBLAYER_WEIGHT: u16 = 0x7fff;

/// 子层内各过滤器的权重：放行高于阻断。
const WEIGHT_PERMIT_TUN: u8 = 15;
const WEIGHT_PERMIT_LOCAL: u8 = 14;
const WEIGHT_BLOCK: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{call} failed with error {code:#010x}")]
pub struct WfpError {
    pub call: &'static str,
    pub code: u32,
}

fn check(call: &'static str, code: u32) -> Result<(), WfpError> {
    if code == 0 {
        Ok(())
    } else {
        Err(WfpError { call, code })
    }
}

/// TUN 网段：本地地址落在这里的连接正经 TUN 走。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunRanges {
    pub v4: (Ipv4Addr, u8),
    pub v6: (Ipv6Addr, u8),
}

/// 动态 WFP 会话。丢弃（或进程退出）时系统删除其中的全部过滤器与子层。
#[derive(Debug)]
pub struct FailClosedFilters {
    engine: HANDLE,
    tun: TunRanges,
}

// SAFETY: 引擎句柄可以在线程间传递；本类型的方法都要 `&mut self`，同一时刻只有一个线程使用它。
unsafe impl Send for FailClosedFilters {}

impl FailClosedFilters {
    /// 打开动态会话并添加子层。需要管理员权限。
    pub fn open(tun: TunRanges) -> Result<Self, WfpError> {
        let name = to_wide("ProcRoute fail-closed");
        // SAFETY: FWPM_SESSION0 是纯数据结构，全零合法；下面填上需要的字段。
        let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        session.displayData.name = name.as_ptr().cast_mut();
        let mut engine: HANDLE = ptr::null_mut();
        // SAFETY: 本机引擎（服务器名为空）；认证身份为空表示当前进程身份；`session` 与其中的名字在调用期间有效。
        check("FwpmEngineOpen0", unsafe {
            FwpmEngineOpen0(
                ptr::null(),
                RPC_C_AUTHN_WINNT,
                ptr::null(),
                &session,
                &mut engine,
            )
        })?;
        let filters = Self { engine, tun };
        // SAFETY: 全零的子层结构合法；下面填上需要的字段。
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
        sublayer.subLayerKey = SUBLAYER_KEY;
        sublayer.displayData = FWPM_DISPLAY_DATA0 {
            name: name.as_ptr().cast_mut(),
            description: ptr::null_mut(),
        };
        sublayer.weight = SUBLAYER_WEIGHT;
        // SAFETY: 引擎句柄有效；`sublayer` 与名字在调用期间有效；不设安全描述符。
        check("FwpmSubLayerAdd0", unsafe {
            FwpmSubLayerAdd0(filters.engine, &sublayer, ptr::null_mut())
        })?;
        Ok(filters)
    }

    /// 为一个可执行文件装上 fail-closed 过滤器（IPv4 与 IPv6 各三条，一个事务内完成）。
    pub fn protect(&mut self, exe: &Path) -> Result<(), WfpError> {
        let app = AppId::from_path(exe)?;
        // SAFETY: 引擎句柄有效；标志 0 表示读写事务。
        check("FwpmTransactionBegin0", unsafe {
            FwpmTransactionBegin0(self.engine, 0)
        })?;
        match self.add_all(&app) {
            Ok(()) => {
                // SAFETY: 引擎句柄有效，上面开启了事务。
                check("FwpmTransactionCommit0", unsafe {
                    FwpmTransactionCommit0(self.engine)
                })
            }
            Err(e) => {
                // SAFETY: 同上；放弃事务里已经加的过滤器。
                unsafe { FwpmTransactionAbort0(self.engine) };
                Err(e)
            }
        }
    }

    fn add_all(&self, app: &AppId) -> Result<(), WfpError> {
        let (v4, v4_len) = self.tun.v4;
        let (v6, v6_len) = self.tun.v6;
        let mut tun4 = v4_mask(v4, v4_len);
        let mut tun6 = v6_mask(v6, v6_len);
        let mut local4 = [
            v4_mask(Ipv4Addr::new(127, 0, 0, 0), 8),
            v4_mask(Ipv4Addr::new(169, 254, 0, 0), 16),
            v4_mask(Ipv4Addr::new(224, 0, 0, 0), 4),
            v4_mask(Ipv4Addr::BROADCAST, 32),
        ];
        let mut local6 = [
            v6_mask(Ipv6Addr::LOCALHOST, 128),
            v6_mask(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
            v6_mask(Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
        ];
        let app_cond = || app.condition();

        // IPv4
        let mut c = [app_cond(), local_v4(&mut tun4)];
        self.add(
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &mut c,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT_TUN,
        )?;
        let mut c: Vec<_> = std::iter::once(app_cond())
            .chain(local4.iter_mut().map(remote_v4))
            .collect();
        self.add(
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &mut c,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT_LOCAL,
        )?;
        let mut c = [app_cond()];
        self.add(
            FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            &mut c,
            FWP_ACTION_BLOCK,
            WEIGHT_BLOCK,
        )?;

        // IPv6
        let mut c = [app_cond(), local_v6(&mut tun6)];
        self.add(
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            &mut c,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT_TUN,
        )?;
        let mut c: Vec<_> = std::iter::once(app_cond())
            .chain(local6.iter_mut().map(remote_v6))
            .collect();
        self.add(
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            &mut c,
            FWP_ACTION_PERMIT,
            WEIGHT_PERMIT_LOCAL,
        )?;
        let mut c = [app_cond()];
        self.add(
            FWPM_LAYER_ALE_AUTH_CONNECT_V6,
            &mut c,
            FWP_ACTION_BLOCK,
            WEIGHT_BLOCK,
        )
    }

    /// 加一条过滤器。同一字段的多个条件之间是「或」，不同字段之间是「与」。
    fn add(
        &self,
        layer: GUID,
        conditions: &mut [FWPM_FILTER_CONDITION0],
        action: u32,
        weight: u8,
    ) -> Result<(), WfpError> {
        let name = to_wide("ProcRoute fail-closed");
        // SAFETY: 全零的过滤器结构合法；下面填上需要的字段。
        let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
        filter.displayData.name = name.as_ptr().cast_mut();
        filter.flags = FWPM_FILTER_FLAG_NONE;
        filter.layerKey = layer;
        filter.subLayerKey = SUBLAYER_KEY;
        filter.weight = FWP_VALUE0 {
            r#type: FWP_UINT8,
            Anonymous: FWP_VALUE0_0 { uint8: weight },
        };
        filter.numFilterConditions = conditions.len() as u32;
        filter.filterCondition = conditions.as_mut_ptr();
        filter.action = FWPM_ACTION0 {
            r#type: action,
            Anonymous: FWPM_ACTION0_0 {
                filterType: GUID::from_u128(0),
            },
        };
        filter.Anonymous = FWPM_FILTER0_0 { rawContext: 0 };
        let mut id = 0u64;
        // SAFETY: 引擎句柄有效；`filter` 及其指向的条件数组、条件里的地址与应用 ID 在调用期间都有效；
        // 不设安全描述符。
        check("FwpmFilterAdd0", unsafe {
            FwpmFilterAdd0(self.engine, &filter, ptr::null_mut(), &mut id)
        })
    }
}

impl Drop for FailClosedFilters {
    fn drop(&mut self) {
        // SAFETY: 引擎句柄由 FwpmEngineOpen0 返回，只在这里关闭一次；动态会话里的对象随之删除。
        unsafe { FwpmEngineClose0(self.engine) };
    }
}

/// `FwpmGetAppIdFromFileName0` 返回的应用 ID（设备路径形式），由 WFP 分配，丢弃时释放。
struct AppId(*mut FWP_BYTE_BLOB);

impl AppId {
    fn from_path(exe: &Path) -> Result<Self, WfpError> {
        let wide = to_wide(&exe.to_string_lossy());
        let mut blob: *mut FWP_BYTE_BLOB = ptr::null_mut();
        // SAFETY: `wide` 以 NUL 结尾；成功时 `blob` 指向 WFP 分配的内存，由 Drop 释放。
        check("FwpmGetAppIdFromFileName0", unsafe {
            FwpmGetAppIdFromFileName0(wide.as_ptr(), &mut blob)
        })?;
        Ok(Self(blob))
    }

    fn condition(&self) -> FWPM_FILTER_CONDITION0 {
        FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_ALE_APP_ID,
            matchType: FWP_MATCH_EQUAL,
            conditionValue: FWP_CONDITION_VALUE0 {
                r#type: FWP_BYTE_BLOB_TYPE,
                Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: self.0 },
            },
        }
    }

    #[cfg(test)]
    fn len(&self) -> u32 {
        // SAFETY: 成功创建时 `self.0` 指向有效的 FWP_BYTE_BLOB。
        unsafe { (*self.0).size }
    }
}

impl Drop for AppId {
    fn drop(&mut self) {
        let mut p = self.0.cast::<c_void>();
        // SAFETY: 内存由 FwpmGetAppIdFromFileName0 分配，只在这里释放一次。
        unsafe { FwpmFreeMemory0(&mut p) };
    }
}

fn v4_mask(addr: Ipv4Addr, prefix: u8) -> FWP_V4_ADDR_AND_MASK {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    // WFP 的 IPv4 地址与掩码都是主机字节序
    FWP_V4_ADDR_AND_MASK {
        addr: u32::from(addr) & mask,
        mask,
    }
}

fn v6_mask(addr: Ipv6Addr, prefix: u8) -> FWP_V6_ADDR_AND_MASK {
    FWP_V6_ADDR_AND_MASK {
        addr: addr.octets(),
        prefixLength: prefix.min(128),
    }
}

fn addr_condition(field: GUID, kind: i32, value: FWP_CONDITION_VALUE0_0) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}

fn local_v4(m: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    addr_condition(
        FWPM_CONDITION_IP_LOCAL_ADDRESS,
        FWP_V4_ADDR_MASK,
        FWP_CONDITION_VALUE0_0 { v4AddrMask: m },
    )
}

fn remote_v4(m: &mut FWP_V4_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    addr_condition(
        FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWP_V4_ADDR_MASK,
        FWP_CONDITION_VALUE0_0 { v4AddrMask: m },
    )
}

fn local_v6(m: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    addr_condition(
        FWPM_CONDITION_IP_LOCAL_ADDRESS,
        FWP_V6_ADDR_MASK,
        FWP_CONDITION_VALUE0_0 { v6AddrMask: m },
    )
}

fn remote_v6(m: &mut FWP_V6_ADDR_AND_MASK) -> FWPM_FILTER_CONDITION0 {
    addr_condition(
        FWPM_CONDITION_IP_REMOTE_ADDRESS,
        FWP_V6_ADDR_MASK,
        FWP_CONDITION_VALUE0_0 { v6AddrMask: m },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_masks_are_host_order_and_truncate_the_address() {
        let m = v4_mask(Ipv4Addr::new(198, 18, 0, 1), 30);
        assert_eq!(m.mask, 0xffff_fffc);
        assert_eq!(m.addr, u32::from(Ipv4Addr::new(198, 18, 0, 0)));
        let all = v4_mask(Ipv4Addr::BROADCAST, 32);
        assert_eq!((all.addr, all.mask), (u32::MAX, u32::MAX));
        assert_eq!(v4_mask(Ipv4Addr::new(10, 0, 0, 1), 0).mask, 0);
    }

    #[test]
    fn v6_masks_keep_the_prefix() {
        let m = v6_mask(Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 1), 126);
        assert_eq!(m.prefixLength, 126);
        assert_eq!(m.addr[0..2], [0xfd, 0xfe]);
        assert_eq!(v6_mask(Ipv6Addr::LOCALHOST, 200).prefixLength, 128);
    }

    #[test]
    fn app_ids_come_from_existing_executables_only() {
        // 只转换路径，不碰过滤引擎，也不需要管理员权限
        let exe = std::env::current_exe().expect("current exe");
        let app = AppId::from_path(&exe).expect("app id");
        assert!(app.len() > 0);
        assert!(AppId::from_path(Path::new(r"C:\no\such\program.exe")).is_err());
    }
}
