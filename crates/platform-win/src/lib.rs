// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows 平台封装（T-050）。
//!
//! 本 crate 是除 `intercept::*::ffi` 之外唯一允许出现 `unsafe` 的地方（C-CODE-01）：
//! crate 级别 `unsafe_code = "deny"`，只有需要调用 Win32 API 的模块用
//! `#![allow(unsafe_code)]` 局部放开，每处 `unsafe` 块上方必须有 `// SAFETY:` 注释
//! （由 `clippy::undocumented_unsafe_blocks` 强制）。
//!
//! 模块划分：
//!
//! - [`secret`]：凭据包装，跨平台；
//! - `path`：NT 设备路径转 DOS 路径、8.3 短名展开（T-052，仅 Windows）；
//! - `dpapi`：机器范围 DPAPI 加解密（T-053，仅 Windows）；
//! - `acl`：控制管道的安全描述符与管道实例创建（T-054，仅 Windows）；
//! - `dir_acl`：配置目录的受保护 DACL 与所有者检查（T-058，C-SEC-05，仅 Windows）；
//! - `process`：管道客户端 PID、进程映像路径与用户 SID、创建时间（T-057、T-079，仅 Windows）；
//! - `etw`：`Microsoft-Windows-Kernel-Process` 的进程启动 / 退出实时事件（T-079，仅 Windows）；
//! - `authenticode`：内嵌签名校验与签名主体（T-057，仅 Windows）；
//! - `service`：服务控制分派器与状态上报（T-057，仅 Windows）；
//! - `hash`：SHA-256，按锁文件校验第三方二进制（C-DEP-04、C-SEC-06，仅 Windows）；
//! - `http`：WinHTTP 的 GET，拉取订阅（C-SEC-07，仅 Windows）；
//! - `library`：按哈希锁定的文件与按完整路径加载的已校验 DLL（C-DRV-01、C-DRV-02，仅 Windows）；
//! - `job`：关闭即终止的作业对象，sing-box 随服务退出（T-056，C-NET-06，仅 Windows）；
//! - `privileges`：服务启动后移除用不到的令牌特权（C-SEC-06，仅 Windows）；
//! - `wfp`：TUN 模式 fail-closed 用的动态 WFP 过滤器（C-NET-03、C-NET-06，仅 Windows）；
//! - `random`：系统 CSPRNG，生成每次启动的控制 API 密钥（T-056，C-NET-08，仅 Windows）；
//! - `os`：系统版本与内存完整性开关，写进诊断包（T-112，仅 Windows）。

pub mod secret;

#[cfg(windows)]
pub mod acl;
#[cfg(windows)]
pub mod authenticode;
#[cfg(windows)]
pub mod dir_acl;
#[cfg(windows)]
pub mod dpapi;
#[cfg(windows)]
pub mod etw;
#[cfg(windows)]
pub mod hash;
#[cfg(windows)]
pub mod http;
#[cfg(windows)]
pub mod job;
#[cfg(windows)]
pub mod library;
#[cfg(windows)]
pub mod os;
#[cfg(windows)]
pub mod path;
#[cfg(windows)]
pub mod privileges;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
pub mod random;
#[cfg(windows)]
pub mod service;
#[cfg(windows)]
pub mod wfp;
#[cfg(windows)]
mod wide;
