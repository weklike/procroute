// SPDX-License-Identifier: GPL-3.0-or-later
//! WinDivert 后端：精确进程模式的默认拦截后端（设计文档 4.1、6.1；T-071 起，仅 Windows）。
//!
//! - [`lock`]：编译进来的版本锁，加载前据此校验 DLL 与驱动；
//! - [`ffi`]：动态加载 `WinDivert.dll` 与句柄封装，本 crate 里唯一允许 `unsafe` 的模块（C-CODE-01）；
//! - [`socket`]：SOCKET 层归属，把每条新连接的判定登记进流表（T-072）；
//! - [`network`]：NETWORK 层，把目标 TCP 流改道到回环中继、回程反向改写（T-075）；
//! - [`worker`]：NETWORK 层的收发线程与首包竞态的暂存、兜底归属（T-075、T-076）；
//! - [`udp`]：目标进程 UDP 交给 UDP 中继、回包注入（T-091）；
//! - [`interceptor`]：把以上组装成 [`crate::Interceptor`]（[`DivertInterceptor`]）。
//!
//! 打开句柄会安装并加载驱动：相关测试只在虚拟机里跑（`--features vm-tests`，C-TEST-04）。

pub mod ffi;
pub mod interceptor;
pub mod lock;
pub mod network;
pub mod socket;
pub mod udp;
pub mod worker;

pub use interceptor::{DivertConfig, DivertInterceptor};
