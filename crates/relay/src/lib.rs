// SPDX-License-Identifier: GPL-3.0-or-later
//! 本地中继：NAT 表、TCP/UDP 中继与 SOCKS5 客户端。
//!
//! 拦截层把目标进程的流改道到这里，中继按 NAT 表取回原始目标，经 sing-box 的本地
//! SOCKS5 入口转发。sing-box 不可达时一律 fail-closed：TCP 回 RST、UDP 丢弃，
//! 本 crate 里没有任何直连原始目标的代码路径（C-NET-03）。
//!
//! 与拦截层只通过 svc 组装的共享 NAT 表和消息交互，不直接依赖（C-ARCH-02）。
//!
//! TCP 中继可以先嗅探首包里的域名（[`sniff`]），按域名发 CONNECT，让远端重新解析（设计文档 6.3）。
#![forbid(unsafe_code)]

pub mod nat;
pub mod sniff;
pub mod socks5;
pub mod tcp;
pub mod udp;

#[cfg(test)]
mod testutil;
