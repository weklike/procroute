<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# WinDivert 版本锁

精确进程模式的默认拦截后端（设计文档 4.1）。本目录只提交版本锁，**不提交二进制**：
`cargo xtask fetch-deps` 按 `lock.json` 下载并逐个校验 SHA256，放进 `bin/`（已在 `.gitignore` 中忽略）。
**禁止**修改、重新签名驱动，或在运行时从网络下载驱动（C-DRV-01、C-DRV-03）。

| 项 | 值 |
| --- | --- |
| 版本 | 2.2.2（`v2.2.2`，发布于 2022-09-21） |
| 源码修订 | `1789526ecfb9ff5397c94f9f54c1a3dc2fb60440` |
| 许可证 | LGPL-3.0-only 或 GPL-2.0-only 二选一；ProcRoute 按 **LGPL-3.0** 使用（C-DEP-02 白名单） |
| 源码 | <https://github.com/basil00/WinDivert/tree/v2.2.2> |

## 文件

只取出 x64 的三个文件（支持矩阵见 C-DRV-05）：

| 文件 | SHA256 | 签名 |
| --- | --- | --- |
| `WinDivert.dll` | `c1e060ee…d7d9a2` | 无 Authenticode 签名（由锁定的哈希保证） |
| `WinDivert64.sys` | `8da08533…a90ddc2` | EV 签名，签名主体 `CN=成都密思听科技有限公司`（C=CN） |
| `LICENSE` | `14a0cb52…79d628` | — |

发布包里的示例程序（`netdump.exe` 等）与 32 位文件不取出、不分发。

## 来源核对（初次锁定，2026-10-29）

- 上游的发布页与 GitHub 资产元数据都没有给出哈希。
- 从 GitHub 发布页下载的 `WinDivert-2.2.2-A.zip`，SHA256 为 `63cb4176…5f3f15`，与 SourceForge 镜像
  （divert.mirror）页面上公布的 SHA256 一致（两个独立来源）。作者站点 reqrypt.org 在锁定时无法连接。
- `WinDivert64.sys` 的 Authenticode 签名有效；发布包的 CHANGELOG 只写明「Released with signed drivers」，
  没有写签名主体。签名主体是一家公司而不是作者本人，**请维护者知悉并确认**。

## 运行时

服务只从安装目录加载 `WinDivert.dll`，加载前按编译进来的锁校验 DLL 与驱动文件的 SHA256；
驱动由 `WinDivertOpen` 安装和加载，加载期间禁止删除或替换 `.sys`（C-DRV-02）。

## 升级流程

与 sing-box 相同（`third_party/sing-box/README.md`）：单独提 PR，只改本目录的版本锁与本文件的核对记录
（C-DEP-04），并在虚拟机里重跑 `cargo nextest run -p procroute-intercept --features vm-tests`（C-TEST-04）。
