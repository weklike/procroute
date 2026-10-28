# ProcRoute 进程级代理客户端项目方案

> 本文件由共享文档《ProcRoute 进程级代理客户端项目方案》（https://claude.ai/artifact/YL6ADQiDN1Yp2ERwWtsvH2，rev 20）导出。
> 以共享文档为准；两处的架构图与里程碑图在这里只保留文字说明。更新时重新导出并整体覆盖本文件。

2026-10-26 · syzygy1

## 1. 项目概述

ProcRoute（暂定代号）是一个 Windows 优先的现代进程级代理客户端：只让用户指定的进程（及其子进程）走代理，其余流量完全不受影响，体验对标 Netch 的「进程模式」。

**一句话定位**：选中游戏或软件 → 一键启动 → 只有它走代理，TCP 和 UDP 都管，DNS 不泄漏，系统路由不被改动。

### 1.1 v1.0 目标

- 按进程名、完整路径、目录、通配符选择目标进程，可选是否包含子进程
- 劫持目标进程的 TCP 与 UDP（含游戏常见的 UDP），并处理 DNS 防泄漏
- 两种工作模式：**精确进程模式**（不改系统路由，最接近 Netch）与 **TUN 分流模式**（兼容性兜底）
- 复用成熟代理内核，支持主流协议（SS、VMess、VLESS/Reality、Trojan、Hysteria2、TUIC、AnyTLS、SOCKS5、HTTP 等）与订阅导入
- GUI 以普通用户权限运行，所有特权操作收敛在一个后台服务里
- 实时连接面板：能看到「哪个进程 → 哪个目标 → 走了哪个出站」

### 1.2 非目标（v1.0 不做）

- 不自研代理协议，不自写加密实现
- 不开发、不自签内核驱动（WFP callout / NDIS 过滤驱动）
- 不做 macOS / Linux 版本，但核心模块按跨平台边界设计，预留接口
- 不做网关 / 路由器 / 局域网共享模式

### 1.3 关键假设

- 目标系统：Windows 10 22H2 及以上、Windows 11，x64 优先，ARM64 列为后续
- 团队规模：1–2 人，按 4 个月交付 v1.0 估算
- 开源发布，许可证需与所用内核的许可证兼容（见第 9 节）
- 若你计划把它当简历项目，第 10 节的 M2 里程碑已经是一个可演示、可讲清楚原理的版本

## 2. 现状与竞品

结论：Netch 的进程模式依赖商业驱动且主仓库处于重构期，ProxiFyre 证明了「现成驱动 + 用户态改道」可行但只能接 SOCKS5，sing-box 协议最全但进程分流必须走 TUN。ProcRoute 的空位是把三者的长处拼起来：不改路由的进程级劫持 + 全协议内核 + 现代化 GUI。

| 项目 | 拦截方式 | 上游协议 | 现状与许可 | 对本项目的启示 |
| --- | --- | --- | --- | --- |
| [Netch](https://github.com/netchx/netch) | 进程模式用 Netfilter 驱动；另有 WinTUN 的 TUN 模式 | Socks5、SS、SSR、WireGuard、Trojan、VMess、VLESS | README 声明为 2.0 做准备将清空 1.0 代码；.NET 6 x64；GPLv3 | 「选进程即生效」的体验是标杆；Netfilter 为商业 SDK，无法直接复用 |
| [ProxiFyre](https://github.com/wiresock/proxifyre) | Windows Packet Filter（NDIS 层）改道 | 仅 SOCKS5，可选 SOCKS5-over-TLS | 活跃，带 GUI 与 Windows 服务；AGPL-3.0；安装包未签名 | 证明按进程转发 TCP/UDP（含 QUIC）可在用户态完成；需另配协议内核 |
| [sing-box](https://sing-box.sagernet.org/configuration/route/rule/) | TUN 入站 + 路由规则 `process_name` / `process_path` / `process_path_regex` | 主流协议几乎全覆盖，AnyTLS 自 1.12 起支持 | 活跃迭代中；GPL-3.0-or-later | 直接作为协议与分流内核；进程规则在 Windows、Linux、macOS 均可用 |

几条值得提前吸取的教训：

- ProxiFyre 文档列出的限制可直接当作需求清单：分片的 IPv6 UDP 会绕过代理、SOCKS5 凭据明文存放、需为动态端口建防火墙规则。
- 进程归属在非管理员权限下只能「尽力而为」，受保护进程和其他用户的进程可能识别失败，所以特权服务是必需的。
- 反作弊会检查已加载的驱动。社区有案例显示 WinDivert 驱动「已加载但文件被删」时 EAC 拒绝启动游戏，驱动生命周期必须干净。

## 3. 需求

v1.0 共 14 条功能需求，其中 8 条 P0 构成最小可用版本；非功能需求以可测的目标值给出，作为第 12 节验收的依据。

### 3.1 功能需求

| 编号 | 需求 | 优先级 | 里程碑 |
| --- | --- | --- | --- |
| F1 | 按进程名、完整路径、目录（可递归）、通配符或正则选择目标进程；可从运行中进程列表或文件对话框添加 | P0 | M1 |
| F2 | TUN 分流模式：由内核 TUN + 进程规则实现，作为兼容性兜底 | P0 | M1 |
| F3 | 节点与订阅：导入分享链接和订阅，测延迟，手动或自动选择 | P0 | M1 |
| F4 | 精确进程模式下劫持目标进程的 TCP，不改系统路由 | P0 | M2 |
| F5 | 失败策略：内核或服务异常时，目标进程流量默认阻断（fail-closed），可改为放行 | P0 | M2 |
| F6 | 劫持目标进程的 UDP（含游戏流量），NAT 类型取决于服务端 | P0 | M3 |
| F7 | 子进程继承：目标进程派生的子进程自动纳入，可按规则关闭 | P0 | M3 |
| F8 | DNS 防泄漏：劫持目标进程直发的 53 端口查询，并对代理流量做域名嗅探 | P0 | M3 |
| F9 | 不同进程组走不同出站或节点分组 | P1 | M3 |
| F10 | 实时连接面板：进程、目标地址、出站、流量、时长 | P1 | M3 |
| F11 | QUIC 策略：可选阻断目标进程的 UDP 443，让应用回落 TCP | P1 | M3 |
| F12 | 托盘、开机自启、一键切换配置方案 | P1 | M4 |
| F13 | 日志查看与诊断包导出（自动脱敏） | P1 | M4 |
| F14 | 规则方案导入导出，并支持导入 Netch 模式文件 | P2 | M4 |

### 3.2 非功能需求

| 类别 | 目标值 |
| --- | --- |
| 性能 | 精确模式下 TCP 吞吐相对「直接用同一 sing-box 的 SOCKS 入口」损耗不超过 10%；新建连接的附加延迟 p95 不超过 2 ms |
| 资源 | 服务进程空闲内存不超过 30 MB（不含 sing-box）；1000 条并发连接时服务 CPU 占用不超过 5%（4 核机器） |
| 可靠性 | 服务停止或崩溃后 3 秒内撤销全部过滤器，系统网络恢复原状；sing-box 异常退出自动拉起，1 分钟内最多 3 次 |
| 安全 | GUI 以普通权限运行；IPC 只接受当前交互用户与管理员；本地 SOCKS 入口仅绑定 127.0.0.1 且使用每次启动随机生成的凭据；节点凭据用 DPAPI 加密落盘 |
| 兼容 | Windows 10 22H2+ 与 Windows 11 x64；精确模式与常见 VPN 客户端共存 |
| 可观测 | 结构化 JSON 日志，按模块分级；每条被改道的连接都能追溯到 PID、规则与出站 |

## 4. 关键技术选型

决策：精确进程模式用 WinDivert 做默认拦截后端，TUN 模式交给 sing-box 兜底；协议全部交给 sing-box 子进程；特权服务和 GUI 后端统一用 Rust。拦截层抽象成 `Interceptor` trait，Windows Packet Filter 作为预留的第二后端。

### 4.1 进程劫持方案对比

| 方案 | 原理 | 只碰目标进程 | 改系统路由 | 驱动来源 | 主要问题 | 结论 |
| --- | --- | --- | --- | --- | --- | --- |
| NetFilter SDK | 商业网络过滤 SDK，Netch 进程模式所用 | 是 | 否 | 商业授权 | 授权费用、闭源、分发受限 | 不采用 |
| WinDivert | WFP callout 驱动 + 用户态读写数据包；SOCKET / FLOW 层事件带 PID | 是 | 否 | 开源，驱动已签名，最新 2.2.2 | 驱动多年未更新；部分杀软和反作弊对它敏感 | **精确模式默认后端** |
| Windows Packet Filter | NDIS 轻量过滤驱动，ProxiFyre 所用 | 是 | 否 | 第三方驱动，需单独安装 | 多一步安装；驱动分发条款需单独确认 | 预留第二后端 |
| TUN + 进程规则 | wintun 虚拟网卡接管路由，内核按进程决定代理或直连 | 否，全部流量先进 TUN | 是 | wintun，随 sing-box 使用 | 与其他 VPN 争路由；影响面是全局 | **兜底模式** |
| 自研 WFP callout 驱动 | 自写内核驱动 | 是 | 否 | 需 EV 证书 + 微软签名 | 成本、风险、维护负担都最高 | 不采用 |

### 4.2 技术栈

| 层 | 选型 | 理由 | 备选 |
| --- | --- | --- | --- |
| GUI | Tauri 2 + React 19 + TypeScript + Vite + shadcn/ui（Radix + Tailwind CSS v4），详见 4.3 | 系统自带 WebView2，包体小；Rust 后端与服务共用类型 | Avalonia（.NET）、Wails（Go） |
| 特权服务 | Rust：tokio、windows-rs、windows-service | 包处理热路径需要内存安全和稳定延迟，无 GC 停顿 | Go（能直接内嵌 sing-box，但隔离性和许可证边界变差） |
| 拦截库 | WinDivert 的 Rust 绑定，或自封装 FFI | 用户态完成全部改包逻辑 | ndisapi crate（Apache-2.0） |
| 协议内核 | sing-box，独立子进程 | 协议全、含 AnyTLS；自带进程规则、协议嗅探和控制 API | mihomo |
| IPC | 命名管道 + JSON-RPC 2.0；Rust 类型自动生成 TS 定义 | 不占 TCP 端口，可加 ACL | gRPC over 命名管道 |
| 进程事件 | ETW Kernel-Process 实时事件 + Toolhelp 快照兜底 | 子进程启动即可纳入 | WMI（延迟大） |
| 打包更新 | Tauri NSIS 安装包 + 服务注册；签名的增量更新 | 一个安装包装全部组件 | MSI |

sing-box 以子进程而非库的方式接入，原因有三：Rust 无法直接链接 Go 代码；内核崩溃不会拖垮特权服务；GPL 代码的边界清晰，升级只需替换一个二进制。

### 4.3 前端技术栈（React）

前端选型围绕两件事：IPC 请求要有缓存和失效管理，连接与日志这类高频事件流不能拖垮渲染。所以请求走 TanStack Query，事件流走自写的订阅 hook 加环形缓冲，长列表一律虚拟化。

| 关注点 | 选型 | 用在哪里 |
| --- | --- | --- |
| 框架 | React 19 + TypeScript（strict）+ Vite | 只用函数组件与 Hooks |
| 路由 | TanStack Router | 类型安全的路由和参数：方案、节点、连接、日志、设置 |
| 请求状态 | TanStack Query | 包装 IPC 请求：缓存、失效、重试；`profile.save`、`node.test` 等用 mutation |
| 界面状态 | Zustand | 主题、侧栏、当前会话状态等纯前端状态；不复制服务端数据 |
| 实时事件 | 自写 `useIpcSubscription` + 环形缓冲 + 按动画帧批量刷新 | `conn.subscribe`、`log.subscribe`，避免每条事件触发一次重渲染 |
| 长列表 | TanStack Virtual | 连接面板、日志、进程列表，动辄上千行 |
| 组件与样式 | shadcn/ui（Radix 原语 + Tailwind CSS v4）+ lucide-react | 组件源码进仓库可改；Radix 负责键盘与读屏可访问性；明暗主题用 CSS 变量 |
| 表单 | React Hook Form + Zod | Profile 编辑器、节点导入；前端校验只为体验，权威校验仍在服务端 |
| 国际化 | react-i18next | 默认 zh-CN，同步 en-US |
| 测试 | Vitest + React Testing Library；端到端用 tauri-driver（WebDriver） | 组件与 hooks 单测；关键流程端到端 |
| 规范 | ESLint（typescript-eslint、react-hooks）+ Prettier | react-hooks 规则设为 error |

WebView 也是攻击面：前端一旦被注入脚本，就能调用 Tauri 命令进而操作服务。因此 Tauri 配置严格 CSP、不加载任何远程资源，节点名和订阅内容等外部数据只按纯文本渲染，禁止 `dangerouslySetInnerHTML`。

## 5. 总体架构

ProcRoute 由三个进程组成：普通权限的 UI、SYSTEM 权限的 procroute-svc、作为子进程运行的 sing-box。只有服务能接触驱动，UI 只能通过一条命名管道下指令。

> 图：精确进程模式架构 · 控制面 + 数据面（图示见共享文档）

上半部分是控制面：UI 经命名管道调用服务，服务内的四个模块决定「谁要改道、走哪个出站」。下半部分是数据面：目标进程的包被 WinDivert 认出并改写，经重定向器转成 SOCKS5 交给 sing-box。TUN 模式下，WinDivert 和重定向器两格由 sing-box 的 TUN 入站整体替代。

### 5.1 进程边界

- **UI（procroute-ui.exe）**：只做展示和编辑，不持有任何凭据明文，不直接读写配置文件。
- **服务（procroute-svc.exe）**：唯一的特权进程，持有驱动句柄、配置、凭据和 sing-box 生命周期。
- **sing-box（子进程）**：只监听 127.0.0.1，配置由服务每次启动时生成，崩溃由服务拉起。

### 5.2 IPC 首批接口

所有方法走 JSON-RPC 2.0，服务主动推送的事件用同一管道上的通知消息。

| 方法 | 作用 |
| --- | --- |
| `session.start` / `session.stop` / `session.status` | 按 Profile 启停改道，查询当前状态 |
| `profile.list` / `profile.get` / `profile.save` / `profile.delete` | 方案的增删改查，保存前做 schema 校验 |
| `node.import` / `node.list` / `node.test` | 导入分享链接或订阅、列出节点、测延迟 |
| `process.list` | 列出运行中进程及其是否命中规则 |
| `conn.subscribe` | 订阅实时连接事件流 |
| `log.subscribe` | 订阅日志流，可按级别过滤 |
| `driver.status` / `driver.unload` | 查看与卸载拦截驱动 |

## 6. 核心流程

精确模式的核心是一张 NAT 映射表：驱动层只负责「认出是谁的包、改写去向」，真正的代理工作全部交给本地中继和 sing-box。下面按 TCP、UDP、DNS、进程匹配、自保护、TUN 模式依次说明。

### 6.1 TCP 改道（精确模式）

1. 进程追踪器维护目标集合，键为「PID + 进程创建时间」，避免 PID 复用导致误判。
2. WinDivert SOCKET 层以只嗅探方式收到 CONNECT 事件，拿到 PID、本地端口和远端地址；命中目标集合则登记进流表。
3. NETWORK 层过滤器只抓流表内五元组的出站包，把去向改写到本地中继，并为该流分配映射端口，写入 NAT 表：映射端口 → 原始目标、PID、命中规则。
4. 中继接受连接后按映射端口取回原始目标，向 sing-box 的本地 SOCKS5 入口发起 CONNECT；用户名填该规则的出站分组标签，sing-box 用 `auth_user` 规则把它路由到对应出站。
5. 回程包在 NETWORK 层反向改写后注入，应用看到的始终是与原目标的连接。
6. 连接关闭或空闲超时后回收表项，TCP 默认 300 s，UDP 默认 60 s。

首个 SYN 可能先于 SOCKET 事件到达：此时把包暂存不超过 50 ms 等待归属，超时则用 `GetExtendedTcpTable` 反查 PID 兜底；仍无法归属的流按非目标放行，并计入 attribution_miss 指标，该指标纳入泄漏测试判据。

### 6.2 UDP

- 按「本地地址 + 本地端口」建会话，而不是按五元组，这样一个本地端口对多个远端时仍保持 Full-cone 语义。
- 每个会话对应 sing-box 的一个 UDP ASSOCIATE；回包按会话改写源地址后注入。
- 分片的 IPv6 UDP 先重组再处理，重组失败按失败策略处理，绝不静默放行直连。

### 6.3 DNS

多数 Windows 应用通过系统的 DNS Client 服务（Dnscache，运行在 svchost 中）解析域名，查询包的发出者不是目标进程，因此无法按进程劫持 DNS。处理分两层：

- **默认策略**：目标进程自己发往 53 端口的 UDP / TCP 查询直接劫持到 sing-box 的 DNS；同时对所有被改道的连接开启协议嗅探（TLS SNI、HTTP Host、QUIC），用嗅探出的域名覆盖目标地址，让远端重新解析，绕开本地 DNS 污染。
- **可选策略**：系统 DNS 接管。把系统 DNS 指向本地 sing-box，非目标域名照常直连上游解析，用户列出的域名走远程 DNS。影响面是全局，默认关闭。

### 6.4 进程匹配与子进程

- 匹配顺序：排除规则 > 完整路径 > 目录 > 进程名 > 通配或正则，首个命中生效。
- 路径先规范化：NT 设备路径转 DOS 路径、大小写不敏感、展开 8.3 短名。
- 子进程：ETW ProcessStart 事件带父 PID。父进程在目标集合内、规则允许继承、且父进程创建时间早于子进程时，子进程才加入集合。
- 服务启动或切换方案时，对已运行进程做一次快照补登。

### 6.5 防回环与自保护

- 永久排除 sing-box 子进程、ProcRoute 服务和 UI 自身的流量，以及去往回环、链路本地和代理服务器 IP 的流量。
- 代理服务器域名在启动和切换节点时解析，结果写入排除表。
- 过滤器句柄随服务进程生命周期存在：服务退出时句柄关闭，驱动撤销全部过滤。
- fail-closed：sing-box 不可用时，中继对新 TCP 连接回 RST、丢弃 UDP，不放行直连。

### 6.6 TUN 模式

服务生成 sing-box 配置：TUN 入站开启自动路由，路由规则用 `process_path` / `process_name` 把目标进程指向代理出站，其余走 direct。拦截、DNS 和嗅探都由 sing-box 完成，服务只负责配置生成、启停和状态汇报。

## 7. 模块与仓库目录结构

仓库是一个 Cargo workspace 加一个 Tauri 应用；纯逻辑模块与平台相关模块严格分开，这样规则引擎、配置和协议类型能在 Linux CI 上单测，只有少数 crate 需要 Windows 环境。

```text
procroute/
├─ AGENTS.md
├─ CONSTRAINTS.md
├─ Cargo.toml              # workspace
├─ rust-toolchain.toml
├─ crates/
│  ├─ proto/               # IPC 方法与消息类型，导出 TS 定义
│  ├─ config/              # Profile 与规则模型、校验、schema 迁移
│  ├─ rules/               # 进程匹配引擎，纯函数，无 IO
│  ├─ procwatch/           # 进程追踪：ETW 事件 + 快照，维护进程树
│  ├─ intercept/           # Interceptor trait 与后端：divert/、tun/，预留 ndis/
│  ├─ relay/               # NAT 表、本地 TCP/UDP 中继、SOCKS5 客户端
│  ├─ core-mgr/            # sing-box 配置生成、子进程守护、API 客户端
│  ├─ platform-win/        # Windows API 封装：路径规范化、DPAPI、ACL、服务控制
│  └─ svc/                 # 二进制：Windows 服务入口，组装各模块
├─ app/
│  ├─ src-tauri/           # Rust：IPC 客户端、托盘、自动更新
│  └─ src/                 # React 19 + TS：routes/ features/ components/ hooks/ stores/ api/
├─ third_party/
│  ├─ windivert/           # 锁定版本 + SHA256 + LICENSE，不改动
│  └─ sing-box/            # 版本锁与下载脚本，不提交二进制
├─ xtask/                  # cargo xtask：生成类型、拉取依赖、打包
├─ tests/
│  ├─ e2e/                 # Windows 虚拟机上的端到端用例
│  └─ fixtures/
└─ docs/
   └─ adr/                 # 架构决策记录
```

依赖方向只允许自上而下：

- `proto`、`config`、`rules` 不依赖任何平台 crate，可在 Linux / macOS 编译和测试。
- `procwatch`、`intercept`、`relay`、`core-mgr` 可依赖 `platform-win`，彼此之间只通过 trait 与消息通信。
- `svc` 是唯一组装点；`app` 只依赖 `proto`，绝不直接调用拦截或驱动相关代码。
- `unsafe` 只允许出现在 `platform-win` 和 `intercept` 的 FFI 子模块里。

## 8. 配置模型

一个 Profile 就是一套「哪些进程、走哪个出站、出错时怎么办」的方案；节点和订阅单独存放，Profile 只按标签引用。所有配置由服务持有，UI 只能通过 IPC 读写。

```json
{
  "schema_version": 1,
  "id": "01JBX7Q3K2M8T5W9Y4C6N0R1PZ",
  "name": "游戏加速",
  "mode": "precise",
  "fail_policy": "block",
  "dns": { "strategy": "sniff", "hijack_port53": true },
  "udp": { "enabled": true, "block_quic": false },
  "groups": [
    {
      "tag": "game",
      "outbound": "hk-auto",
      "include_children": true,
      "match": [
        { "type": "dir", "value": "D:\\Games\\MyGame", "recursive": true },
        { "type": "name", "value": "launcher.exe" }
      ]
    },
    {
      "tag": "browser",
      "outbound": "us-01",
      "include_children": false,
      "match": [
        { "type": "path", "value": "C:\\Program Files\\Mozilla Firefox\\firefox.exe" }
      ]
    }
  ],
  "exclude": [
    { "type": "name", "value": "updater.exe" }
  ]
}
```

| 字段 | 取值 | 说明 |
| --- | --- | --- |
| `mode` | `precise` / `tun` | 精确进程模式或 TUN 分流模式 |
| `fail_policy` | `block`（默认）/ `allow` | 内核或服务异常时目标流量阻断还是放行 |
| `dns.strategy` | `sniff`（默认）/ `system_takeover` | 见 6.3 节 |
| `udp.block_quic` | 布尔 | 阻断目标进程的 UDP 443，迫使应用回落 TCP |
| `groups[].match[].type` | `name` / `path` / `dir` / `glob` / `regex` | 匹配顺序见 6.4 节 |
| `groups[].include_children` | 布尔 | 是否把子进程纳入该组 |
| `groups[].outbound` | 节点或节点组标签 | 对应 sing-box 的出站标签 |
| `exclude` | 同 `match` | 优先级最高，命中即直连 |

存储约定：

- 位置为 `%ProgramData%\ProcRoute\`，ACL 只授予 SYSTEM 和 Administrators 写权限。
- 节点凭据单独存放并用 DPAPI（机器范围）加密，Profile 与日志里永不出现明文。
- 运行时生成的 sing-box 配置写在 `run\` 目录，每次启动重新生成，不允许手改。
- `schema_version` 每次结构变更 +1，并配套迁移函数和迁移测试；旧文件必须能无损升级。

## 9. 安全、权限与分发

原则：所有特权集中在一个服务里，服务对外只开一条有 ACL 的命名管道，本机任何其他入口（SOCKS、内核 API）都绑定回环并带随机凭据。

### 9.1 权限与 IPC

- 服务以 LocalSystem 运行（打开 WinDivert 句柄需要），启动后禁用用不到的令牌特权。
- 命名管道 `\\.\pipe\ProcRoute.Control`：安全描述符只放行 SYSTEM、Administrators 和当前交互用户；设置拒绝远程客户端。
- 连接建立后取客户端 PID，校验其可执行文件位于安装目录且签名与服务一致，否则断开。
- 每个 JSON-RPC 请求做 schema 校验和大小限制（单条不超过 1 MB）；修改类方法写审计日志。
- sing-box 的 SOCKS 入口和控制 API 每次启动随机端口、随机凭据，仅绑定 127.0.0.1，凭据只存在服务内存里。

### 9.2 驱动生命周期

- WinDivert 的 `.sys` 与 `.dll` 随安装包分发，版本与 SHA256 锁定在 `third_party/windivert/`。
- 驱动加载期间禁止删除或替换 `.sys` 文件；升级和卸载前先停服务并确认驱动已卸载。
- UI 显示驱动状态，提供「卸载驱动」按钮；文档列出与之冲突的反作弊场景，建议改用 TUN 模式。

### 9.3 签名、更新与供应链

- 所有自有 exe / dll 做 Authenticode 签名，减少 SmartScreen 拦截和杀软误报。
- 自动更新包使用独立签名密钥校验；sing-box 二进制启动前按锁文件校验 SHA256，不一致拒绝启动。
- Rust 依赖用 `cargo-deny` 检查许可证与漏洞公告；前端依赖锁定 lockfile；依赖升级走单独 PR。

### 9.4 许可证

建议项目整体采用 GPL-3.0-or-later：随包分发的 sing-box 为 GPL-3.0-or-later，WinDivert 为 LGPL-3.0 / GPL-2.0 双许可，统一 GPL 能避免边界争议。仓库根目录放 `NOTICE` 列出全部第三方组件、版本、许可证和源码获取方式。

### 9.5 隐私与合规

- 默认不收集任何遥测；日志只存本地，诊断包导出时自动脱敏节点地址和凭据。
- 软件不内置任何节点或订阅；发布说明提示用户遵守所在地法律法规。

## 10. 里程碑与排期

按 1–2 人估算共 16 周：先用 2 周验证最大的技术风险，第 5 周用 TUN 模式交付第一个可用版本，第 9 周跑通核心的精确进程模式。

> 图：里程碑 · 5 个阶段，共 16 周（图示见共享文档）

每个阶段结束都发一个可安装的预览版，门槛未达标就不进入下一阶段。M0 若发现 WinDivert 在目标环境不可用，M2 改用 Windows Packet Filter 后端，整体顺延约 2 周。

## 11. 风险与对策

最大的两个风险都在驱动层：反作弊和杀软对 WinDivert 的敏感度，以及 WinDivert 多年未更新带来的兼容性不确定。两者共用一个对策：拦截层抽象化，并保留 TUN 模式作为随时可切换的兜底。

| 风险 | 表现 | 对策 |
| --- | --- | --- |
| 反作弊或杀软对 WinDivert 敏感 | 游戏拒绝启动、安装包被报毒 | 驱动按需加载、停止即卸载；全部二进制签名；UI 一键切 TUN 模式；预留 Windows Packet Filter 后端 |
| WinDivert 停更 | 新版 Windows 或开启内存完整性后加载失败 | M0 在 Win10 / Win11（含内存完整性开启）矩阵上验证；后端可替换 |
| DNS 无法按进程归属 | 目标应用拿到被污染的 IP，连接失败 | 协议嗅探覆盖目标地址；可选系统 DNS 接管 |
| SOCKET 事件与首包竞态 | 首个连接漏网直连 | 首包暂存 + 端口表反查；fail-closed 时宁可延迟不泄漏 |
| UWP / AppContainer 回环隔离 | 商店应用改道后连不上本地中继 | M0 专项验证；必要时中继监听本机非回环地址 |
| 与其他 VPN、安全软件的 WFP 过滤冲突 | 规则顺序错乱、流量被二次拦截 | 显式设置过滤器优先级；启动时检测已知冲突软件并提示 |
| sing-box 配置格式随版本变化 | 升级内核后配置无法加载 | 锁定内核版本；配置生成器按版本适配；用内核自带的检查命令做回归测试 |
| GPL 合规遗漏 | 分发 GPL 组件但未提供源码获取方式 | `NOTICE` + 发布页附源码链接，纳入发布检查清单 |
| 维护精力有限 | 范围膨胀、迟迟不能发布 | 严守第 1.2 节非目标清单；每个里程碑都能独立发布 |

## 12. 测试与验收标准

验收的核心只有一句：目标进程的流量一个包都不漏，非目标进程一个包都不碰。为此需要一个自写的「泄漏检测器」：在物理网卡上旁路统计目标 PID 发往非代理服务器地址的包，作为所有集成测试的判据。

### 12.1 测试分层

| 层级 | 覆盖范围 | 工具 | 运行环境 |
| --- | --- | --- | --- |
| 单元 | 规则匹配、配置迁移、NAT 表、SOCKS5 编解码、sing-box 配置生成 | cargo nextest、proptest | Linux 与 Windows CI |
| 组件 | 中继对接假 SOCKS5 服务器；core-mgr 对接真实 sing-box | tokio 测试 | Windows CI |
| 集成 | 服务 + 驱动 + sing-box，跑 TCP / UDP 回显测试进程，泄漏检测器判定 | 自写测试进程与检测器 | Hyper-V 虚拟机，每次用例前还原快照 |
| UI | 添加进程、切换方案、连接面板等关键流程 | Vitest + React Testing Library、tauri-driver | Windows CI |
| 性能 | 吞吐、新建连接延迟、并发 | iperf3、自写压测 | 固定配置的物理机 |

### 12.2 v1.0 验收清单

- [ ] 目标进程 1 小时混合 TCP / UDP 流量中，泄漏检测器计数为 0（排除规则命中的除外）
- [ ] 精确模式下非目标进程的出口 IP、系统路由表、DNS 设置均无变化
- [ ] 启动器拉起的子进程在 1 秒内被纳入目标集合
- [ ] 强杀 sing-box 后目标进程的新连接失败而非直连；服务停止后 3 秒内系统网络恢复原状
- [ ] 目标进程访问被本地 DNS 污染的域名时可以正常连通
- [ ] 第 3.2 节全部非功能目标达标
- [ ] 安装、升级、卸载后无残留驱动、服务和防火墙规则
- [ ] Windows 10 22H2、Windows 11（内存完整性开 / 关）矩阵全部通过

## 13. 前端示例

下面几段是前端的骨架示例，说明 4.3 节的分层如何落到代码上：IPC 客户端在最底层，领域 hook 包住请求，组件只消费 hook，高频事件走订阅 hook 加环形缓冲。给弱模型开发时，可以让它照这些模式填充其余领域。

### 13.1 IPC 客户端（`src/api/client.ts`，手写薄封装）

类型定义由 `cargo xtask gen-types` 生成（见 C-ARCH-04），这里只封装调用方式，组件不直接碰它。

```ts
// SPDX-License-Identifier: GPL-3.0-or-later
// 手写的 IPC 薄封装（T-041）。同目录的 generated.ts 是生成文件，禁止手改（C-ARCH-04）。
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

import type { ErrorCode, IpcChannel, IpcEvent, IpcMethod, IpcRequest, IpcResult } from './generated'

export const IPC_COMMAND = 'ipc_call'

/**
 * Tauri 事件名只允许字母、数字、`-`、`/`、`:`、`_`，
 * 所以 `conn.subscribe` 映射为 `ipc:conn:subscribe`；Tauri 后端发事件时用同样的规则。
 */
export function tauriEventName(channel: IpcChannel): string {
  return `ipc:${channel.replaceAll('.', ':')}`
}

export async function call<M extends IpcMethod>(
  method: M,
  params: IpcRequest[M],
): Promise<IpcResult[M]> {
  try {
    return await invoke<IpcResult[M]>(IPC_COMMAND, { method, params })
  } catch (e) {
    throw IpcError.from(e)
  }
}

export function subscribe<E extends IpcChannel>(
  channel: E,
  onEvent: (payload: IpcEvent[E]) => void,
): Promise<UnlistenFn> {
  return listen<IpcEvent[E]>(tauriEventName(channel), (e) => {
    onEvent(e.payload)
  })
}

export type ClientErrorCode = ErrorCode | 'ipc.transport'

export class IpcError extends Error {
  readonly code: ClientErrorCode
  constructor(code: ClientErrorCode, message: string) {
    super(message)
    this.name = 'IpcError'
    this.code = code
  }
  static from(e: unknown): IpcError {
    if (e instanceof IpcError) return e
    if (isStructured(e)) return new IpcError(e.code, e.message)
    return new IpcError('ipc.transport', e instanceof Error ? e.message : String(e))
  }
}

function isStructured(e: unknown): e is { code: ErrorCode; message: string } {
  if (typeof e !== 'object' || e === null) return false
  const o = e as Record<string, unknown>
  return typeof o.code === 'string' && o.code.includes('.') && typeof o.message === 'string'
}
```

### 13.2 领域 hook（`src/features/profile/api.ts`）

每个领域一个 `api.ts`，用 TanStack Query 包住请求；组件只 import 这里的 hook（见 C-CODE-09）。

```ts
// SPDX-License-Identifier: GPL-3.0-or-later
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { call } from '@/api/client'
import type { Profile } from '@/api/generated'

const keys = {
  all: ['profile'] as const,
  detail: (id: string) => ['profile', id] as const,
}

export function useProfiles() {
  return useQuery({ queryKey: keys.all, queryFn: () => call('profile.list', {}) })
}

export function useSaveProfile() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (p: Profile) => call('profile.save', p),
    onSuccess: (_r, p) => {
      qc.invalidateQueries({ queryKey: keys.all })
      qc.invalidateQueries({ queryKey: keys.detail(p.id) })
    },
  })
}
```

### 13.3 实时事件订阅 hook（`src/hooks/useIpcSubscription.ts`）

连接和日志每秒上千条，必须经环形缓冲按动画帧批量刷新，禁止逐条 `setState`（见 C-CODE-10）。

```ts
// SPDX-License-Identifier: GPL-3.0-or-later
import type { UnlistenFn } from '@tauri-apps/api/event'
import { useEffect, useState } from 'react'

import { subscribe } from '@/api/client'
import type { IpcChannel, IpcEvent } from '@/api/generated'

export const DEFAULT_CAP = 2000

export function useIpcSubscription<E extends IpcChannel>(
  channel: E,
  cap: number = DEFAULT_CAP,
): IpcEvent[E][] {
  const [items, setItems] = useState<IpcEvent[E][]>([])

  useEffect(() => {
    let disposed = false
    let frame: number | null = null
    let pending: IpcEvent[E][] = []
    let unlisten: UnlistenFn | null = null

    const flush = () => {
      frame = null
      if (disposed || pending.length === 0) return
      // 先把缓冲取出来再交给 setState：更新函数必须是纯函数，
      // 严格模式下 React 会调用它两次，在更新函数里清空缓冲会丢事件。
      const batch = pending
      pending = []
      setItems((prev) => appendCapped(prev, batch, cap))
    }

    subscribe(channel, (payload) => {
      if (disposed) return
      pending.push(payload)
      frame ??= requestAnimationFrame(flush)
    }).then(
      (fn) => {
        if (disposed) fn() // 订阅建立前组件就卸载了：立刻取消
        else unlisten = fn
      },
      () => {
        // 订阅失败时保持空列表；服务状态由 session.status 单独展示
      },
    )

    return () => {
      disposed = true
      if (frame !== null) cancelAnimationFrame(frame)
      unlisten?.()
    }
  }, [channel, cap])

  return items
}

export function appendCapped<T>(prev: readonly T[], batch: readonly T[], cap: number): T[] {
  const merged = prev.concat(batch)
  return merged.length > cap ? merged.slice(merged.length - cap) : merged
}
```

### 13.4 组件：连接面板（`src/features/conn/ConnTable.tsx`）

组件只消费 hook，长列表用 TanStack Virtual 虚拟化（见 C-CODE-10）；外部数据按纯文本渲染（见 C-SEC-10）。

```tsx
// SPDX-License-Identifier: GPL-3.0-or-later
import { useRef } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { useTranslation } from 'react-i18next'
import { useIpcSubscription } from '@/hooks/useIpcSubscription'

export function ConnTable() {
  const { t } = useTranslation()
  const rows = useIpcSubscription('conn.subscribe')
  const parent = useRef<HTMLDivElement>(null)
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => 36,
    overscan: 12,
  })

  if (rows.length === 0) {
    return <p className="text-muted-foreground p-4">{t('conn.empty')}</p>
  }
  return (
    <div ref={parent} className="h-full overflow-auto">
      <div style={{ height: virt.getTotalSize(), position: 'relative' }}>
        {virt.getVirtualItems().map((v) => {
          const r = rows[v.index]
          return (
            <div
              key={v.key}
              className="absolute inset-x-0 grid grid-cols-4 gap-2 px-3 text-sm"
              style={{ height: v.size, transform: `translateY(${v.start}px)` }}
            >
              <span className="truncate">{r.process}</span>
              <span className="truncate">{r.target}</span>
              <span>{r.outbound}</span>
              <span className="tabular-nums">{r.download_bytes}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
```

### 13.5 纯前端状态（`src/stores/ui.ts`）

Zustand 只放主题、侧栏等纯前端状态，不复制服务端数据（见 C-CODE-09）；订阅时用 selector。

```ts
// SPDX-License-Identifier: GPL-3.0-or-later
import { create } from 'zustand'

type Theme = 'light' | 'dark' | 'system'

interface UiState {
  theme: Theme
  sidebarOpen: boolean
  activeProfileId: string | null
  setTheme: (t: Theme) => void
  toggleSidebar: () => void
  setActiveProfile: (id: string | null) => void
}

export const useUiStore = create<UiState>((set) => ({
  theme: 'system',
  sidebarOpen: true,
  activeProfileId: null,
  setTheme: (theme) => set({ theme }),
  toggleSidebar: () => set((s) => ({ sidebarOpen: !s.sidebarOpen })),
  setActiveProfile: (activeProfileId) => set({ activeProfileId }),
}))

// 用法：const theme = useUiStore((s) => s.theme)  // 只在 theme 变化时重渲染
```

## 参考资料

- [netchx/netch — GitHub](https://github.com/netchx/netch)
- [wiresock/proxifyre README — GitHub](https://github.com/wiresock/proxifyre/blob/main/README.md)
- [WinDivert Releases — GitHub](https://github.com/basil00/WinDivert/releases)
- [sing-box Route Rule 文档](https://sing-box.sagernet.org/configuration/route/rule/)
- [sing-box PR #2615：Implement AnyTLS client & server](https://github.com/SagerNet/sing-box/pull/2615)
- [zapret-discord-youtube issue #4813：EAC 与 WinDivert 驱动冲突案例](https://github.com/Flowseal/zapret-discord-youtube/issues/4813)
- [Tauri 2 文档：Embedding External Binaries](https://v2.tauri.app/develop/sidecar/)

