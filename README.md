<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# ProcRoute

Windows 优先的进程级代理客户端：只让指定的进程（及其子进程）走代理，其余流量完全不受影响。

选中游戏或软件 → 一键启动 → 只有它走代理：TCP、UDP 都管，DNS 不泄漏，不改系统路由。

## 两种工作模式

| 模式 | 原理 | 适用 |
| --- | --- | --- |
| **精确进程模式**（默认） | WinDivert 认出目标进程的连接，把数据包改写到本机回环上的中继，中继再交给 sing-box 的本地 SOCKS 入口；非目标进程的包原样放回 | 不改系统路由，最接近 Netch 的进程模式 |
| **TUN 分流模式** | sing-box 的 TUN 入站加按进程的路由规则 | 兼容性兜底 |

失败策略默认是 **阻断**（fail-closed）：内核或中继不可用时，目标进程的新连接会失败，不会悄悄直连。用户也可以在方案里改成「放行」。

## 当前状态

v1.0 的 8 条 P0 功能均已实现，并在 Windows Sandbox 中端到端验证（真实的服务、sing-box 与 WinDivert）：

| 功能 | 状态 |
| --- | --- |
| 按进程名、完整路径、目录、通配符、正则选择目标进程；可从运行中的进程列表添加 | ✅ |
| TUN 分流模式 | ✅ |
| 节点与订阅：分享链接、订阅导入与刷新、测延迟 | ✅ |
| 精确模式下劫持目标进程的 TCP，不改系统路由 | ✅ |
| fail-closed：内核放弃重启时目标进程的网络被阻断（`allow` 策略则撤下拦截） | ✅ |
| 精确模式下劫持目标进程的 UDP（游戏流量），回包注入回应用 | ✅ |
| 子进程继承：启动器拉起的子进程即使一启动就连接，也走同一个出站 | ✅ |
| DNS 防泄漏：劫持目标进程直发的 53 端口查询，Web 连接按 TLS SNI / HTTP Host 嗅探出的域名转发 | ✅ |
| 托盘、开机自启、一键切换方案；连接面板；日志查看；脱敏诊断包 | ✅ |

支持的节点协议：Shadowsocks（含 2022、obfs / v2ray-plugin）、VMess（AEAD）、VLESS（含 Reality / Vision）、Trojan、Hysteria2、TUIC v5、AnyTLS、SOCKS5、HTTP(S)。订阅支持纯文本、整体 Base64 与 SIP008 JSON。

### 已知限制

- IPv4 分片与带扩展头的 IPv6 包读不出端口，原样放回；分片的目标 UDP 会绕过代理（待分片重组）。
- 会话进行中修改节点后，排除表不会自动更新，需要重新启动会话。
- TUN 模式下「包含子进程」不生效（sing-box 只按发起连接的进程判定）。
- 不支持 Clash / mihomo 的 YAML 订阅；暂时不能从文件对话框添加进程（可以从运行中的进程列表添加）。
- 安装器用每次打包临时生成的自签名证书签名，Windows 会提示「未知发布者」，SmartScreen 可能拦截；要消除提示需要公共信任的代码签名证书（[ADR 0002](./docs/adr/0002-release-signing-same-certificate.md)）。
- 逐包统计的泄漏检测器（T-080）与自动更新（T-111）尚未实现。

完整进度与每项实现的取舍见 [`TASKS.md`](./TASKS.md)。

## 系统要求

- Windows 10 22H2 及以上，或 Windows 11，x64；
- 管理员权限（安装服务与加载 WinDivert 驱动时需要；日常使用界面不需要）；
- WebView2 运行时（Windows 11 自带；没有时安装器会下载引导程序）。

## 下载与安装

1. 从 [Releases](https://github.com/weklike/procroute/releases) 下载 `ProcRoute_<版本>_x64-setup.exe`。目前的版本都是预发布，不会显示为 Latest，请在列表里找。
2. 运行安装器。Windows 会提示「未知发布者」，SmartScreen 拦截时点「更多信息 → 仍要运行」。**不需要安装任何证书。**安装器会：
   - 把界面、服务、sing-box、WinDivert 装到 `C:\Program Files\ProcRoute`；
   - 登记并启动 Windows 服务 `ProcRoute`（LocalSystem，开机自动启动，异常退出 5 秒后重启）。

每个 Release 都附有 `SHA256SUMS.txt` 与构建来源证明，可以确认安装包由本仓库的 GitHub Actions 从对应的源码构建：

```powershell
gh attestation verify ProcRoute_<版本>_x64-setup.exe --repo weklike/procroute
```

服务以 LocalSystem 运行，只接受安装目录内、与服务用同一张证书签名的界面程序（C-SEC-02），其他程序一律拒绝连接。安装包的证书每次打包临时生成，用完连同私钥删除，所以没有人能再用它签出被接受的程序（[ADR 0002](./docs/adr/0002-release-signing-same-certificate.md)）。

自己构建（需要先配好开发环境，见「开发」）：

```powershell
cargo xtask fetch-deps   # 拉取并校验锁定版本的 sing-box 与 WinDivert
cargo xtask bundle       # 输出到 target\bundle\
```

**卸载**：从「设置 → 应用」或开始菜单卸载。卸载会停止并删除服务；服务退出时 WinDivert 过滤器随之撤销，不留路由或防火墙规则。配置目录 `%ProgramData%\ProcRoute`（方案、节点、日志）会保留，需要时手动删除。

**升级**：直接运行新版本的安装器，它会先停止服务再覆盖文件。目前没有自动更新。

## 使用

1. 打开开始菜单里的 ProcRoute。
2. **节点**：粘贴分享链接或订阅地址导入。测延迟前，先在「设置」里填写一个 `https://` 的测速地址；软件不内置任何地址。
3. **方案**：新建方案，选择模式（精确 / TUN），添加进程组。每个组包含要代理的进程（可从运行中的进程列表选择）和要使用的节点；可选择是否包含子进程。
4. 在顶部状态条选择方案并启动会话。状态条会如实显示服务、驱动、内核三个组件的状态；进入阻断状态时会明确提示「目标进程网络已阻断」。
5. **连接**页可以看到「哪个进程 → 哪个目标 → 走了哪个出站」。

遇到问题时：服务日志在 `C:\ProgramData\ProcRoute\logs\svc.log`；「设置 → 导出诊断包」会生成脱敏的报告（不含凭据、节点地址），保存到「下载」文件夹。

## 架构

| 进程 | 权限 | 职责 |
| --- | --- | --- |
| `procroute-ui.exe`（Tauri 2 + React 19） | 普通用户 | 展示与编辑，只通过命名管道调用服务 |
| `procroute-svc.exe`（Rust，Windows 服务） | LocalSystem | 唯一的特权进程：驱动、配置、凭据（DPAPI 加密）、sing-box 生命周期 |
| `sing-box.exe` | 继承服务 | 协议、DNS、出站；入站与控制 API 只监听 127.0.0.1，每次启动随机端口与凭据 |

详细设计见 [`docs/design.md`](./docs/design.md)，架构决策见 [`docs/adr/`](./docs/adr/)。

## 开发

- 开发约定与命令表：[`AGENTS.md`](./AGENTS.md)（开始任何改动前先读）；
- 硬性约束：[`CONSTRAINTS.md`](./CONSTRAINTS.md)；
- Windows 开发机一次性配置（管理员 PowerShell）：[`scripts/setup-windows-dev.ps1`](./scripts/setup-windows-dev.ps1)。
  另外需要在「Windows 功能」里启用 **Windows 沙盒**。

工具链：Rust 版本由 `rust-toolchain.toml` 锁定；Node.js 版本见 `.nvmrc`；包管理器用 pnpm；打包需要 PowerShell 7。

### 日常命令

```powershell
cargo xtask fetch-deps                       # 拉取锁定版本的 sing-box 与 WinDivert（按 SHA256 校验）
cargo nextest run --workspace                # 全部单元测试（不加载驱动，开发机上可跑）
pnpm -C app dev                              # 浏览器里开发界面（内置模拟服务）
$env:VITE_IPC_MOCK='1'; pnpm -C app exec tauri dev   # 桌面外壳 + 模拟服务
```

### 只在虚拟机里运行的部分

加载驱动、注册服务、改动网络设置的事一律不在开发机上做（C-TEST-04、AGENTS 第 8 节）。仓库用 Windows Sandbox 作为这类测试的虚拟机，程序在开发机上编译，进沙盒运行：

```powershell
cargo xtask sandbox-test [--only <测试名>]   # 驱动、WFP、ETW 测试，以及精确模式的端到端测试 precise_e2e
cargo xtask sandbox-dev                      # 在沙盒里运行真实的服务与界面，供手动联调（沙盒保持打开）
cargo xtask sandbox-install                  # 在沙盒里验证安装器：安装、服务与界面、伪造界面被拒绝、卸载后无残留
```

`precise_e2e` 不需要外网：测试自己起一个 SOCKS5 节点作为「远端代理」，验证目标进程的 TCP、UDP 与子进程经过节点，非目标进程与停止会话后不经过。

提交前必须通过的检查见 [`AGENTS.md`](./AGENTS.md) 第 3.3 节。

### 发版

在 GitHub 上发布 Release，tag 形如 `v1.2.3`。工作流会跑 CI，按 tag 打包并上传安装器、校验和与构建证明，不需要任何密钥。详见 [`AGENTS.md`](./AGENTS.md) 第 3.2 节。

## 许可证

ProcRoute 以 GPL-3.0-or-later 发布，见 [`LICENSE`](./LICENSE)。

第三方组件（各自的锁定版本与核对记录见对应目录）：

- [sing-box](https://github.com/SagerNet/sing-box) 1.14.4，GPL-3.0-or-later（[`third_party/sing-box`](./third_party/sing-box/README.md)）；
- [WinDivert](https://github.com/basil00/WinDivert) 2.2.2，按 LGPL-3.0 使用（[`third_party/windivert`](./third_party/windivert/README.md)）。

其余依赖的声明见 [`NOTICE`](./NOTICE)；安装器会把许可证文件一并装到安装目录的 `licenses\` 下。
