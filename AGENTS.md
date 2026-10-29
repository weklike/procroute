# AGENTS.md — ProcRoute

> 本文件写给在本仓库工作的编码 Agent（Claude Code、Codex、Cursor 等）和新加入的开发者。
> 开始任何任务前，先完整阅读本文件和 [`CONSTRAINTS.md`](./CONSTRAINTS.md)。
> **两者冲突时以 `CONSTRAINTS.md` 为准**；`CONSTRAINTS.md` 中的条款不得自行修改或绕过。

---

## 1. 项目是什么

ProcRoute 是一个 Windows 优先的进程级代理客户端，对标 Netch 的「进程模式」：
只让用户指定的进程（及其子进程）走代理，其余流量完全不受影响。

- **精确进程模式**（默认）：WinDivert 识别目标进程的流并改写数据包 → 本地重定向器（NAT 表 + 中继）→ sing-box 的本地 SOCKS5 入口 → 代理服务器。不修改系统路由。
- **TUN 分流模式**（兜底）：由 sing-box 的 TUN 入站 + `process_path` / `process_name` 规则完成，服务只负责生成配置和守护进程。

三个运行时进程：

| 进程 | 权限 | 职责 |
| --- | --- | --- |
| `procroute-ui.exe`（Tauri 2 + React 19） | 普通用户 | 展示与编辑；只通过命名管道调用服务 |
| `procroute-svc.exe`（Rust，Windows 服务） | LocalSystem | 唯一特权进程：驱动、配置、凭据、sing-box 生命周期 |
| `sing-box.exe`（子进程） | 继承服务 | 协议、DNS、嗅探、出站分组；只监听 127.0.0.1 |

完整设计见 `docs/design.md`（由项目方案导出），架构决策见 `docs/adr/`。

---

## 2. 仓库地图

```text
crates/
  proto/         IPC 方法与消息类型（唯一事实来源），导出 TS 定义     [跨平台]
  config/        Profile / 规则模型、校验、schema 迁移                 [跨平台]
  rules/         进程匹配引擎，纯函数，无 IO                           [跨平台]
  procwatch/     进程追踪：ETW 事件 + Toolhelp 快照，维护进程树          [Windows]
  intercept/     Interceptor trait 与后端：divert/、tun/（预留 ndis/）  [Windows；trait、判定逻辑与 mock 跨平台]
  relay/         NAT 表、本地 TCP/UDP 中继、SOCKS5 客户端               [跨平台]
  core-mgr/      节点模型与分享链接解析、sing-box 配置生成、子进程守护、控制 API 客户端  [Windows；守护以外跨平台]
  platform-win/  Windows API 封装：路径规范化、DPAPI、ACL、服务控制      [Windows；Secret<T> 跨平台]
  svc/           二进制：Windows 服务入口，唯一的组装点                 [Windows]
app/
  src-tauri/     Rust（包名 procroute-ui）：控制管道客户端 ipc.rs、窗口 / 托盘 / 开机自启 shell.rs（只依赖 proto）
  src/           React 19 + TypeScript
    routes/        页面与路由定义（TanStack Router）
    features/      按领域划分：session/ profile/ node/ conn/ log/，各自含 api.ts（Query hooks）与组件
    components/    通用组件；components/ui/ 为 shadcn/ui 组件源码
    hooks/         通用 hooks，含 useIpcSubscription
    stores/        Zustand store（只放纯前端状态）
    api/           generated.ts 由 gen-types 生成（禁止手改）；client.ts 为手写 IPC 薄封装；shell.ts 为外壳命令（托盘、自启、连接状态）薄封装
    i18n/          zh-CN / en-US 文案资源
third_party/
  windivert/     锁定版本的 dll/sys + SHA256 + LICENSE（只读）
  sing-box/      版本锁文件与下载脚本（不提交二进制）
xtask/           cargo xtask：生成类型、拉取依赖、开发运行、打包、e2e
tests/e2e/       Windows 虚拟机上的端到端用例；tests/fixtures/ 测试数据
docs/            design.md、adr/
```

Crate 的包名统一为 `procroute-<目录名>`，例如 `crates/rules` → `procroute-rules`。

**依赖方向（必须遵守，详见 CONSTRAINTS C-ARCH-02）**：
`proto`、`config`、`rules` 不依赖任何平台 crate；`svc` 是唯一组装点；`app` 只依赖 `proto`。

---

## 3. 环境与命令

### 3.1 环境

- Rust：版本由 `rust-toolchain.toml` 锁定，edition 2024。
- Node.js：当前 LTS，版本以 `.nvmrc` 为准；包管理器 pnpm（版本见 `package.json` 的 `packageManager`）。
- Windows 10 22H2+ / Windows 11 x64：编译和测试 `[Windows]` 标记的 crate 需要。
- 跨平台 crate（`proto`、`config`、`rules`、`relay`，以及 `intercept` 的 trait 与 mock、`platform-win` 的 `Secret<T>`）可在 Linux / macOS 上开发和测试。

### 3.2 常用命令

| 目的 | 命令 |
| --- | --- |
| 格式化 | `cargo fmt --all` ；`pnpm -C app format` |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` ；`pnpm -C app lint` ；`pnpm -C app typecheck` |
| 跨平台单测（任意 OS） | `cargo nextest run -p procroute-proto -p procroute-config -p procroute-rules -p procroute-intercept -p procroute-relay -p procroute-platform-win -p procroute-core-mgr`（core-mgr 的 `sing-box check` 回归只在 Windows 上编译） |
| 行覆盖率（C-TEST-01） | `cargo llvm-cov nextest -p <crate> --fail-under-lines 80`（`rules`、`config`、`relay` 在 CI 中强制） |
| 全量单测（Windows） | `cargo nextest run --workspace` |
| 前端单测 | `pnpm -C app test` |
| 生成 IPC 的 TS 类型 | `cargo xtask gen-types` |
| 拉取并校验第三方二进制 | `cargo xtask fetch-deps`（Windows；按 `third_party/*/lock.json` 校验 SHA256，输出到各自的 `third_party/<组件>/bin/`：sing-box、WinDivert） |
| 驱动相关测试（只在虚拟机） | 管理员终端：`cargo nextest run -p procroute-intercept --features vm-tests`（会安装并加载 WinDivert 驱动，禁止在开发机上运行，C-TEST-04） |
| 本地开发运行 | 开发机：`pnpm -C app dev`（浏览器里打开，模拟 IPC，不连真实服务）；桌面外壳：PowerShell 里 `$env:VITE_IPC_MOCK='1'; pnpm -C app tauri dev`（同样用模拟 IPC）；完整联调：在测试虚拟机里运行 `cargo xtask dev`（控制台模式启动 svc + `tauri dev`，需要管理员终端，会加载驱动，禁止在开发机上运行，见第 8 节第 5 条） |
| 构建桌面客户端 | `pnpm -C app tauri build --debug --no-bundle`（先跑前端生产构建，再编译 `procroute-ui.exe`；不出安装包） |
| 打包安装包 | `cargo xtask bundle` |
| 端到端测试 | `cargo xtask e2e --vm <name>`（只在 Hyper-V 虚拟机中运行） |
| 依赖与许可审计 | `cargo deny check` ；`pnpm -C app audit` |
| 添加 shadcn/ui 组件 | `pnpm -C app dlx shadcn@latest add <component>` |

> 项目早期部分 xtask 子命令可能尚未实现。遇到缺失时，**先实现该命令再使用**，不要用临时脚本绕过；
> 新增命令后同步更新本表。

### 3.3 提交前必须全部通过

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo xtask fetch-deps               # 仅 Windows：core-mgr 的 sing-box check 回归需要锁定版本的二进制
cargo nextest run --workspace        # 非 Windows 环境下改为 3.2 节的跨平台单测
cargo deny check
pnpm -C app lint && pnpm -C app typecheck && pnpm -C app test
```

---

## 4. 工作流程

### 4.1 接到任务后

1. 判断任务落在哪个 crate / 目录；读该 crate 的 `README.md` 与模块文档注释。
2. 对照 `CONSTRAINTS.md` 找出与本任务相关的条款编号，在计划或 PR 描述中列出。
3. 改动尽量限制在一个 crate 内；跨 crate 改动先改 `proto` / trait，再改实现。
4. 小步提交，每一步都能编译、测试通过。

### 4.2 特定改动的附加步骤

| 改动类型 | 必须同时完成 |
| --- | --- |
| 修改 `crates/proto` | 运行 `cargo xtask gen-types`，提交生成的 `app/src/api/` 文件；破坏性变更需提升 IPC 协议版本号 |
| 修改 Profile / 配置结构 | `schema_version` +1，新增迁移函数和迁移测试（旧样例放 `tests/fixtures/config/`） |
| 修改 `intercept` / `relay` | 补充或更新单测；PR 描述说明对「泄漏」「fail-closed」「防回环」三项的影响 |
| 修改 sing-box 配置生成 | 用锁定版本的 sing-box 执行配置检查命令做回归；更新快照测试 |
| 升级 sing-box / WinDivert | 单独 PR，只改版本锁与 SHA256；附兼容性验证记录 |
| 新增 IPC 修改类方法 | 加 schema 校验、大小限制和审计日志 |
| 新增 UI 文案 | 写入 i18n 资源（默认 `zh-CN`，同步 `en-US`），不在组件里硬编码 |

### 4.3 完成定义（Definition of Done）

- [ ] 3.3 节的检查全部通过
- [ ] 新逻辑有测试覆盖；修复的 bug 有回归测试
- [ ] 没有违反 `CONSTRAINTS.md` 的任何条款；如需例外，已有获批的 ADR
- [ ] 公共 API、IPC 方法、配置字段有文档注释
- [ ] 日志中不含凭据、节点完整地址等敏感数据
- [ ] 必要时已更新本文件的命令表或仓库地图

---

## 5. 编码约定

### 5.1 Rust

- 错误：库 crate 用 `thiserror` 定义具体错误类型；`anyhow` 只允许出现在 `svc` 的 main、`xtask` 和测试中。
- 禁止在非测试代码中使用 `unwrap()` / `expect()`；确属不变量的位置用 `expect("INVARIANT: …")` 写明理由。
- 异步运行时统一 tokio。WinDivert 的阻塞式收包放在专用 OS 线程，通过有界 channel 与异步部分通信，禁止在 async 任务里阻塞。
- 日志统一 `tracing`，使用结构化字段：`tracing::info!(pid, rule = %rule_id, "flow redirected")`。
- `unsafe` 只允许出现在 `platform-win` 和 `intercept::*::ffi` 子模块；每个 `unsafe` 块上方必须有 `// SAFETY:` 注释。
- 热路径（逐包处理）内禁止分配堆内存、禁止加全局锁、禁止写 info 及以上级别日志。
- 公共类型实现 `Debug` 时，凭据字段必须手动脱敏（使用 `platform-win` 提供的 `Secret<T>` 包装）。

### 5.2 前端（React 19 + TypeScript）

技术栈：Vite、TanStack Router、TanStack Query、Zustand、TanStack Virtual、shadcn/ui（Radix + Tailwind CSS v4）、lucide-react、React Hook Form + Zod、react-i18next。

- **组件**：只用函数组件与 Hooks，禁止类组件。一个文件只导出一个组件，文件名 `PascalCase.tsx`；hooks 文件名 `useXxx.ts`。
- **类型**：TypeScript `strict: true`，禁止 `any`（确需时用 `unknown` 再收窄）；props 用 `type` 声明，不用 `React.FC`。
- **Hooks 规则**：`eslint-plugin-react-hooks` 的规则为 error，禁止用 `eslint-disable` 绕过依赖数组检查；需要稳定引用时调整代码结构，而不是关掉 lint。
- **数据分层**：`组件 → features/<领域>/api.ts 中的 Query / Mutation hook → src/api/ 生成客户端 → Tauri invoke`。组件禁止直接调用 `src/api/` 或 Tauri `invoke`。
- **状态归属**：来自服务的数据只存在 TanStack Query 缓存里，不复制进 Zustand；Zustand 只放主题、侧栏、选中项等纯前端状态，订阅时必须用 selector。
- **实时事件**：`conn.subscribe`、`log.subscribe` 统一用 `useIpcSubscription` 写入环形缓冲，按动画帧批量刷新；超过 100 行的列表必须用 TanStack Virtual。
- **组件库**：优先使用 `components/ui/` 中的 shadcn/ui 组件；修改其源码时在文件头注释写明改动点。样式用 Tailwind 工具类 + 主题 CSS 变量，不写死颜色值。
- **表单**：React Hook Form + Zod；前端校验只为体验，提交后以服务端返回的错误为准并回显到对应字段。
- **安全**：禁止 `dangerouslySetInnerHTML`、`eval`、`new Function`；节点名、订阅备注等外部数据一律按纯文本渲染；不加载任何远程脚本、字体或图片。
- **文案**：全部走 react-i18next，不在 JSX 中硬编码中文或英文。

### 5.3 命名

- IPC 方法：`<领域>.<动词>`，全小写，例如 `session.start`、`profile.save`、`conn.subscribe`。
- IPC 错误码：`<领域>.<原因>`，例如 `profile.invalid_schema`、`driver.not_loaded`。
- 配置字段：`snake_case`；枚举值：小写 `snake_case` 字符串。
- 分支：`feat/<scope>-<简述>`、`fix/<scope>-<简述>`。

---

## 6. 测试要求

- 单元测试与被测代码同文件（`#[cfg(test)] mod tests`）；跨模块测试放 crate 的 `tests/`。
- `rules`、`config` 的核心函数用 `proptest` 做属性测试（例如：路径规范化幂等、排除规则优先级恒成立）。
- `relay` 用假 SOCKS5 服务器做组件测试，覆盖：正常转发、sing-box 不可达时 fail-closed、NAT 表项超时回收。
- e2e 用例只在虚拟机中运行；判据统一使用泄漏检测器（目标 PID 发往非代理服务器地址的包计数必须为 0）。
- 前端组件与 hooks 用 Vitest + React Testing Library，按用户可见行为断言（优先 `getByRole` / `getByLabelText`），不断言内部 state 或实现细节；IPC 客户端在测试中用 mock 替换。
- UI 端到端用 tauri-driver（WebDriver），覆盖添加进程、切换方案、启动会话、连接面板四条关键流程。
- 不得为了让测试通过而放宽断言、跳过用例或增加 `#[ignore]`；确需跳过时在 PR 描述中说明并建 issue。

---

## 7. 提交与 PR

- 提交信息使用 Conventional Commits，scope 用 crate 目录名或 `app` / `docs` / `ci`：
  - `feat(relay): add UDP session table with full-cone semantics`
  - `fix(intercept): hold first SYN until socket event arrives`
- 一个 PR 只做一件事；依赖升级、格式化、重构与功能改动分开提交。
- PR 描述包含：动机、改动摘要、涉及的 CONSTRAINTS 条款编号、测试方式、风险与回滚方式。

---

## 8. 必须停下来询问人类的情况

遇到以下任一情况，**停止实现，先说明情况并等待确认**：

1. 需要修改、放宽或例外处理 `CONSTRAINTS.md` 中的任何条款。
2. 引入新的运行时依赖，尤其是：新的内核驱动、含大量 `unsafe` 的 crate、许可证不在 C-DEP-02 白名单内的包。
3. 对 IPC 或配置格式做破坏性变更。
4. 涉及代码签名证书、更新签名密钥、发布流程或 CI 密钥。
5. 需要在开发者主机（而非虚拟机）上安装或加载驱动、注册或启动 Windows 服务、修改系统路由或 DNS 设置。
6. 需求与 `docs/design.md` 描述的行为不一致，或无法在不泄漏流量的前提下实现。

---

## 9. 常见陷阱

- **DNS 归属**：大多数应用经系统 Dnscache 服务（svchost）解析，查询包不属于目标进程。不要尝试「按进程劫持全部 DNS」，用协议嗅探覆盖目标地址（见 design 6.3）。
- **PID 复用**：进程身份必须用「PID + 创建时间」，只用 PID 会误判。
- **首包竞态**：SOCKET 层事件可能晚于首个 SYN 到达，按 design 6.1 的暂存 + 反查处理，不得放行直连。
- **自身回环**：sing-box、服务、UI 自身的流量以及去往代理服务器 IP 的流量必须排除，否则会形成环路。
- **驱动文件**：驱动加载期间禁止删除或替换 `.sys`，否则可能导致反作弊拒绝启动游戏。
- **sing-box 配置版本**：其配置字段随版本频繁弃用，生成器必须以锁定版本为准，不要照搬网上的旧配置。
- **React 严格模式下 effect 执行两次**：开发环境中 effect 会挂载、卸载、再挂载。订阅类 effect 必须在清理函数里取消订阅，否则会向服务重复订阅事件流。
- **高频事件直接 setState**：连接和日志事件每秒可能上千条，逐条 `setState` 会卡死界面，必须经环形缓冲批量刷新。
