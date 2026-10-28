# TASKS.md — ProcRoute 细粒度开发任务

> 本文件把 ProcRoute 拆成一个个小到「一次一个模块、甚至一个文件」的任务，供**较弱的编码模型**逐条实现。
> 配合 `AGENTS.md`（流程与约定）和 `CONSTRAINTS.md`（硬约束）使用。

---

## 0. 怎么用这份清单（面向弱模型的开发方式）

弱模型容易跑偏、容易一次改太多、容易忘约束。所以把每个任务做小、做死、做可验证，一次只喂一个任务。

**每次对编码 Agent 的输入固定三段：**

1. **上下文**：固定附上 `AGENTS.md` + `CONSTRAINTS.md`（这两个文件放进项目根目录，Claude Code 会自动读 `AGENTS.md`）。
2. **任务**：从本文件**原样复制一条**任务，不要一次给多条。
3. **收尾指令**：固定一句——「只做这一条任务；完成后运行该任务的『验收命令』并贴出结果；不要改动任务『产出文件』之外的文件；涉及 `CONSTRAINTS.md` 的条款在回复里列出编号」。

**每条任务做完后，由你（人）或一个单独的审查步骤检查：**

- 产出文件是否只限于任务声明的范围（弱模型常顺手改别的文件）。
- 验收命令是否真的通过（让它贴真实输出，不接受「应该能过」）。
- 是否违反任务列出的约束编号。

**三个硬规矩，贴进每次提示里：**

- 一次一个任务，一个任务一个提交（commit message 用 `AGENTS.md` 第 7 节的格式）。
- 不许为了让测试通过而放宽断言或加 `#[ignore]`（C-TEST-03）。
- 拿不准、或要动 `CONSTRAINTS.md` 的任何条款，**停下来问人**，不要自己绕过（`AGENTS.md` 第 8 节）。

**任务字段说明：**

- `前置`：必须先完成的任务号。按顺序做就不会缺前置。
- `产出`：这条任务允许创建或修改的文件，别的不碰。
- `约束`：实现时必须满足的 `CONSTRAINTS.md` 条款。
- `验收`：一条可运行的命令 + 期望结果。命令过不了就是没做完。

**并行与依赖**：`crates/proto`、`crates/config`、`crates/rules`、`crates/relay` 以及 `intercept` 的 trait 与 mock 可在 Linux/macOS 上开发，不依赖 Windows，适合先做、也适合多人/多轮并行。带 `[Windows]` 的任务需要 Windows 环境。

---

## 进度

| 阶段 | 已完成 | 下一条 |
| --- | --- | --- |
| M0 | T-000 ~ T-010、T-020 ~ T-022、T-030 ~ T-033、T-040 ~ T-042 | M0 中需要 Windows 的验证：WinDivert 改道原型（见 M0 里程碑验收） |
| M1 | T-050 ~ T-054、T-057、T-058（部分，见下）、T-060 ~ T-062 | T-055 需先锁定 sing-box 版本；T-058 的 node.* 需先定分享链接/订阅的支持范围 |
| M2 | T-070、T-073、T-074 | T-071（需要 Windows） |
| M3 | T-090、T-096、T-097 | T-091（需要 Windows）；T-092、T-095 依赖 T-055 |

偏离原计划的地方：

- `Profile` 定义在 proto，rules 依赖 proto 而非 config（docs/adr/0001）。
- 前端 Tauri 事件名把 `.` 换成 `:`，例如 `conn.subscribe` → `ipc:conn:subscribe`（app/src/api/client.ts）。
- `IpcError` 增加可选的 `fields`（`path` + `code` + `message`），表单据此把服务端校验问题标到对应字段；
  `procroute-config::validate::to_ipc_error` 负责转换。属于新增可选字段，协议版本不变。
- 浏览器里开发时（开发构建且不在 Tauri 中），`client.ts` 使用 `app/src/api/mock/` 的内存模拟服务；
  生产构建通过 `import.meta.env.DEV` 整体剔除，不随安装包分发示例地址（C-SEC-09）。
- ui.shadcn.com 在构建环境中不可达，`components/ui/` 的组件源码取自 shadcn-ui/ui 仓库（MIT，见 NOTICE）。
  表单里的下拉框使用原生 `<select>` 包装（`components/NativeSelect.tsx`），便于 register 与测试。
- Win32 绑定用 `windows-sys` 0.61（tokio/mio 已依赖同一版本），没有再引入 `windows` crate（C-DEP-03）。
  platform-win 用自己的 `[lints]`：crate 级 `unsafe_code = "deny"`，只在调用 Win32 的模块局部放开，
  并开启 `clippy::undocumented_unsafe_blocks`。
- T-054：交互用户在管道 DACL 里拿到的是 `GRGW` 而不是更窄的掩码。标准客户端打开方式（`GENERIC_READ|GENERIC_WRITE`）
  会请求 `FILE_APPEND_DATA`（对管道即 `FILE_CREATE_PIPE_INSTANCE`），收窄会让 UI 连不上，而自定义掩码打开需要
  UI 侧 `unsafe`。只有交互用户本人能因此添加实例；名字抢注由 `FILE_FLAG_FIRST_PIPE_INSTANCE` 挡住。详见 `acl.rs` 模块文档。
- T-057：Win32 部分（管道客户端 PID/映像/SID、Authenticode、服务分派器）放在 platform-win 的 `process`、
  `authenticode`、`service` 模块；客户端校验单独放 `crates/svc/src/client_auth.rs`。管道上一行一条 JSON-RPC 消息
  （`\n` 或 `\r\n` 结尾，不含行尾不超过 1 MiB）。签名校验关闭吊销检查、只用本地缓存（C-SEC-08）。
  开发构建可开 `insecure-skip-client-auth` 特性跳过客户端校验，release 构建开启会编译失败（C-SEC-02）。
- T-058 只完成了一部分：`profile.*`、`session.status`/`session.stop`、配置目录 ACL（`platform-win::dir_acl`，C-SEC-05）、
  服务模式日志 `logs\svc.log`。`session.start` 返回 `kernel.unavailable`（等 T-055）；`node.*` 等未接入的方法返回
  `internal.error`，不假装成功。DPAPI（T-053）因此暂无调用方。日志暂无轮转。
- 服务启动后禁用多余令牌特权（C-SEC-06）尚未实现，随 T-056（sing-box 守护）一起做。
- relay 不在连接关闭时删除 NAT 表项：拦截层改写最后的 FIN/ACK 还要用它，由拦截层的 `Closed` 事件或空闲超时回收。
- T-055 / T-092 / T-095（sing-box 配置生成）暂缓：需要先在 `third_party/sing-box/` 锁定版本与 SHA256（单独 PR，C-DEP-04），
  再用该版本的 `sing-box check` 做回归；生成器必须以锁定版本的配置格式为准（AGENTS 第 9 节）。

## 阶段 M0 — 脚手架与可跨平台内核（第 1–2 周）

### T-000 workspace 骨架
- 前置：无
- 产出：`Cargo.toml`（workspace）、`rust-toolchain.toml`、`.gitignore`、`LICENSE`(GPL-3.0)、`NOTICE`(占位)、`README.md`(一句话)
- 约束：C-DEP-01
- 做什么：建空 workspace，members 先留空数组；`rust-toolchain.toml` 锁定 edition 2024 的稳定版。
- 验收：`cargo metadata --format-version 1` 成功返回；`cargo fmt --all --check` 通过。

### T-001 cargo-deny 许可白名单
- 前置：T-000
- 产出：`deny.toml`
- 约束：C-DEP-02
- 做什么：按 C-DEP-02 的白名单写 licenses 段，`deny.toml` 中 copyleft/unknown 默认 deny。
- 验收：`cargo deny check licenses` 通过（空 workspace 下应为 0 问题）。

### T-002 CI 工作流
- 前置：T-000
- 产出：`.github/workflows/ci.yml`
- 约束：C-CODE-03、C-DEP-02
- 做什么：两个 job——Linux 上跑 `fmt --check` + `clippy -D warnings` + 跨平台三件套 nextest + `cargo deny check`；Windows 上跑全量 nextest（此时可先只跑已存在的 crate）。
- 验收：本地 `act` 或推分支后 CI 绿；至少 `cargo fmt --all --check` 在本地通过。

### T-003 proto crate 骨架
- 前置：T-000
- 产出：`crates/proto/Cargo.toml`、`crates/proto/src/lib.rs`
- 约束：C-CODE-01（`#![forbid(unsafe_code)]`）、C-CODE-07（SPDX 头）
- 做什么：建 `procroute-proto`，lib.rs 加 SPDX 头与 `#![forbid(unsafe_code)]`；定义协议版本常量 `pub const IPC_PROTOCOL_VERSION: u32 = 1;`。把它加进 workspace members。
- 验收：`cargo build -p procroute-proto` 成功。

### T-004 proto：会话方法类型
- 前置：T-003
- 产出：`crates/proto/src/session.rs`（在 lib.rs 中 `mod session;`）
- 约束：C-ARCH-04、C-CODE-07
- 做什么：定义 `session.start` / `session.stop` / `session.status` 的入参与返回结构体，serde 可序列化；字段 `snake_case`。
- 验收：`cargo test -p procroute-proto`（含一个 serde round-trip 单测）通过。

### T-005 proto：方案方法类型
- 前置：T-003
- 产出：`crates/proto/src/profile.rs`
- 约束：C-ARCH-04
- 做什么：定义 `profile.list` / `profile.get` / `profile.save` / `profile.delete` 的入参与返回类型（`Profile` 结构体先放最小字段，后续 T-020 对齐）。
- 验收：`cargo test -p procroute-proto` 通过。

### T-006 proto：节点方法类型
- 前置：T-003
- 产出：`crates/proto/src/node.rs`
- 约束：C-ARCH-04、C-SEC-04（凭据字段用专门的掩码类型，不裸露 String）
- 做什么：定义 `node.import` / `node.list` / `node.test` 类型；节点返回里的凭据字段用 `Masked` 占位类型（只存掩码串）。
- 验收：`cargo test -p procroute-proto` 通过。

### T-007 proto：事件类型
- 前置：T-003
- 产出：`crates/proto/src/event.rs`
- 约束：C-ARCH-04
- 做什么：定义 `conn.subscribe`、`log.subscribe`、`driver.status` 的事件负载类型（连接事件含 process/target/outbound/bytes/started_at）。
- 验收：`cargo test -p procroute-proto` 通过。

### T-008 proto：错误码
- 前置：T-003
- 产出：`crates/proto/src/error.rs`
- 约束：C-ARCH-07
- 做什么：定义 IPC 错误枚举，错误码字符串格式 `<领域>.<原因>`（如 `profile.invalid_schema`、`driver.not_loaded`、`ipc.version_mismatch`）。
- 验收：`cargo test -p procroute-proto` 通过（含 code 字符串断言）。

### T-009 xtask 骨架
- 前置：T-000
- 产出：`xtask/Cargo.toml`、`xtask/src/main.rs`、`.cargo/config.toml`(alias `xtask`)
- 约束：C-CODE-07
- 做什么：建 `xtask` 二进制，支持子命令分发（先只有 `help`）。
- 验收：`cargo xtask help` 打印可用子命令。

### T-010 xtask gen-types
- 前置：T-004、T-005、T-006、T-007、T-008、T-009
- 产出：`xtask/src/gen_types.rs`、`crates/proto` 加 ts-rs 派生、`app/src/api/generated.ts`(生成物)
- 约束：C-ARCH-04
- 做什么：用 ts-rs（或 typeshare）为 proto 类型派生 TS，`cargo xtask gen-types` 输出到 `app/src/api/generated.ts`；文件头写「生成文件，禁止手改」。
- 验收：`cargo xtask gen-types` 生成文件；`git diff --exit-code app/src/api/generated.ts` 在重复运行后无变化（幂等）。

### T-020 config：Profile 数据结构
> 已按 docs/adr/0001 调整：`Profile` 定义在 proto，config 只重新导出并负责校验与迁移；rules 依赖 proto 而非 config。
- 前置：T-003
- 产出：`crates/config/Cargo.toml`、`crates/config/src/lib.rs`、`crates/config/src/model.rs`
- 约束：C-ARCH-02（不碰 IO/平台）、C-CODE-01、C-ARCH-06
- 做什么：建 `procroute-config`，照方案第 8 节定义 `Profile`、`Group`、`MatchRule`、枚举（`Mode`、`FailPolicy`、`DnsStrategy`、`MatchType`），含 `schema_version`。
- 验收：`cargo test -p procroute-config`（serde round-trip）通过；crate 根有 `#![forbid(unsafe_code)]`。

### T-021 config：校验
- 前置：T-020
- 产出：`crates/config/src/validate.rs`
- 约束：C-ARCH-02
- 做什么：实现 `Profile::validate()`：组标签唯一、出站非空、匹配项非空、正则可编译；返回结构化错误。
- 验收：`cargo test -p procroute-config` 通过（覆盖合法与每类非法各一例）。

### T-022 config：迁移框架
- 前置：T-020
- 产出：`crates/config/src/migrate.rs`、`tests/fixtures/config/v1.json`
- 约束：C-ARCH-06、C-TEST-05
- 做什么：实现按 `schema_version` 升级的迁移入口 `migrate(value) -> Profile`；当前仅 v1，放一个 v1 fixture。
- 验收：`cargo test -p procroute-config`（加载 v1 fixture 成功）通过。

### T-030 rules：路径规范化
- 前置：T-000
- 产出：`crates/rules/Cargo.toml`、`crates/rules/src/lib.rs`、`crates/rules/src/path.rs`
- 约束：C-ARCH-02、C-DRV-04、C-CODE-01
- 做什么：建 `procroute-rules`；实现 `normalize_path`（小写、分隔符统一、去尾斜杠的纯字符串逻辑；NT→DOS 与 8.3 展开留 trait 注入，纯函数部分先做）。
- 验收：`cargo test -p procroute-rules` 通过；用 proptest 验证幂等：`normalize(normalize(p)) == normalize(p)`。

### T-031 rules：匹配项求值
- 前置：T-020、T-030
- 产出：`crates/rules/src/match_item.rs`
- 约束：C-ARCH-02
- 做什么：实现单条 `MatchRule` 对「进程名 + 规范化路径」的求值：name/path/dir(recursive)/glob/regex 五种。
- 验收：`cargo test -p procroute-rules` 通过（每种类型命中/不命中各一例）。

### T-032 rules：规则引擎
- 前置：T-031
- 产出：`crates/rules/src/engine.rs`
- 约束：C-ARCH-02
- 做什么：实现 `match_process(profile, proc) -> Decision`：排除优先 → 路径 → 目录 → 名称 → 通配/正则，首个命中生效，返回命中的组标签或「直连」。
- 验收：`cargo test -p procroute-rules` 通过；proptest 验证「排除命中时永不返回代理」。

### T-033 rules：子进程继承判定
- 前置：T-032
- 产出：`crates/rules/src/inherit.rs`
- 约束：C-ARCH-02、C-DRV-04
- 做什么：纯函数 `should_inherit(parent_decision, group_include_children, parent_created_at, child_created_at) -> bool`。
- 验收：`cargo test -p procroute-rules` 通过（父在集合内/外、开关、时间先后的组合）。

### T-040 前端脚手架 [可在任意 OS]
- 前置：无
- 产出：`app/`（Vite + React 19 + TS 工程）、`app/package.json`、`app/tsconfig.json`、`app/vite.config.ts`、`app/.eslintrc`、Tailwind v4 + shadcn/ui 初始化
- 约束：C-CODE-06
- 做什么：`pnpm create vite app --template react-ts`；装 Tailwind v4、shadcn/ui、TanStack Query/Router/Virtual、Zustand、react-i18next、RHF+Zod；开 `strict`，`eslint-plugin-react-hooks` 设 error。
- 验收：`pnpm -C app lint && pnpm -C app typecheck && pnpm -C app build` 全过。

### T-041 前端：IPC 客户端薄封装
- 前置：T-010、T-040
- 产出：`app/src/api/client.ts`
- 约束：C-CODE-09、C-CODE-07
- 做什么：照方案 13.1 实现 `call` / `subscribe` / `IpcError`，引用 `generated.ts` 的类型。
- 验收：`pnpm -C app typecheck` 通过；一个 Vitest 单测 mock `invoke` 验证 `call` 透传与错误包装。

### T-042 前端：事件订阅 hook
- 前置：T-041
- 产出：`app/src/hooks/useIpcSubscription.ts`
- 约束：C-CODE-10
- 做什么：照方案 13.3 实现环形缓冲 + rAF 批量刷新 hook，清理函数取消订阅与取消帧。
- 验收：Vitest + React Testing Library 单测：推 N 条事件只触发有限次 render，卸载后 unlisten 被调用。

### M0 里程碑验收
- 跨平台三件套全绿：`cargo nextest run -p procroute-proto -p procroute-config -p procroute-rules`。
- `cargo xtask gen-types` 幂等；前端 `lint + typecheck + build` 全过。
- （Windows，若已有 WinDivert 环境）一个手写验证脚本能把指定进程的一条 HTTP 请求改道到本地 SOCKS5（见 T-060 之后）。

---

## 阶段 M1 — TUN 模式可用（第 3–5 周）

### T-050 platform-win：crate 骨架 [Windows]
- 前置：T-000
- 产出：`crates/platform-win/Cargo.toml`、`src/lib.rs`
- 约束：C-CODE-01（本 crate 允许 `unsafe`，但每处带 `// SAFETY:`）、C-CODE-07
- 做什么：建 `procroute-platform-win`，依赖 `windows`/`windows-rs`；lib.rs 分模块占位：`path`、`dpapi`、`acl`、`service`、`secret`。
- 验收：`cargo build -p procroute-platform-win`（Windows）成功。

### T-051 platform-win：Secret 包装
- 前置：T-050
- 产出：`crates/platform-win/src/secret.rs`
- 约束：C-SEC-04
- 做什么：`Secret<T>` 包装：`Debug`/`Display` 输出 `***`，提供显式 `expose()`。
- 验收：`cargo test`（Windows）通过；单测断言 `format!("{:?}", Secret::new("x"))` 不含明文。

### T-052 platform-win：路径补全
- 前置：T-050、T-030
- 产出：`crates/platform-win/src/path.rs`
- 约束：C-DRV-04
- 做什么：实现 NT 设备路径→DOS 路径、8.3 短名展开，注入给 `rules` 的规范化。
- 验收：`cargo test`（Windows）通过（真实系统盘路径各一例）。

### T-053 platform-win：DPAPI
- 前置：T-050
- 产出：`crates/platform-win/src/dpapi.rs`
- 约束：C-SEC-04
- 做什么：封装机器范围 DPAPI 加解密 `protect/unprotect`。
- 验收：`cargo test`（Windows）通过：`unprotect(protect(x)) == x`。

### T-054 platform-win：命名管道 ACL
- 前置：T-050
- 产出：`crates/platform-win/src/acl.rs`
- 约束：C-SEC-01
- 做什么：构造只授予 SYSTEM/Administrators/当前交互用户、拒绝远程的安全描述符。
- 验收：`cargo test`（Windows）通过：建管道后用非授权令牌连接被拒（能测到的部分）。

### T-055 core-mgr：sing-box 配置生成（TUN） [Windows]
- 前置：T-020、T-005
- 产出：`crates/core-mgr/Cargo.toml`、`src/lib.rs`、`src/config_gen.rs`
- 约束：C-ARCH-03、C-ARCH-05、C-NET-08
- 做什么：由 `Profile`(mode=tun) 生成 sing-box 配置：TUN 入站 + auto-route + `process_path`/`process_name` 路由规则；入站/控制 API 绑定回环、随机端口与凭据。
- 验收：`cargo test`（Windows）：生成的 JSON 过 `sing-box check -c <file>`（用锁定版本二进制）。

### T-056 core-mgr：子进程守护
- 前置：T-055
- 产出：`crates/core-mgr/src/supervisor.rs`
- 约束：C-SEC-06、C-PERF-05
- 做什么：按锁文件校验 SHA256 后从安装目录启动 sing-box；崩溃自动重启（1 分钟最多 3 次），超出则上报停止。
- 验收：`cargo test`（Windows）：杀掉子进程后被重启；第 4 次崩溃在 1 分钟内触发停止信号。

### T-057 svc：服务骨架 + 命名管道 server [Windows]
- 前置：T-003、T-054
- 产出：`crates/svc/Cargo.toml`、`src/main.rs`、`src/ipc_server.rs`
- 约束：C-ARCH-01、C-SEC-01、C-SEC-02、C-SEC-03
- 做什么：Windows 服务入口；起带 ACL 的命名管道，JSON-RPC 收发；校验客户端可执行路径与签名；每请求 schema 校验 + 1MB 上限；版本不匹配回 `ipc.version_mismatch`。
- 验收：`cargo test`（Windows）：合法请求回包正常；超限消息被拒；版本不符被拒。

### T-058 svc：接上 session/profile/node 方法
- 前置：T-057、T-022、T-055、T-053
- 产出：`crates/svc/src/handlers/*.rs`
- 约束：C-SEC-03、C-SEC-04、C-ARCH-05
- 做什么：实现各 IPC handler：profile 读写走 config + DPAPI 存凭据；修改类方法写审计日志（不含凭据）；session.start(tun) 调 core-mgr。
- 验收：`cargo test`（Windows）：profile.save→get round-trip，凭据读回为掩码；审计日志不含明文。

### T-060 app：路由与骨架页
- 前置：T-040、T-041
- 产出：`app/src/routes/*`、`app/src/App.tsx`、`app/src/i18n/*`
- 约束：C-CODE-06、C-UI-04
- 做什么：TanStack Router 配置方案/节点/连接/日志/设置五个路由；接 QueryClientProvider；i18n 初始化 zh-CN/en-US。
  另外：未检测到 Tauri 运行环境时（`pnpm -C app dev` 在浏览器里打开），`src/api/client.ts` 改用内存里的模拟服务，返回设计稿里的示例数据，方便在开发机上做界面而不连真实服务。
- 验收：`pnpm -C app build` 通过；`pnpm -C app test` 下路由冒烟测试通过。

### T-061 app：节点与方案的 feature 模块
- 前置：T-060、T-042
- 产出：`app/src/features/node/*`、`app/src/features/profile/*`
- 约束：C-CODE-09、C-SEC-10、C-UI-03
- 做什么：照方案 13.2 写 `api.ts`（Query/Mutation）；列表与编辑组件用 shadcn/ui + RHF+Zod；凭据字段只写不回显明文；外部数据纯文本渲染。
- 验收：`pnpm -C app lint && typecheck && test`；组件测试用 mock 的 `call` 验证保存流程。

### T-062 app：会话开关与状态条
- 前置：T-061
- 产出：`app/src/features/session/*`
- 约束：C-UI-01、C-UI-02
- 做什么：启动/停止会话按钮（可一键撤销）；状态条如实显示服务/驱动/内核三态；fail-closed 时明确提示「目标进程网络已阻断」。
- 验收：组件测试覆盖三态渲染与阻断提示。

### M1 里程碑验收
- 普通用户安装后，选定进程经 TUN 模式走代理（手动 e2e）。
- `cargo nextest run --workspace`（Windows）全绿；前端 `lint+typecheck+test+build` 全过。

---

## 阶段 M2 — 精确进程模式 / TCP（第 6–9 周，核心）

### T-070 intercept：trait 与假后端
- 前置：T-003
- 产出：`crates/intercept/Cargo.toml`、`src/lib.rs`、`src/backend.rs`（`Interceptor` trait）、`src/mock/`
- 约束：C-DRV-06、C-ARCH-02
- 做什么：定义 `Interceptor` trait（开始/停止、流事件、改写接口）；提供可在非 Windows 跑的 mock 后端供上层测试。
- 验收：`cargo test -p procroute-intercept`（mock，可跨平台）通过。

### T-071 intercept：WinDivert FFI 封装 [Windows]
- 前置：T-070、T-050
- 产出：`crates/intercept/src/divert/ffi.rs`、`third_party/windivert/`（锁版本+SHA256+LICENSE）
- 约束：C-DRV-01、C-DRV-02、C-CODE-01、C-DEP-04
- 做什么：`// SAFETY:` 包裹 WinDivert open/recv/send/close 的 FFI；只用锁定版本驱动；句柄绑定对象生命周期，Drop 时关闭。
- 验收：`cargo test`（Windows）：能 open/close 句柄，Drop 后驱动过滤被撤销。

### T-072 intercept：SOCKET 层归属
- 前置：T-071、T-033
- 产出：`crates/intercept/src/divert/socket.rs`
- 约束：C-NET-02、C-DRV-04
- 做什么：嗅探 SOCKET 层 CONNECT 事件，拿 PID/本地端口/远端；命中目标集合登记进流表；非目标只读元数据不改写。
- 验收：`cargo test`（Windows，受控进程）：目标进程 connect 被登记，其他进程不被登记。

### T-073 relay：NAT 表
- 前置：T-003
- 产出：`crates/relay/Cargo.toml`、`src/nat.rs`
- 约束：C-PERF-04、C-ARCH-02
- 做什么：映射端口→(原始目标,PID,规则) 表；TCP 300s/UDP 60s 空闲回收；上限 65536，超限对新流按 fail_policy，不淘汰活跃流。
- 验收：`cargo test -p procroute-relay`（可跨平台）：插入/查找/超时回收/超限行为。

### T-074 relay：本地 TCP 中继 + SOCKS5 客户端
- 前置：T-073
- 产出：`crates/relay/src/tcp.rs`、`src/socks5.rs`
- 约束：C-NET-03、C-NET-08、C-CODE-05
- 做什么：中继按映射端口取原始目标，向 sing-box 本地 SOCKS5 发起 CONNECT（用户名=出站组标签）；sing-box 不可达时对新连接回 RST，绝不直连。
- 验收：`cargo test -p procroute-relay`：对假 SOCKS5 正常转发；SOCKS 不可达时 fail-closed（回 RST，无直连）。

### T-075 intercept：NETWORK 层改写 + 回程 [Windows]
- 前置：T-072、T-074
- 产出：`crates/intercept/src/divert/network.rs`、`src/divert/worker.rs`
- 约束：C-NET-02、C-CODE-04、C-CODE-05
- 做什么：只抓流表内五元组出站包改写去向到中继，回程反向改写注入；收发在专用 OS 线程，经有界 channel 交互；热路径零堆分配、零全局锁。
- 验收：`cargo test`（Windows）：目标进程 TCP 连接经中继到达；回程可达；无目标进程流量不受影响。

### T-076 intercept：首包竞态 + 端口反查
- 前置：T-075
- 产出：`crates/intercept/src/divert/pending.rs`
- 约束：C-NET-04
- 做什么：首个 SYN 早于 SOCKET 事件时暂存≤50ms，用 `GetExtendedTcpTable` 反查 PID；仍无法归属按非目标放行并计 `attribution_miss`。
- 验收：`cargo test`（Windows）：构造竞态场景，暂存命中归属；超时走反查；指标递增。

### T-077 intercept/relay：防回环与自保护
- 前置：T-075
- 产出：`crates/intercept/src/divert/exclude.rs`
- 约束：C-NET-05、C-NET-06
- 做什么：永久排除 sing-box/svc/ui 自身、回环、链路本地、代理服务器 IP；代理地址变更 1s 内更新；服务退出 3s 内撤销全部过滤。
- 验收：`cargo test`（Windows）：排除表命中直连；停止服务后过滤器清零、无残留。

### T-078 svc：精确模式接线 + fail_policy
- 前置：T-075、T-058
- 产出：`crates/svc/src/handlers/session.rs`(扩展)
- 约束：C-NET-03、C-NET-07
- 做什么：session.start(precise) 组装 procwatch+intercept+relay+core-mgr；`fail_policy` 默认 block；无法处理的包按策略处理不静默放行。
- 验收：`cargo test`（Windows）集成：精确模式启动后目标 TCP 走代理；杀 sing-box 后新连接失败不直连。

### T-079 procwatch：进程追踪 [Windows]
- 前置：T-050、T-033
- 产出：`crates/procwatch/Cargo.toml`、`src/lib.rs`、`src/etw.rs`、`src/snapshot.rs`
- 约束：C-DRV-04、C-ARCH-02
- 做什么：ETW ProcessStart/Stop 维护进程树（PID+创建时间）；启动时 Toolhelp 快照补登；暴露目标集合变更给 intercept。
- 验收：`cargo test`（Windows）：启动子进程后 1s 内进入集合；PID 复用不误判。

### T-080 测试：泄漏检测器 [Windows]
- 前置：T-075
- 产出：`tests/e2e/leak_detector.rs`、`tests/e2e/echo_target.rs`
- 约束：C-TEST-02、C-TEST-04
- 做什么：旁路统计目标 PID 发往非代理服务器地址的包；配一个 TCP 回显目标进程。只在虚拟机跑。
- 验收：在 VM 中对已知泄漏/不泄漏场景各判定正确。

### M2 里程碑验收（核心门槛）
- 精确模式 1 小时混合 TCP 流量，泄漏检测器计数为 0；非目标进程出口 IP/路由/DNS 不变。
- `attribution_miss` 不超过基线；杀 sing-box 后 fail-closed 生效。

---

## 阶段 M3 — UDP、DNS 与子进程（第 10–13 周）

> 颗粒度同上，每条仍是「一个模块 + 验收命令」。

### T-090 relay：UDP 会话表与中继
- 前置：T-073、T-074 — 产出：`crates/relay/src/udp.rs` — 约束：C-NET-07
- 做什么：按「本地地址+端口」建会话保持 full-cone；每会话一个 SOCKS5 UDP ASSOCIATE；回包按会话改写注入。
- 验收：`cargo test -p procroute-relay`：一端口对多远端仍同一会话；回包正确。

### T-091 intercept：UDP 劫持 + IPv6 分片 [Windows]
- 前置：T-075、T-090 — 产出：`crates/intercept/src/divert/udp.rs` — 约束：C-NET-07
- 做什么：劫持目标进程 UDP；IPv6 分片先重组再处理，失败按 fail_policy，不静默放行。
- 验收：`cargo test`（Windows）：游戏类 UDP 回显通过；构造分片失败走策略。

### T-092 core-mgr：DNS 嗅探策略
- 前置：T-055 — 产出：`crates/core-mgr/src/dns.rs` — 约束：C-NET-09
- 做什么：默认 sniff——劫持目标进程直发 53 + 对改道连接开 TLS/HTTP/QUIC 嗅探覆盖目标地址；system_takeover 默认关、需确认、退出恢复。
- 验收：`cargo test`（Windows）：生成配置含嗅探；被污染域名在集成测试中可连通。

### T-093 intercept：QUIC 阻断开关
- 前置：T-091 — 产出：`crates/intercept/src/divert/quic.rs` — 约束：C-NET-07
- 做什么：按 `udp.block_quic` 阻断目标进程 UDP 443 迫使回落 TCP。
- 验收：`cargo test`（Windows）：开关开启时 443/udp 被丢。

### T-094 svc：子进程继承接线
- 前置：T-079、T-078 — 产出：`crates/svc/src/handlers/session.rs`(扩展) — 约束：C-DRV-04
- 做什么：procwatch 的新进程事件按 `include_children` 并入目标集合；方案切换时快照补登。
- 验收：`cargo test`（Windows）集成：启动器拉起的子进程 1s 内被代理。

### T-095 svc：多出站分组
- 前置：T-078、T-055 — 产出：`crates/core-mgr/src/config_gen.rs`(扩展) — 约束：C-ARCH-05
- 做什么：不同组用 SOCKS 用户名=组标签，sing-box 用 `auth_user` 路由到各出站。
- 验收：`cargo test`（Windows）：两组流量分别命中两个出站。

### T-096 app：连接面板（虚拟化）
- 前置：T-042、T-062 — 产出：`app/src/features/conn/*` — 约束：C-CODE-10、C-SEC-10
- 做什么：照方案 13.4 实现虚拟化连接表，消费 `useIpcSubscription('conn.subscribe')`。
- 验收：`pnpm -C app test`：注入上千条事件界面不卡、渲染次数有限。

### T-097 app：日志查看
- 前置：T-096 — 产出：`app/src/features/log/*` — 约束：C-CODE-10、C-SEC-04
- 做什么：虚拟化日志视图 + 级别过滤；展示层不含凭据。
- 验收：`pnpm -C app test` 通过。

### M3 里程碑验收
- 游戏类 UDP 可用；被污染域名可连通；子进程 1s 内纳入；多出站分流正确。

---

## 阶段 M4 — 加固与发布 v1.0（第 14–16 周）

### T-110 打包与签名
- 前置：各 crate 完成 — 产出：`app/src-tauri/tauri.conf.json`、`xtask/src/bundle.rs`、`NOTICE`(完整)
- 约束：C-SEC-10、C-DEP-05、C-NET-06
- 做什么：Tauri NSIS 打包 + 服务注册；严格 CSP、capabilities 最小化；Authenticode 签名；卸载清理服务/驱动/防火墙规则；`NOTICE` 列全第三方。
- 验收：安装→升级→卸载后无残留（VM 验证脚本）。

### T-111 自动更新
- 前置：T-110 — 产出：`app/src-tauri/updater.*` — 约束：C-DEP-04、C-SEC-08
- 做什么：独立签名密钥校验更新包；更新检查可在设置关闭。
- 验收：对篡改包拒绝安装；关闭后无自动请求。

### T-112 诊断包导出（脱敏）
- 前置：T-058 — 产出：`crates/svc/src/diag.rs`、`app/src/features/settings/*` — 约束：C-SEC-04
- 做什么：导出日志/状态诊断包，自动脱敏节点地址与凭据。
- 验收：导出物经扫描无明文凭据/完整节点地址。

### T-113 托盘、自启、方案切换
- 前置：T-062 — 产出：`app/src-tauri/tray.*`、`app/src/features/settings/*` — 约束：C-UI-01
- 做什么：托盘菜单、开机自启开关、一键切换方案。
- 验收：手动验证 + 组件测试覆盖切换逻辑。

### T-114 性能调优与基准
- 前置：T-078、T-090 — 产出：`tests/perf/*` — 约束：C-PERF-01、C-PERF-02、C-PERF-03
- 做什么：TCP 吞吐/新建连接延迟/并发基准；接入 CI 退化门槛。
- 验收：满足 C-PERF-01/02；相对基线退化>10% 时 CI 失败。

### M4 / v1.0 验收
- 跑通 `docs/design.md` 第 12.2 节全部验收清单；Win10 22H2 与 Win11（内存完整性开/关）矩阵全绿。

---

## 附：给审查步骤的小抄

每条任务合并前核对：

1. 只动了 `产出` 列的文件？（`git diff --stat` 对照）
2. `验收` 命令真实通过？（要真实输出）
3. 任务 `约束` 列的条款没破？尤其 C-NET-03（fail-closed）、C-NET-05（防回环）、C-ARCH-02（依赖方向）、C-CODE-09（前端分层）。
4. 非测试代码没有 `unwrap/panic/todo`（C-CODE-02）？`unsafe` 只在允许的 crate 且带 `// SAFETY:`（C-CODE-01）？
5. 提交信息符合 Conventional Commits，PR 描述列了涉及的约束编号（AGENTS 第 7 节）。
