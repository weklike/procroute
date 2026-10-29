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
| M1 | T-050 ~ T-058、T-060 ~ T-062 | 在虚拟机里验证 TUN + `block` 的 WFP 阻断（`procroute-platform-win --features vm-tests`） |
| M2 | T-070、T-071（FFI 与版本锁；驱动相关测试待虚拟机验证）、T-073、T-074、T-079（ETW 部分待管理员终端验证，见下） | 在虚拟机里跑 `--features vm-tests`，通过后做 T-072 / T-075（改道到回环中继的方式需在虚拟机里试） |
| M3 | T-090、T-092（中继嗅探 + 远程 DNS，见下）、T-095（配置生成部分）、T-096、T-097 | T-091（需要 Windows）；T-095 的接线随 T-078 |
| M4 | T-113（外壳与界面部分，见下） | T-110 打包（服务注册、签名，需要先确认签名与发布流程，AGENTS 第 8 节第 4 条） |

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
- T-058：`profile.*`、`session.*`、`node.import`（分享链接）/ `node.list`、`process.list`、配置目录 ACL
  （`platform-win::dir_acl`，C-SEC-05）、服务模式日志 `logs\svc.log`。`process.list` 只列与调用者同一 Windows
  会话的进程（服务能看到所有用户的进程），并标出命中运行中会话方案的进程组。`node.test` 见下面的测速一条；
  未接入的方法（`driver.*`）返回 `internal.error`，不假装成功。日志暂无轮转。
  - `session.start` 目前只能启动 TUN 模式且 `fail_policy = allow`：精确进程模式返回 `driver.not_loaded`（等 T-071 起的
    拦截后端）；TUN + `block` 返回新增的 `session.fail_closed_unsupported`（见下面 T-055 的 C-NET-03 一条）。
    内核状态（重启中、恢复、超出重启上限）实时写回会话：`block` 进入 `blocked`，`allow` 结束会话、内核显示失败。
    内核的启动经 `svc::kernel::KernelLauncher`，测试用假实现；开发机上不真正建 TUN（C-TEST-04）。
  - TUN 模式的连接面板：会话运行期间每秒读一次内核控制 API 的连接列表（`core-mgr::clash_api`，手写 HTTP/1.0，
    不引入 HTTP 库），差异转成 `conn.subscribe` 事件（`svc::conn_watch`）。只推被改道的连接，内核路由为 `direct`
    的不推也不保留（C-NET-02）；进程组按规则引擎对进程路径重新判定；TUN 模式拿不到 PID，事件里为 0。
  - 管道上的推送：握手后每次会话状态变化都推 `session.status`；`conn.subscribe` / `log.subscribe` 由管道服务端
    处理（不进 `Handler`），订阅持续到连接断开，`log.subscribe` 按 `min_level` 过滤。服务日志经 `svc::log_stream`
    转成日志事件；sing-box 自己的输出直接丢弃（它的日志带网关、目标地址）。连接事件的来源随 M2 接入。
  - 服务在配置目录加固之后移除令牌特权，只保留 `SeTcb`（`WTSQueryUserToken`）、`SeLoadDriver`（wintun /
    WinDivert）、`SeChangeNotify`、`SeCreateGlobal`（C-SEC-06）。**待验证**：虚拟机里确认 TUN 在收窄后的令牌下可用。
- node.import 的支持范围（近五年主流客户端通用、且 sing-box 1.14.4 支持；详见 `core-mgr::link` 模块文档）：
  `ss://`（SIP002 / 旧版整段 Base64，AEAD 与 2022 加密，插件 obfs-local / v2ray-plugin）、`vmess://`（v2rayN JSON，
  只收 AEAD）、`vless://` / `trojan://`（Xray 分享链接标准，含 REALITY 与 Vision）、`hysteria2://` / `hy2://`、`tuic://`（v5）、
  `anytls://`、`socks(5)://`、`http(s)://`；订阅内容支持纯文本、整体 Base64 与 SIP008 JSON。不收录 SSR、Hysteria 1、
  SS 流加密、VMess alterId > 0、xhttp / kcp / quic 传输、WireGuard、NaiveProxy、ShadowTLS；Hysteria2 的 `pinSHA256`
  无等价选项，拒绝而不是丢弃。分享链接与 URI / Base64 解析手写，未引入新依赖。
  - 跳过原因是固定的原因代码（如 `unsupported_protocol`、`duplicate`），不回显输入；界面按代码走 i18n 翻译
    （`app/src/features/node/issues.ts`），未知代码原样显示。
  - 存储：`<配置根>\nodes.json`，参数明文、凭据按节点 DPAPI 加密后十六进制存放（C-SEC-04）；读失败时不覆盖。
    每个节点暂时就是一个 `single` 出站（标签 = 节点 id），节点组的增删改还没有 IPC 方法。
  - 订阅（2026-10-29 定用 WinHTTP）：`platform-win::http` 封装系统 WinHTTP（TLS 由 Schannel 校验，不引入 HTTP / TLS
    库），只由用户操作触发（C-SEC-08），上限 10 MB（C-SEC-07）。再次导入同一地址即刷新：内容没变的节点保留原 id。
    订阅地址可能含令牌，加密落盘，只有 `scheme://host` 出现在日志、错误与界面里（C-SEC-04）。`nodes.json` 升到
    格式 2（读到格式 1 视为没有订阅，下次写入即升级）。Clash / mihomo YAML 订阅仍不支持（需要 YAML 库，未定）。
  - 测速 `node.test`：`NodeTestParams` 新增可选的 `url`（新增可选字段，协议版本不变）。测速地址由用户在设置里填写，
    保存在界面偏好中，不内置任何地址，留空即不能测速（C-SEC-08、C-SEC-09）。服务每次调用临时启动一个**没有入站**的
    sing-box（`config_gen::generate_probe`：只有直连与节点出站和控制 API，不建 TUN、不监听代理端口），经控制 API 的
    `/proxies/{tag}/delay` 测速，16 个并行、单个 5 秒，测完即停；一次最多 64 个节点，界面分批调用，保证每次调用在
    60 秒调用超时之内。**只接受 `https://`**：锁定的 sing-box 1.14.4 在这个接口上会把 `http://` 开头的地址悄悄换成
    内置的默认测速地址（实测），既不是用户选的地址也违反 C-SEC-09；服务、`clash_api::fetch_delay` 与界面三处都拒绝。
- T-056：sing-box 的配置经标准输入（`-c stdin`）交给内核，不写进 `run\` 目录：配置里有节点凭据明文，落盘会违反
  C-SEC-04（优先于设计文档第 8 节的「写在 run\ 目录」）；`run\` 只作为 sing-box 的工作目录。版本锁在编译时嵌入
  （`core-mgr::kernel_lock`），每次（重新）启动前校验安装目录里的 `sing-box.exe`，校验到进程创建完成之间以只读共享
  持有文件；内核放进关闭即终止的作业对象，随服务退出（C-NET-06）。
- T-071：WinDivert 2.2.2 锁在 `third_party/windivert/lock.json`（上游未公布哈希；发布包哈希与 SourceForge 镜像公布的
  一致，驱动的 EV 签名有效，签名主体记录在该目录的 README，请维护者确认）。`fetch-deps` 一并拉取。服务运行时从安装
  目录按完整路径加载 `WinDivert.dll`，加载前校验 DLL 与驱动的 SHA-256，驱动文件在使用期间以只读共享方式锁定，不能被
  删除或替换（C-DRV-01、C-DRV-02）。打开句柄会加载驱动，相关测试在 `crates/intercept/tests/divert_vm.rs`，只在
  `--features vm-tests` 时编译，必须在虚拟机里以管理员身份运行（C-TEST-04）；开发机上只测 DLL 加载与过滤器语法。
  **待验证**：`WINDIVERT_ADDRESS` 里地址数组的字序（按 WinDivert 的 `ntoh` 助手推断为 `[0]` 最低位），由
  `socket_layer_reports_this_process_connects` 在虚拟机里确认。
- 桌面客户端（`app/src-tauri`，包名 `procroute-ui`）：只依赖 proto；一条长连接、断线每 2 秒重连并重放订阅。
  外壳自己的事件 `shell:connection`（与服务的连接变化，界面据此清空服务端数据，C-UI-02）与 `shell:tray`（托盘点击）
  不属于 IPC 协议，类型写在 `app/src/api/shell.ts`。托盘菜单由前端生成并下发（文案走 i18n，C-UI-04），外壳只处理
  「显示主窗口」「退出」。CSP 不允许远程来源与内联脚本，允许内联样式（Radix 运行时插入 `<style>`，因此对
  `style-src` 关闭 Tauri 的 nonce 注入）。应用命令登记在 app manifest，主窗口只授权实际用到的 4 个命令与事件监听。
  - `cargo deny` 只审计 Windows 目标：只分发 Windows 产物；同时列 Linux 时 cargo-deny 会把「Windows 上才依赖插件」
    与「插件在 Linux 上才依赖 zbus」拼在一起，误报 Tauri 的 GTK / D-Bus 依赖。
  - **已知风险**：服务未运行时，其他进程可以抢先创建同名管道冒充服务。界面只能依赖 proto（C-ARCH-02），
    校验服务端身份（`GetNamedPipeServerProcessId` + 映像路径 / 签名）需要 FFI，要么走例外 ADR、要么由 proto 之外的
    小模块提供，待确认。
  - 修复：生产构建曾把模拟服务（含示例数据）打进包里（Vite 8 / Rolldown 不会跨函数判断 `import.meta.env.DEV`），
    现在动态 import 直接放在 `DEV` 分支里，CI 检查生产构建产物。
- T-095（配置生成部分）：`core-mgr::config_gen::generate_precise` 生成精确模式配置：一个回环 SOCKS5 入口
  （随机端口与密码），每个进程组一个用户（用户名 = 组标签，与 relay 的握手一致），`auth_user` 路由到各组出站；
  入口上未匹配任何组的连接最后一条规则拒绝，不直连（C-NET-03）。用锁定版本 `sing-box check` 回归，快照在
  `crates/core-mgr/snapshots/precise_sample.json`。svc 的接线随 T-078。
- T-092（2026-10-29 定为「两者都做」）：sing-box 1.13 起删除了入站的 `sniff_override_destination`（1.14.4 解析时
  直接报错），规则动作里也没有替代，所以设计文档 6.3 的「用嗅探出的域名覆盖目标地址」改为：
  1. 中继嗅探（`relay::sniff`）：在 Web 端口（默认 80 / 443）上先读客户端首包，取 TLS SNI / HTTP Host 后按域名发
     SOCKS5 CONNECT，读到的字节在 CONNECT 后补发；取不到或 300 ms 超时就按原始 IP 连接。QUIC 暂不嗅探（可开
     「阻断 QUIC」让应用回落 TCP）。TUN 模式没有中继，走系统解析的应用仍会拿到被污染的地址（已知局限）。
  2. 远程 DNS（方案 schema 2 的 `dns.remote_server`）：用户填写 udp / tcp / tls / https 服务器，目标进程直发的
     53 端口查询被劫持到内核，经该进程组的出站解析（每个出站一个服务器，`detour`）；TUN 按进程、精确模式按 SOCKS
     用户匹配。不内置任何服务器地址（C-SEC-09）。精确模式下把目标进程的 UDP 53 交给中继，随 T-091 接入。
- relay 不在连接关闭时删除 NAT 表项：拦截层改写最后的 FIN/ACK 还要用它，由拦截层的 `Closed` 事件或空闲超时回收。
- sing-box 锁定为 1.14.4（`third_party/sing-box/lock.json`，单独 PR，C-DEP-04）。`cargo xtask fetch-deps` 用系统自带的
  `curl.exe` / `tar.exe` 拉取，SHA256 用 Windows CNG（`platform-win::hash`，T-056 校验 sing-box 时复用），
  只在 Windows 上可用；CI 的 Windows job 在跑测试前执行它。生成器以锁定版本的配置格式为准（AGENTS 第 9 节）。
- T-055：节点模型（`core-mgr::node`，参数可序列化、凭据只在 `Credentials` 里以 `Secret` 持有）与出站渲染一起放在
  core-mgr，T-058 的 node.* 与配置生成共用。配置生成是纯函数，跨平台可测；Windows 上另有用锁定版本执行
  `sing-box check` 的回归（`cargo xtask fetch-deps` 之后才能跑），快照在 `crates/core-mgr/snapshots/`。
  与锁定版本相关的取舍：
  - sing-box 的 `process_name` / `process_path` 区分大小写，五种规则一律翻译成 `(?i)` 的 `process_path_regex`，
    按规则引擎的优先级展开成有序路由规则，测试中与 `procroute-rules` 的判定逐条对照；
  - TUN `stack` 固定 `gvisor`：`system` / `mixed` 会给 sing-box 添加持久的 Windows 防火墙规则且不删除（C-NET-06）；
  - TUN `dns_mode` 显式 `disabled`：1.14 开启 `auto_route` 时默认 `hijack`，等同系统 DNS 接管（C-NET-09）；
  - `urltest` 组的测速地址必须由用户配置，不使用 sing-box 内置的默认地址（C-SEC-08、C-SEC-09）；
  - TUN 模式下 `include_children` 不生效（sing-box 只按发起连接的进程判定）。
  - C-NET-03（2026-10-29 定为动态 WFP 过滤器）：sing-box 退出时 TUN 与路由随之撤销。`block` 策略的 TUN 会话在
    内核启动前由 `svc::fail_closed` 装上过滤器（`platform-win::wfp`）：对每个目标可执行文件，本地地址在 TUN 网段内
    放行，远端为回环 / 链路本地 / 组播放行，其余阻断；动态会话随服务退出自动删除（C-NET-06）。名称、目录、通配、
    正则规则由进程追踪（T-079）跟进：启动时快照一遍，之后靠 ETW 进程事件（约 100 ms），ETW 不可用时每 500 ms
    快照一次。**已知窗口**：内核不在、命中进程刚启动而事件还没送到的这段时间没有保护。只保护自身命中规则的可执行
    文件（TUN 模式下继承不生效）。过滤器装不上则不启动会话（`session.fail_closed_unsupported`）。
    **待验证**：`crates/platform-win/tests/wfp_vm.rs` 在虚拟机里以管理员身份运行。
- T-079：`procroute-procwatch`（新 crate）。`tree` 是跨平台的进程树：键为「PID + 创建时间」，同一 PID 出现更晚的
  创建时间即按旧进程退出处理，更早的视为过时事件；判定用 `rules::inherit::decide_child`；目标集合的变化以
  `Change::{Targeted, Released}` 交出（`inherited` 标出继承来的子进程），换方案时按创建时间顺序重判、只报变化。
  `watcher`（Windows）在专用线程上持有进程树：先开 ETW 会话再拍快照（启动返回前完成第一次快照），之后由事件驱动，
  每 30 s 用快照校正；事件队列满或会话被外部停掉时立即校正 / 退回每 500 ms 快照。不依赖 intercept（C-ARCH-02），
  由 svc 接线：目前接到 TUN fail-closed 的 `WfpGuard`，精确模式的接线随 T-078 / T-094。
  - ETW 的 unsafe 部分在 `platform-win::etw`（C-CODE-01）：订阅 `Microsoft-Windows-Kernel-Process` 的
    `WINEVENT_KEYWORD_PROCESS`，负载按清单模板的定长前缀解码。**版本 3 起启动事件在 `CreateTime` 前插入了
    `ProcessSequenceNumber`**，偏移表按 (事件 id, 版本) 区分，单元测试读本机清单（`Get-WinEvent -ListProvider`，
    不需要管理员）核对。`platform-win::process` 新增 `process_creation_time` 与核对创建时间的
    `process_image_path_checked`；快照里的路径展开 8.3 短名（C-DRV-04）。
  - 文件划分与原计划不同：ETW 的消费在 `platform-win::etw`，procwatch 里是 `tree.rs`、`snapshot.rs`、`watcher.rs`。
  - **待验证**（管理员终端，开发机或虚拟机）：`cargo nextest run -p procroute-platform-win -p procroute-procwatch
    --features admin-tests`，覆盖真实 ETW 事件、事件里的创建时间与 `GetProcessTimes` 一致、残留会话替换、1 秒内继承。
    服务启动后会移除大部分令牌特权（只留 SeTcb / SeLoadDriver / SeChangeNotify / SeCreateGlobal），ETW 会话在
    这种令牌下能否启动也要在虚拟机里看服务日志确认；启动不了时退回快照并记一条 warn，不影响功能。

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
