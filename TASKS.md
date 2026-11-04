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
| M1 | T-050 ~ T-058、T-060 ~ T-062；TUN + `block` 的 WFP 阻断已在沙盒中验证；收窄令牌后 ETW 与 wintun 都可用（沙盒，见下） | 完成 |
| M2 | T-070 ~ T-076、T-078 ~ T-080（精确模式端到端与泄漏测试已在沙盒中通过，见下）；T-077 的排除与撤销部分 | M2 验收的「1 小时混合流量」；T-077 剩下的「代理地址变化 1 秒内更新排除表」（会话中改节点时） |
| M3 | T-090 ~ T-097（UDP 中继、QUIC 阻断、子进程继承、多出站分组均已接线，见下） | IPv6 上的泄漏测试（沙盒没有 IPv6 路由）；已经分片的包（T-091 下的已知缺口） |
| M4 | T-110（一次性证书的安装器，安装 / 升级 / 卸载已在沙盒中验证；发布 Release 时自动打包上传，见下）、T-112、T-113（外壳与界面部分，见下） | 在本机安装试用（用户自己装）；T-111 自动更新（需要独立的更新签名密钥，AGENTS 第 8 节第 4 条）；M4 / v1.0 验收清单（在此之前的 Release 标记为预发布） |

偏离原计划的地方：

- `Profile` 定义在 proto，rules 依赖 proto 而非 config（docs/adr/0001）。
- 发版用一次性自签名证书，服务按「同一张证书」校验客户端，没有用 design 9.3 假定的公共信任证书（docs/adr/0002）。
- 泄漏检测器的观察点是优先级最低的 WinDivert 只嗅探句柄，不是 design 第 12 节说的物理网卡（T-080）。
- 方案可以选择在会话期间挡住全机 ping，这是 C-NET-02 的例外（docs/adr/0003），默认关闭。
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
    WinDivert）、`SeChangeNotify`、`SeCreateGlobal`（C-SEC-06）。TUN 在收窄后的令牌下可用：`leak_e2e` 在控制台模式下启动 TUN
    会话，确认系统里出现了 TUN 网卡的地址（2026-11-04）。
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
  `WINDIVERT_ADDRESS` 里地址数组的字序（按 WinDivert 的 `ntoh` 助手推断为 `[0]` 最低位）已由
  `socket_layer_reports_this_process_connects` 在 Windows Sandbox 中确认（2026-10-29）。
- T-072：`intercept::divert::socket`。SOCKET 层以 `SNIFF | RECV_ONLY` 打开，只收 TCP / UDP 的 CONNECT 与 CLOSE，
  回环连接在过滤器里就滤掉（C-NET-05），队列长度取上限 16384。CONNECT 事件只带 PID，创建时间由 `ProcessResolver`
  补上（默认 `SystemProcesses`：`OpenProcess` + `GetProcessTimes`，与 procwatch 同源，C-DRV-04），再按 `decide` 判定：
  - 改道 / 阻断的目标流登记进 `FlowTable`，供 T-075 的 NETWORK 层按出站包查询。键是协议 + 本地端口 + 远端，不含本地
    地址（事件与包里的本地地址写法可能不同）；64 个分片各自加锁，逐包查询只锁一个分片、不分配内存（C-CODE-04）；
    上限 65536，满了拒绝新登记并计数，不淘汰已有登记。
  - 非目标流不进表、不改写（C-NET-02）；同一键上残留的旧登记随之清掉，端口被非目标进程复用时不会被误改道。
  - CLOSE 按 PID 撤销该套接字的登记；未连接的 UDP 套接字关闭时没有远端，撤销整个端口。
  - 每条流在这里判定一次，计数器（含 `attribution_miss`）也在这里记一次。收事件的线程出错退出时
    `SocketMonitor::failure()` 给出错误，之后不再有新的归属，上层必须按 fail_policy 处理（随 T-078）。
  - 进程追踪（ETW 约 100 ms）还没登记的新进程第一次 connect 时由 svc 当场判定（见下面 T-078），不会被判成非目标。
  - NETWORK 层抓全部出站 TCP / UDP 之后（2026-11-03 定，见 T-075），非目标进程的 CONNECT 也登记为「放行」，
    它们的第一个 SYN 直接放回，不必暂存等待归属。
  - 产出与原计划不同：单元测试在 `divert/socket/tests.rs`（不加载驱动），收事件线程的测试加在 `tests/divert_vm.rs`。
  - 2026-11-03 在 Windows Sandbox 中通过（`cargo xtask sandbox-test --only divert_vm`，4 个测试）：本进程的 TCP connect
    被登记（进程身份、进程组、非零本地端口），子进程的 connect 被判定但不登记，套接字关闭后登记被撤销。第一次运行时
    发往 TEST-NET-1 的 connect 被立即接受（宿主网络上有透明代理），测试已改成连上与连不上两种情况都成立。
- T-075 / T-076（2026-11-03）：`intercept::divert::{network, worker, interceptor}`。
  - **改道方式**：用 `tests/redirect_vm.rs` 在沙盒里比较了「改写到回环中继」与「反射到本机网卡」（WinDivert
    streamdump 的做法），两者都可行，选回环中继：中继只监听回环、不受防火墙影响、不暴露给局域网。目标流的出站包
    改写成「回环:应用源端口 → 回环:中继端口」后出站注入，映射端口就是应用的源端口；中继的回包（回环包）改写成
    「原始目标 → 应用」，按原接口入站注入。改写第一个 SYN 之前经 `RedirectMap`（svc 实现）同步登记 NAT，中继接受
    连接时一定查得到。
  - **与设计文档 6.1 不同（2026-11-03 用户确认）**：WinDivert 的过滤器在打开句柄时固定，无法只抓「流表内的五元组」；
    每条目标连接单独开句柄会让每条新连接多出数毫秒（违反 C-PERF-02）。所以 NETWORK 层抓本机全部出站 TCP / UDP
    （不含回环、不含其他驱动注入的包），非目标的包只读五元组、原样立即放回（C-NET-02），只改写目标流。
  - 连接跟踪按 FIN / RST 回收（双方 FIN 后留 30 秒、RST 后留 5 秒，接住迟到的 ACK），没有收尾的空闲两小时回收。
  - T-076：第一个 SYN 还没有登记时暂存（预分配的 256 个槽），每 2 ms 重查；50 ms 后按「本地端口 + 远端」在
    `GetExtendedTcpTable`（`platform-win::nettable`）里反查 PID，再走与 SOCKET 层相同的判定。反查不到按无法归属放行
    并计入 `attribution_miss`。
  - 收包线程 2 个（WinDivert 允许并发收同一句柄），缓冲区启动时分配；逐包路径只锁一个分片、不分配、不写日志。
  - 沙盒测试：`redirect_vm`（两种改道方式）、`precise_vm`（整个后端：目标进程经后端到达测试中继，子进程不经过，
    停止后撤销）。
- T-078（2026-11-03）：`svc::precise` 与 `handlers::session` 的精确模式分支。启动顺序：进程追踪 → sing-box（本地
  SOCKS 入口，随机端口与密码，C-NET-08）→ 回环中继（IPv4，有 IPv6 回环时再加一个，共用 NAT 表）→ UDP 中继 →
  WinDivert 后端（排除服务自身与解析出的节点服务器地址，C-NET-05）→ 流事件转连接面板。后端起不来返回
  `driver.not_loaded` 并停掉已启动的部分。
  - 目标集合 `Targets`（拦截层的 `FlowPolicy`）：进程追踪报来的为准；还没报到的新进程当场判定——先看自身规则，
    没命中再看父进程（`platform-win::process::process_parent_id`，用创建时间核对，最多往上 4 层）是否是允许继承的
    目标组（F7）。ProcRoute 自身（服务、界面、sing-box）按路径永远排除，否则 sing-box 去代理服务器的连接会成环。
  - 内核放弃重启：`block` 保持拦截（中继对新连接回 RST，C-NET-03），`allow` 撤下拦截、目标进程回到直连。
  - 端到端测试 `tests/e2e/tests/precise_e2e.rs`（`cargo xtask sandbox-test --only precise_e2e`，沙盒里运行真实的
    服务、sing-box 与 WinDivert；「远端代理」是测试自己起的 SOCKS5 节点，沙盒不需要外网）：curl（TCP）、
    powershell（UDP）经节点往返；非目标进程不经过节点；停止会话后不再经过节点；只命中 cmd.exe 的方案下，cmd 拉起后
    立即连接的 curl 同样经过节点。2026-11-03 全部通过；服务日志确认收窄令牌后 ETW 进程事件可用。
- T-091 / T-093 / T-094（2026-11-03）：
  - UDP：目标数据报交给进程内的 UDP 中继（`svc::precise::UdpBridge` → `relay::udp`，每个应用套接字一个
    SOCKS5 UDP ASSOCIATE），原包丢弃；回包由拦截层拼成「远端 → 应用」的入站数据报注入。目标套接字按本地端口登记，
    发往新远端时 SOCKET 事件还没到也认得出；SOCKET 层的登记优先（排除表与 QUIC 阻断仍然生效）。中继拒收的丢弃，
    不直连（C-NET-03）。53 端口查询走同一路径（F8）。
  - QUIC 阻断（T-093）：判定时 UDP 443 记为阻断；已知目标套接字的 443 数据报同样丢弃。
  - 组播、广播地址与回环、链路本地一样永远排除（局域网发现协议没有理由进代理）。
  - 2026-11-04 更正（T-080 的实测）：NETWORK 层看到的是分片之前的完整数据报（4000 字节的 UDP 是一个 4028 字节
    的包），所以普通的大数据报能进中继、回显正确，不存在原先记录的「分片的目标 UDP 绕过代理」。原先观察到的现象其实是
    下面的首包泄漏，与大小无关。
  - **已知缺口**（违反 C-NET-07 的字面要求，要改需要人来定）：已经分片的 IPv4 包（原始套接字才会产生）与带扩展头
    的 IPv6 包读不出端口，原样放回。IPv6 上的行为没有实测，沙盒没有 IPv6 路由。
- 拦截层管不到的协议（2026-11-04，`platform-win::wfp::ProtocolFilters`、`svc::protocol_filters`，维护者选择的方案）。拦截层只
  改道 TCP 与 UDP，ICMP 按发送方式有两种情况（沙盒实测）：`ping.exe`、.NET `Ping` 这类走 `IcmpSendEcho` 的，SOCKET 与 FLOW 事件
  的 PID 都是 4，归属不到调用进程；进程自己开原始套接字发的，事件带真实 PID。于是：
  - 精确模式 + `block`：目标可执行文件 TCP、UDP 以外的协议在 `ALE_AUTH_CONNECT` 挡住（C-NET-07）。包发出之前同步判定，没有首包
    竞态，也不用抓其他进程的包。按可执行文件判定：同一文件的非目标进程也一起挡，进程退出后不撤销，直到会话结束。完整路径
    规则启动时就装好；其他规则与继承来的子进程等进程追踪报到（约 100 ms），这段时间没有保护。回环、链路本地、组播、广播放行。
  - 方案字段 `icmp.block_all_ping`（schema 3，默认关闭，开启前要确认）：会话期间挡住全机发往外部的回显请求（ICMP 类型 8、
    ICMPv6 类型 128），不看 fail_policy，两种模式都生效。是 C-NET-02 的例外（docs/adr/0003）。只挡回显请求，IPv6 邻居发现不受影响。
  - 装不上就不启动会话（`session.fail_closed_unsupported`）。过滤器随会话结束、服务退出撤销（C-NET-06）；`allow` 策略下内核放弃
    重启、会话结束时一并撤销。
  - `leak_e2e` 覆盖了 IPv4 上的全部行为。IPv6 的回显请求与 ICMPv6 原始套接字没有实测，沙盒没有 IPv6 路由。
- 修复（2026-11-04，T-080 查出）：目标进程的**第一个 UDP 数据报泄漏**。没有登记的数据报原来直接放回，而刚启动的
  进程要当场判定、CONNECT 事件走得慢，第一个数据报几乎每次都赢（改之前实测：刚启动就发包的 24 个 UDP 进程有 22 个泄漏，
  10 个经启动器继承的全部泄漏，都收不到回包；TCP 一直没有泄漏）。现在和 SYN 一样暂存，50 ms 后按本地地址与端口在 UDP 表里反查（`platform-win::nettable::udp_owner_pid`，
  C-NET-04）；放不进暂存槽的（超过 256 字节）立即反查。按代码推断（没有单独实测）：会话开始前就在通信的目标
  UDP 流也会被接管，原来它们没有 CONNECT 事件，整个会话都直连。代价：非目标进程发往新远端的第一个数据报在事件到达前同样要等，
  通常 2 ms 以内，最多 50 ms。
  - 已知局限：非目标 UDP 登记到 CLOSE 才撤销。一个套接字累计发往的远端让放行登记达到上限（49152）后，发往新远端的
    每个数据报都要等 50 ms 再放行（目标流预留了容量，不受影响）。
- 修复（2026-11-04，T-080 查出）：拦截层放回一个包时，WFP 为这次注入再报一个 PID 4 的 CONNECT，没有对应的 CLOSE
  （沙盒实测）。原来它会登记成「放行」，盖掉同一条流的改道登记，每条非目标流还在表里留下一条撤销不了的记录。现在 System
  的事件一律不处理。代价：内核自己发起的连接（SMB 等）没有事件，第一个 SYN 走暂存与反查，最多多等 50 ms；非目标流重传的
  SYN 也一样（第一个 SYN 已用掉登记）。
- T-080（2026-11-04）：`tests/e2e`（新 crate `procroute-e2e`，`crates/svc/tests/precise_e2e.rs` 也移到这里，共用
  测试框架 `harness.rs`）。
  - 检测器 `leak_detector.rs`：NETWORK 层优先级最低的只嗅探句柄看真正发出去的包（改写或丢弃之后还能走到这里的），SOCKET 层
    事件给出端口 → PID，结束后按驱动时间戳统一配对，所以不受首包竞态影响。不用产品的解析与判定逻辑。`finish` 先发一个标记
    数据报，确认两层都在工作才交出报告，否则计数为 0 说明不了什么。解析与配对是纯逻辑，单测在任意 OS 上跑。
  - 用例 `tests/leak_e2e.rs`（`cargo xtask sandbox-test --only leak_e2e`）。已知泄漏：没有会话时的直连必须被抓到，发往
    代理地址的不算。已知不泄漏（计数必须为 0，同时确认回显正确、节点见过目标、检测器看得到旁观者的包）：经过会话的 TCP
    与 UDP、48 个刚启动就发包的进程、20 个经启动器继承的子进程、超过 MTU 的数据报、强杀 sing-box 的重启窗口与超出重启上限后
    （`blocked` 时 TCP 收到连接重置、UDP 丢弃，C-NET-03）。
  - `attribution_miss` 的基线是 0（连续 3 次运行、15 个会话实测）。服务在会话结束时把拦截层计数写进日志，用例从那里读，
    没有新增 IPC。
  - 第一次运行就查出上面两个修复。还没有做的：1 小时混合流量（M2 验收）、IPv6（沙盒没有路由）。
- T-110（2026-11-04 定用一次性证书，docs/adr/0002；在开发机上的安装由用户自己做）：`cargo xtask bundle`。
  - 证书：每次打包在当前用户证书库里新建 `CN=ProcRoute Build` 的代码签名证书（私钥不可导出，20 年），打包结束后连同
    私钥删除。服务只要求界面与自己用同一张证书（比对证书的 SHA-256），不要求证书受信任（C-SEC-02），用户不需要改动
    证书信任。开发机证书库里旧的 `CN=ProcRoute Local Code Signing` 不再使用。
  - 构建：服务与界面都是静态 CRT 的 release 构建（安装的机器上不需要 VC++ 运行库）；服务不含
    `insecure-skip-client-auth`。Tauri NSIS 打包，`perMachine`，WebView2 用下载引导程序（本机已有运行时则跳过）。
  - 签名：打包器在自定义签名命令下仍用 signtool 判断「是否已签名」，本机没有 Windows SDK，`TAURI_WINDOWS_SIGNTOOL_PATH`
    指向 `xtask/bundle/signtool-verify.cmd`（一律回答未签名）；签名策略全在 `xtask/bundle/sign.ps1`：锁定的第三方
    二进制（sing-box、WinDivert）跳过，否则签名会改变它们的 SHA-256、服务拒绝加载（C-DEP-04、C-DRV-01），其余
    （服务、界面、NSIS 插件、卸载器、安装器）用同一张证书签名。
  - 安装器钩子 `app/src-tauri/windows/hooks.nsh`：登记服务 ProcRoute（LocalSystem、自动启动、异常退出 5 秒后重启），
    升级前与卸载前 `net stop`，卸载时删除服务登记与界面的开机自启项；`%ProgramData%\ProcRoute`（方案、节点、日志）保留。
  - 验证：`cargo xtask sandbox-install` 在不信任任何证书的沙盒里静默安装（`--upgrade-from` 时先装旧版并运行其界面）→
    检查文件、签名、服务、控制管道 → 启动界面并从服务的调试日志确认签过名的界面被接受 → 确认安装目录里主题相同、证书
    不同的界面被拒绝 → 静默卸载 → 检查服务、文件、进程、WinDivert、防火墙规则、开机自启项没有残留。卸载检查没有覆盖
    「加载过驱动之后」的情形（这一步需要会话，只有界面能发起）。
  - 发版：在 GitHub 上发布 Release 时，`.github/workflows/release.yml` 跑 CI，按 tag 改版本号（`cargo xtask set-version`，
    安装包、界面与服务的版本都跟随 tag），打包并上传安装器、`SHA256SUMS.txt` 和构建来源证明，并在发行说明后追加安装
    说明、校验和与源码链接（C-DEP-05、design 9.5）。不需要任何密钥。改动打包相关文件的 PR 只打包，安装器留在 artifact 里。
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
- 虚拟机专属测试（2026-10-29 定用 Windows Sandbox 作为 C-TEST-04 的虚拟机）：`cargo xtask sandbox-test` 在开发机上
  用静态 CRT 编译 `wfp_vm`、`etw_admin`、`watcher_admin`、`divert_vm`（沙盒里没有 VC++ 运行库，输出在独立的
  `target/sandbox/build`），连同锁定的 WinDivert 文件只读映射进沙盒，由 `xtask/sandbox/run.ps1` 复制到沙盒本地
  磁盘后逐个运行，结果写回 `target/sandbox/out` 后沙盒自动关机。沙盒启用默认 NAT 网络（WFP 测试要区分「被过滤器
  拒绝」与「没有路由」）。登录命令不是管理员时整次运行判为失败。2026-10-29 首次运行 4 个文件 6 个测试全部通过。
  客户机关机后，沙盒的客户端窗口偶尔不退出，下一次运行会提示「已有一个 Windows Sandbox 在运行」，关掉该窗口
  即可（2026-11-03 遇到一次）。
- 沙盒联调（2026-11-03）：`cargo xtask sandbox-dev` 在开发机上编译前端生产构建、服务（调试构建 +
  `insecure-skip-client-auth`）与界面（`tauri/custom-protocol`），连同锁定的 sing-box 映射进沙盒，由
  `xtask/sandbox/dev.ps1` 装到 `C:\Program Files\ProcRoute`，在可见的控制台里运行 `procroute-svc --console`
  （日志同时写到 `target/sandbox/dev-out/svc.log`），再启动界面并在桌面放快捷方式；沙盒保持打开，开启剪贴板
  便于粘贴节点链接。与 `sandbox-test` 共用 `xtask/src/sandbox.rs`。实测要点：
  - Windows Sandbox 的系统镜像不带 WebView2 运行时；沙盒也上不了外网（开发机经本地代理上网，沙盒的 NAT 不走它，
    在沙盒里下载 WebView2 报 `Unable to connect to the remote server`）。所以把开发机已安装的运行时版本目录只读
    映射进沙盒，复制到本地盘、给 AppContainer 授权后经 `WEBVIEW2_BROWSER_EXECUTABLE_FOLDER` 使用。
  - 同一原因，沙盒里连代理服务器多半也会失败：沙盒联调适合看界面与服务的交互，走代理的效果要在能直连外网的虚拟机里看。
  - 控制台模式下服务收窄令牌后（移除 21 个特权）控制管道正常监听，界面能连上；WinDivert 驱动加载与 ETW 进程
    事件也正常（见 T-078 的端到端测试），wintun 也能创建（见 T-058）。
  - std 在 Windows 上创建子进程总是继承可继承句柄，`cmd /C start` 也一样（实测），沙盒启动器会一直拿着调用方的
    输出管道；改经 PowerShell 的 `Start-Process`（ShellExecute）启动。
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
    `crates/platform-win/tests/wfp_vm.rs` 已在 Windows Sandbox 中以管理员身份通过（2026-10-29）。
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
  - 管理员终端的测试（`cargo nextest run -p procroute-platform-win -p procroute-procwatch --features admin-tests`：
    真实 ETW 事件、事件里的创建时间与 `GetProcessTimes` 一致、残留会话替换、1 秒内继承）2026-10-29 已全部通过。
    **待验证**：服务启动后会移除大部分令牌特权（只留 SeTcb / SeLoadDriver / SeChangeNotify / SeCreateGlobal），
    ETW 会话在这种令牌下能否启动要在虚拟机里看服务日志确认；启动不了时退回快照并记一条 warn，不影响功能。
- T-112：新增读方法 `diag.export`（返回 `proto::diag::DiagReport`，新增方法，协议版本不变）。服务端
  `svc::diag` 收集版本与系统信息（`platform-win::os` 读注册表里的系统版本与内存完整性开关）、安装目录里
  sing-box 与版本锁的比对、会话状态、方案、节点概况和 `logs\svc.log` 末尾 512 KiB；任何一部分读不出只记进
  `problems`，不影响导出。整份报告控制在一条 IPC 消息以内（C-SEC-03），超出时从最旧的日志行丢起。
  - 脱敏（C-SEC-04，`svc::diag::redact`）：不导出凭据、订阅地址、节点名称与地址（只留端口），节点只列方案用到的，
    其余按协议计数；日志逐行把登记过的节点地址 / TLS 服务器名 / 凭据 / 订阅地址换成占位符（短的只按整词），
    凭据样式字段（与界面 `features/log/redact.ts` 同一组关键词）的值换成 `***`，公网 IP 换成 `<ip>`（回环、
    私有、链路本地、100.64/10、198.18/15 保留），`\Users\<名字>` 换成 `<user>`；方案规则里的用户名同样处理，
    远程 DNS 服务器只留协议。
  - 保存：报告不经过 WebView。外壳命令 `diag_export`（`app/src-tauri/src/diag.rs`）调用 `diag.export`，加上界面
    版本，以 `procroute-diag-<UTC 时间>.json` 新建在当前用户的「下载」文件夹（只新建、不覆盖），把路径交给界面
    显示。没有用保存对话框：那需要新增 `tauri-plugin-dialog` 依赖（AGENTS 第 8 节第 2 条）。失败分「服务」与
    「存盘」两类，界面分别提示。不在桌面外壳里时设置页不显示入口。
  - 产出文件与原计划不同：除 `svc/src/diag.rs` 与 `features/settings/*` 外，还改了 proto、platform-win 与外壳。
  - WinDivert 文件与锁的比对随 T-078（svc 接入 intercept）补上。

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
