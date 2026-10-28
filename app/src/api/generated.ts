// SPDX-License-Identifier: GPL-3.0-or-later
// 本文件由 `cargo xtask gen-types` 从 crates/proto 生成，禁止手改（C-ARCH-04）。

export const IPC_PROTOCOL_VERSION = 1;

/**
 * 进入 `blocked` 的原因。只给原因码，文案由界面的 i18n 资源提供。
 */
export type BlockedReason = "kernel_crash_loop" | "relay_unavailable" | "driver_failed";

/**
 * 单个组件的状态。界面按组件把它翻译成「运行中 / 已加载」等文字。
 */
export type ComponentState = "active" | "inactive" | "restarting" | "failed";

/**
 * 服务、驱动、内核三者的状态，界面必须如实显示（C-UI-02）。
 */
export type ComponentStatus = { service: ComponentState, driver: ComponentState, kernel: ComponentState, };

/**
 * 一条被改道连接的事件（`conn.subscribe` 通道）。
 */
export type ConnEvent = { conn_id: number, phase: ConnPhase, pid: number, process: string, 
/**
 * `host:port` 或 `ip:port`。
 */
target: string, network: Network, 
/**
 * 命中的进程组标签。
 */
group: string, outbound: string, upload_bytes: number, download_bytes: number, started_at_ms: number, };

/**
 * 连接事件所处的阶段。
 */
export type ConnPhase = "opened" | "updated" | "closed";

/**
 * 凭据是否已设置。不携带凭据本身。
 */
export type CredentialState = "set" | "not_set";

export type DnsSettings = { strategy: DnsStrategy, 
/**
 * 劫持目标进程自己发往 53 端口的查询。
 */
hijack_port53: boolean, };

/**
 * DNS 处理策略。
 */
export type DnsStrategy = "sniff" | "system_takeover";

/**
 * 拦截驱动的状态（`driver.status` 的返回值与事件负载）。
 */
export type DriverStatus = { state: ComponentState, 
/**
 * 锁定的驱动版本，例如 `2.2.2`。
 */
version: string | null, };

/**
 * 没有参数或没有返回值的方法使用的空对象，序列化为 `{}`。
 */
export type Empty = Record<symbol, never>;

/**
 * 全部错误码。新增时在 [`ErrorCode::ALL`] 里同步登记，测试会检查。
 */
export type ErrorCode = "ipc.version_mismatch" | "ipc.invalid_request" | "ipc.payload_too_large" | "ipc.unauthorized" | "ipc.unknown_method" | "ipc.invalid_params" | "session.already_running" | "session.not_running" | "profile.not_found" | "profile.invalid_schema" | "profile.in_use" | "node.not_found" | "node.import_failed" | "driver.not_loaded" | "driver.load_failed" | "driver.busy" | "kernel.unavailable" | "internal.error";

/**
 * 内核或中继不可用时，目标进程流量的处理方式。
 */
export type FailPolicy = "block" | "allow";

/**
 * 某个字段上的一个问题。
 */
export type FieldIssue = { 
/**
 * 出问题的字段，例如 `groups[1].match[0].value`。
 */
path: string, code: FieldIssueCode, 
/**
 * 给开发者看的细节；界面文案按 `code` 取。
 */
message: string, };

/**
 * 字段校验问题的种类。界面按它从 i18n 资源取文案，并标到对应字段上。
 */
export type FieldIssueCode = "schema_version" | "empty" | "too_long" | "too_many" | "invalid_id" | "invalid_tag" | "control_char" | "duplicate_tag" | "no_matchers" | "invalid_rule";

/**
 * 进程组：同一组的进程走同一个出站。
 */
export type Group = { 
/**
 * 组标签，同一方案内唯一；也用作本地 SOCKS 用户名以选择出站。
 */
tag: string, 
/**
 * 出站或出站组的标签，对应 sing-box 的出站。
 */
outbound: string, 
/**
 * 是否把本组进程派生的子进程纳入本组（F7）。
 */
include_children: boolean, match: Array<MatchRule>, };

/**
 * `ipc.hello` 的参数：连接建立后的第一条请求。
 */
export type HelloParams = { protocol_version: number, client_version: string, };

/**
 * `ipc.hello` 的返回值。
 */
export type HelloResult = { protocol_version: number, service_version: string, };

/**
 * 导入时被跳过的一行及原因。
 */
export type ImportIssue = { 
/**
 * 输入中的行号，从 1 开始；0 表示针对整段输入（例如 `clash_yaml_unsupported`）。
 */
line: number, 
/**
 * 稳定的原因代码（`snake_case`，例如 `unsupported_protocol`、`duplicate`），界面据此翻译。
 * 只取固定代码，不回显输入内容与凭据（C-SEC-04）。
 */
reason: string, };

/**
 * 返回给客户端的错误。
 */
export type IpcError = { code: ErrorCode, message: string, 
/**
 * 逐字段的校验问题（例如 `profile.invalid_schema`）；没有时省略。
 */
fields?: Array<FieldIssue>, };

/**
 * 单个节点的测速结果。
 */
export type LatencyResult = { id: string, 
/**
 * 超时或失败时为空。
 */
latency_ms: number | null, timed_out: boolean, };

/**
 * 一条日志（`log.subscribe` 通道）。字段里不得含凭据（C-SEC-04）。
 */
export type LogEvent = { ts_ms: number, level: LogLevel, 
/**
 * 产生日志的模块，例如 `intercept`、`relay`。
 */
module: string, message: string, fields: { [key in string]: string }, };

/**
 * 日志级别，按严重程度从低到高排列。
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

/**
 * `log.subscribe` 的参数。
 */
export type LogSubscribeParams = { min_level: LogLevel, };

/**
 * 一条进程匹配规则。
 */
export type MatchRule = { type: MatchType, value: string, 
/**
 * 只对 `dir` 有意义：是否包含子目录。
 */
recursive: boolean, };

/**
 * 匹配项类型。求值顺序见 `procroute-rules`。
 */
export type MatchType = "name" | "path" | "dir" | "glob" | "regex";

/**
 * 工作模式。
 */
export type Mode = "precise" | "tun";

/**
 * 传输层协议。
 */
export type Network = "tcp" | "udp";

/**
 * `node.import` 的参数。
 */
export type NodeImportParams = { "kind": "share_links", text: string, } | { "kind": "subscription", name: string, url: string, };

/**
 * `node.import` 的返回值。
 */
export type NodeImportResult = { added: number, skipped: number, issues: Array<ImportIssue>, };

/**
 * 返回给 UI 的节点信息。
 */
export type NodeInfo = { id: string, name: string, protocol: NodeProtocol, 
/**
 * `host:port`。服务器地址不是凭据，但诊断包导出时会脱敏。
 */
server: string, subscription_id: string | null, credential: CredentialState, };

/**
 * `node.list` 的返回值。
 */
export type NodeListResult = { nodes: Array<NodeInfo>, outbounds: Array<OutboundInfo>, subscriptions: Array<SubscriptionInfo>, };

/**
 * 节点协议。实际支持范围以锁定版本的 sing-box 为准。
 */
export type NodeProtocol = "shadowsocks" | "vmess" | "vless" | "trojan" | "hysteria2" | "tuic" | "anytls" | "socks" | "http";

/**
 * `node.test` 的参数；`ids` 为空表示测全部节点。
 */
export type NodeTestParams = { ids: Array<string>, };

/**
 * `node.test` 的返回值。
 */
export type NodeTestResult = { results: Array<LatencyResult>, };

/**
 * 方案里的进程组按 `tag` 引用出站。
 */
export type OutboundInfo = { tag: string, kind: OutboundKind, 
/**
 * 成员节点 id。
 */
members: Array<string>, 
/**
 * 当前实际使用的成员节点 id（自动选择或手动选择时）。
 */
current: string | null, };

/**
 * 出站的种类。
 */
export type OutboundKind = "single" | "url_test" | "selector";

/**
 * 运行中的一个进程（`process.list`）。
 */
export type ProcessInfo = { pid: number, name: string, path: string, 
/**
 * 若命中当前方案，给出进程组标签。
 */
matched_group: string | null, };

/**
 * `process.list` 的返回值。
 */
export type ProcessListResult = { processes: Array<ProcessInfo>, };

/**
 * 方案。
 */
export type Profile = { schema_version: number, id: string, name: string, mode: Mode, fail_policy: FailPolicy, dns: DnsSettings, udp: UdpSettings, groups: Array<Group>, 
/**
 * 排除规则，优先级最高，命中即直连。
 */
exclude: Array<MatchRule>, };

/**
 * `profile.get` / `profile.delete` 的参数。
 */
export type ProfileIdParams = { id: string, };

/**
 * `profile.list` 的返回值。
 */
export type ProfileListResult = { profiles: Array<ProfileSummary>, };

/**
 * `profile.save` 的返回值。
 */
export type ProfileSaveResult = { id: string, };

/**
 * 方案列表里的一项。
 */
export type ProfileSummary = { id: string, name: string, mode: Mode, group_count: number, 
/**
 * 是否为当前会话正在使用的方案。
 */
active: boolean, };

/**
 * `session.start` 的参数。
 */
export type SessionStartParams = { profile_id: string, };

/**
 * 会话整体状态。
 */
export type SessionState = "stopped" | "starting" | "running" | "stopping" | "blocked";

/**
 * `session.status` 的返回值，也是 `session.status` 事件的负载。
 */
export type SessionStatus = { state: SessionState, profile_id: string | null, profile_name: string | null, mode: Mode | null, components: ComponentStatus, blocked_reason: BlockedReason | null, };

/**
 * 订阅。完整订阅地址常含令牌，视同凭据，只返回 `scheme://host` 用于展示。
 */
export type SubscriptionInfo = { id: string, name: string, url_display: string, node_count: number, updated_at_ms: number | null, };

export type UdpSettings = { 
/**
 * 是否代理目标进程的 UDP 流量。
 */
enabled: boolean, 
/**
 * 阻断目标进程的 UDP 443，让应用回落到 TCP。
 */
block_quic: boolean, };

/** 方法名 → 参数类型 */
export interface IpcRequest {
  "ipc.hello": HelloParams;
  "session.start": SessionStartParams;
  "session.stop": Empty;
  "session.status": Empty;
  "profile.list": Empty;
  "profile.get": ProfileIdParams;
  "profile.save": Profile;
  "profile.delete": ProfileIdParams;
  "node.import": NodeImportParams;
  "node.list": Empty;
  "node.test": NodeTestParams;
  "process.list": Empty;
  "conn.subscribe": Empty;
  "log.subscribe": LogSubscribeParams;
  "driver.status": Empty;
  "driver.unload": Empty;
}

/** 方法名 → 返回值类型 */
export interface IpcResult {
  "ipc.hello": HelloResult;
  "session.start": SessionStatus;
  "session.stop": SessionStatus;
  "session.status": SessionStatus;
  "profile.list": ProfileListResult;
  "profile.get": Profile;
  "profile.save": ProfileSaveResult;
  "profile.delete": Empty;
  "node.import": NodeImportResult;
  "node.list": NodeListResult;
  "node.test": NodeTestResult;
  "process.list": ProcessListResult;
  "conn.subscribe": Empty;
  "log.subscribe": Empty;
  "driver.status": DriverStatus;
  "driver.unload": DriverStatus;
}

/** 事件通道 → 负载类型 */
export interface IpcEvent {
  "conn.subscribe": ConnEvent;
  "log.subscribe": LogEvent;
  "session.status": SessionStatus;
  "driver.status": DriverStatus;
}

export type IpcMethod = keyof IpcRequest;
export type IpcChannel = keyof IpcEvent;

/** 会修改服务状态的方法（服务端会写审计日志） */
export const MUTATING_METHODS: readonly IpcMethod[] = [
  "session.start",
  "session.stop",
  "profile.save",
  "profile.delete",
  "node.import",
  "driver.unload",
];
