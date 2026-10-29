// SPDX-License-Identifier: GPL-3.0-or-later
// 浏览器开发与测试用的内存模拟服务（T-060）。
//
// 行为尽量贴近真实服务：会话三态、方案校验错误按字段返回、节点凭据只写不读、
// 会话运行时推送连接与日志事件。只在开发构建、不在 Tauri 里运行时加载。
import type {
  ConnEvent,
  ErrorCode,
  FieldIssue,
  IpcChannel,
  IpcEvent,
  IpcMethod,
  IpcRequest,
  IpcResult,
  LogEvent,
  NodeImportResult,
  NodeInfo,
  NodeProtocol,
  Profile,
  SessionStatus,
} from '../generated'
import { CONNECTIONS, LOGS, NODES, OUTBOUNDS, PROCESSES, PROFILES, SUBSCRIPTIONS } from './fixtures'

type Handlers = { [M in IpcMethod]: (params: IpcRequest[M]) => IpcResult[M] }
type Listener = (payload: never) => void

export type MockService = {
  call<M extends IpcMethod>(method: M, params: IpcRequest[M]): Promise<IpcResult[M]>
  subscribe<E extends IpcChannel>(
    channel: E,
    onEvent: (payload: IpcEvent[E]) => void,
  ): Promise<() => void>
}

/** 与服务端错误同形，交给 IpcError.from 包装。 */
function fail(code: ErrorCode, message: string, fields?: FieldIssue[]): never {
  // 刻意抛出普通对象：Tauri 的 invoke 失败时传回的就是这种结构
  throw { code, message, fields }
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T

const SCHEMES: Record<string, NodeProtocol> = {
  ss: 'shadowsocks',
  vmess: 'vmess',
  vless: 'vless',
  trojan: 'trojan',
  hysteria2: 'hysteria2',
  hy2: 'hysteria2',
  tuic: 'tuic',
  anytls: 'anytls',
  socks: 'socks',
  socks5: 'socks',
  http: 'http',
  https: 'http',
}

const TAG = /^[a-z0-9_-]{1,32}$/

/** 与 procroute-config 的校验保持同样的字段路径与问题码（只覆盖常见情形）。 */
function validate(p: Profile): FieldIssue[] {
  const issues: FieldIssue[] = []
  const add = (path: string, code: FieldIssue['code']) => issues.push({ path, code, message: code })
  if (p.name.trim() === '') add('name', 'empty')
  else if ([...p.name].length > 64) add('name', 'too_long')
  const seen = new Set<string>()
  p.groups.forEach((g, i) => {
    if (!TAG.test(g.tag)) add(`groups[${i}].tag`, g.tag === '' ? 'empty' : 'invalid_tag')
    else if (seen.has(g.tag)) add(`groups[${i}].tag`, 'duplicate_tag')
    seen.add(g.tag)
    if (g.outbound.trim() === '') add(`groups[${i}].outbound`, 'empty')
    if (g.match.length === 0) add(`groups[${i}].match`, 'no_matchers')
    g.match.forEach((r, j) => {
      if (r.value.trim() === '') add(`groups[${i}].match[${j}].value`, 'empty')
    })
  })
  p.exclude.forEach((r, j) => {
    if (r.value.trim() === '') add(`exclude[${j}].value`, 'empty')
  })
  return issues
}

export function createMockService(): MockService {
  const profiles = clone(PROFILES)
  const nodes = clone(NODES)
  const outbounds = clone(OUTBOUNDS)
  const subscriptions = clone(SUBSCRIPTIONS)
  let seq = 0
  let session: SessionStatus = {
    state: 'stopped',
    profile_id: null,
    profile_name: null,
    mode: null,
    components: { service: 'active', driver: 'inactive', kernel: 'inactive' },
    blocked_reason: null,
  }
  const listeners = new Map<IpcChannel, Set<Listener>>()
  let ticker: ReturnType<typeof setInterval> | null = null
  let connSeq = 0
  const live = new Map<number, ConnEvent>()

  const emit = <E extends IpcChannel>(channel: E, payload: IpcEvent[E]) => {
    for (const l of listeners.get(channel) ?? []) (l as (p: IpcEvent[E]) => void)(clone(payload))
  }

  const setSession = (next: SessionStatus) => {
    session = next
    emit('session.status', next)
    syncTicker()
  }

  /** 会话运行且有人订阅时才产生连接与日志事件。 */
  const syncTicker = () => {
    const wanted =
      session.state === 'running' &&
      ((listeners.get('conn.subscribe')?.size ?? 0) > 0 ||
        (listeners.get('log.subscribe')?.size ?? 0) > 0)
    if (wanted && ticker === null) ticker = setInterval(tick, 500)
    if (!wanted && ticker !== null) {
      clearInterval(ticker)
      ticker = null
    }
  }

  const tick = () => {
    const now = Date.now()
    // 新连接
    const [process, pid, target, network, group, outbound] =
      CONNECTIONS[connSeq % CONNECTIONS.length] ?? CONNECTIONS[0]
    connSeq += 1
    const opened: ConnEvent = {
      conn_id: connSeq,
      phase: 'opened',
      pid,
      process,
      target,
      network,
      group,
      outbound,
      upload_bytes: 0,
      download_bytes: 0,
      started_at_ms: now,
    }
    live.set(opened.conn_id, opened)
    emit('conn.subscribe', opened)
    // 已有连接的流量增长，偶尔关闭
    for (const c of live.values()) {
      c.upload_bytes += Math.floor(Math.random() * 20_000)
      c.download_bytes += Math.floor(Math.random() * 400_000)
      const closing = live.size > 40 && Math.random() < 0.2
      emit('conn.subscribe', { ...c, phase: closing ? 'closed' : 'updated' })
      if (closing) live.delete(c.conn_id)
    }
    const [level, module, message, fields] = LOGS[connSeq % LOGS.length] ?? LOGS[0]
    const log: LogEvent = { ts_ms: now, level, module, message, fields: { ...fields } }
    emit('log.subscribe', log)
  }

  const summary = (p: Profile) => ({
    id: p.id,
    name: p.name,
    mode: p.mode,
    group_count: p.groups.length,
    active: session.profile_id === p.id && session.state !== 'stopped',
  })

  const importLinks = (text: string): NodeImportResult => {
    const result: NodeImportResult = { added: 0, skipped: 0, issues: [] }
    text.split(/\r?\n/).forEach((raw, i) => {
      const line = raw.trim()
      if (line === '') return
      const scheme = /^([a-z0-9]+):\/\//i.exec(line)?.[1]?.toLowerCase() ?? ''
      const protocol = SCHEMES[scheme]
      if (!protocol) {
        result.skipped += 1
        // 与服务一样只给原因代码，不回显链接内容（C-SEC-04）
        result.issues.push({ line: i + 1, reason: scheme ? 'unsupported_protocol' : 'malformed' })
        return
      }
      const fragment = line.includes('#') ? line.slice(line.lastIndexOf('#') + 1) : ''
      let name = `导入节点 ${nodes.length + 1}`
      try {
        if (fragment) name = decodeURIComponent(fragment)
      } catch {
        // 保持默认名
      }
      const node: NodeInfo = {
        id: `n-mock-${++seq}`,
        name,
        protocol,
        server: 'imported.example.net:443',
        subscription_id: null,
        credential: 'set',
      }
      nodes.push(node)
      outbounds.push({ tag: `node-${seq}`, kind: 'single', members: [node.id], current: node.id })
      result.added += 1
    })
    return result
  }

  const handlers: Handlers = {
    'ipc.hello': (p) => ({ protocol_version: p.protocol_version, service_version: '0.1.0-mock' }),
    'session.start': ({ profile_id }) => {
      const p = profiles.find((x) => x.id === profile_id)
      if (!p) fail('profile.not_found', `no profile ${profile_id}`)
      if (session.state === 'running' || session.state === 'starting')
        fail('session.already_running', 'session is running')
      setSession({
        state: 'running',
        profile_id: p.id,
        profile_name: p.name,
        mode: p.mode,
        components: {
          service: 'active',
          driver: p.mode === 'precise' ? 'active' : 'inactive',
          kernel: 'active',
        },
        blocked_reason: null,
      })
      return session
    },
    'session.stop': () => {
      if (session.state === 'stopped') fail('session.not_running', 'session is not running')
      live.clear()
      setSession({
        state: 'stopped',
        profile_id: null,
        profile_name: null,
        mode: null,
        components: { service: 'active', driver: 'inactive', kernel: 'inactive' },
        blocked_reason: null,
      })
      return session
    },
    'session.status': () => session,
    'profile.list': () => ({ profiles: profiles.map(summary) }),
    'profile.get': ({ id }) => profiles.find((p) => p.id === id) ?? fail('profile.not_found', id),
    'profile.save': (p) => {
      const issues = validate(p)
      if (issues.length > 0)
        fail('profile.invalid_schema', `${issues.length} invalid field(s)`, issues)
      const saved = { ...p, id: p.id === '' ? `p-mock-${++seq}` : p.id }
      const at = profiles.findIndex((x) => x.id === saved.id)
      if (at >= 0) profiles[at] = saved
      else profiles.push(saved)
      return { id: saved.id }
    },
    'profile.delete': ({ id }) => {
      if (session.profile_id === id && session.state !== 'stopped')
        fail('profile.in_use', 'profile is used by the running session')
      const at = profiles.findIndex((x) => x.id === id)
      if (at < 0) fail('profile.not_found', id)
      profiles.splice(at, 1)
      return {}
    },
    'node.import': (p) => {
      if (p.kind === 'share_links') return importLinks(p.text)
      let display = ''
      try {
        const u = new URL(p.url)
        display = `${u.protocol}//${u.host}`
      } catch {
        fail('node.import_failed', 'invalid subscription url')
      }
      subscriptions.push({
        id: `s-mock-${++seq}`,
        name: p.name,
        url_display: display,
        node_count: 0,
        updated_at_ms: null,
      })
      return { added: 0, skipped: 0, issues: [] }
    },
    'node.list': () => ({ nodes, outbounds, subscriptions }),
    'node.test': ({ ids, url }) => {
      // 与服务一致：测速地址由用户填写，一次最多 64 个节点
      if (!url || !/^https:\/\/\S+$/.test(url)) {
        fail('ipc.invalid_params', 'set a latency test URL first')
      }
      const targets = ids.length > 0 ? [...new Set(ids)] : nodes.map((n) => n.id)
      if (targets.some((id) => !nodes.some((n) => n.id === id))) {
        fail('node.not_found', 'node not found')
      }
      if (targets.length > 64) fail('ipc.invalid_params', 'at most 64 nodes per call')
      return {
        results: targets.map((id, i) => {
          const timedOut = i % 5 === 2
          return {
            id,
            latency_ms: timedOut ? null : 30 + ((i * 47) % 260),
            timed_out: timedOut,
          }
        }),
      }
    },
    'process.list': () => ({ processes: PROCESSES }),
    'conn.subscribe': () => ({}),
    'log.subscribe': () => ({}),
    'driver.status': () => ({ state: session.components.driver, version: '2.2.2' }),
    'driver.unload': () => {
      if (session.state !== 'stopped') fail('driver.busy', 'session is running')
      return { state: 'inactive', version: '2.2.2' }
    },
    // 只为类型完整：界面经外壳的 `diag_export` 导出，浏览器里不显示导出入口
    'diag.export': () => ({
      generated_at_ms: Date.now(),
      environment: {
        service_version: '0.1.0-mock',
        protocol_version: 1,
        os_build: null,
        os_display_version: null,
        memory_integrity: null,
        kernel_version: null,
        kernel_binary: 'unknown',
      },
      session,
      profiles,
      nodes: null,
      log: { available: false, truncated: false, lines: [] },
      problems: [],
    }),
  }

  return {
    call(method, params) {
      try {
        const handler = handlers[method] as (p: typeof params) => IpcResult[typeof method]
        return Promise.resolve(clone(handler(params)))
      } catch (e) {
        return Promise.reject(e)
      }
    },
    subscribe(channel, onEvent) {
      const set = listeners.get(channel) ?? new Set<Listener>()
      listeners.set(channel, set)
      const l = onEvent as Listener
      set.add(l)
      syncTicker()
      return Promise.resolve(() => {
        set.delete(l)
        syncTicker()
      })
    },
  }
}
