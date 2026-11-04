// SPDX-License-Identifier: GPL-3.0-or-later
// 手动添加节点：表单的字段与校验，以及把表单拼成分享链接。
//
// 服务只有一条导入路径（`node.import`，解析与校验都在 procroute-core-mgr::link）。表单拼出链接后走同一条路径，
// 校验、去重和凭据存储都不用重写，也不用新增 IPC 方法。拼出的链接要能被解析器读对：两边共用
// tests/fixtures/node-links/manual.json，manualNode.test.ts 确认这里拼出的就是其中的链接，
// core-mgr 的 link 测试确认这些链接解析出的就是预期的节点。
import { z } from 'zod'

import type { NodeProtocol } from '@/api/generated'

export const PROTOCOLS: readonly NodeProtocol[] = [
  'shadowsocks',
  'vmess',
  'vless',
  'trojan',
  'hysteria2',
  'tuic',
  'anytls',
  'socks',
  'http',
]

export const SS_METHODS = [
  '2022-blake3-aes-128-gcm',
  '2022-blake3-aes-256-gcm',
  '2022-blake3-chacha20-poly1305',
  'aes-128-gcm',
  'aes-192-gcm',
  'aes-256-gcm',
  'chacha20-ietf-poly1305',
  'xchacha20-ietf-poly1305',
] as const

export const VMESS_CIPHERS = ['auto', 'aes-128-gcm', 'chacha20-poly1305', 'none', 'zero'] as const

export const FINGERPRINTS = [
  'chrome',
  'firefox',
  'edge',
  'safari',
  '360',
  'qq',
  'ios',
  'android',
  'random',
  'randomized',
] as const

export const TRANSPORTS = ['tcp', 'ws', 'grpc', 'h2', 'httpupgrade'] as const
export const TUIC_CONGESTION = ['bbr', 'cubic', 'new_reno'] as const
export const TUIC_UDP_RELAY = ['native', 'quic'] as const

export type Security = 'none' | 'tls' | 'reality'

/** 可选传输安全的协议能选什么；其余协议固定（trojan 等必须 TLS，shadowsocks 与 socks 没有 TLS）。 */
function securityChoices(protocol: NodeProtocol): readonly Security[] {
  if (protocol === 'vless') return ['tls', 'reality', 'none']
  if (protocol === 'vmess' || protocol === 'http') return ['none', 'tls']
  return []
}

/** 切换协议时传输安全的默认值。 */
export function defaultSecurity(protocol: NodeProtocol): Security {
  return securityChoices(protocol)[0] ?? 'none'
}

/** 这个协议与传输安全下，表单显示哪些字段；没显示的字段不进链接。 */
export function fieldsOf(protocol: NodeProtocol, security: Security) {
  const choices = securityChoices(protocol)
  const alwaysTls = ['trojan', 'hysteria2', 'tuic', 'anytls'].includes(protocol)
  const tls = alwaysTls || (choices.includes(security) && security !== 'none')
  const reality = protocol === 'vless' && security === 'reality'
  // HTTPS 代理的链接带不了 TLS 参数（带查询参数的会被当成订阅地址）
  const tlsOptions = tls && protocol !== 'http'
  return {
    uuid: protocol === 'vmess' || protocol === 'vless' || protocol === 'tuic',
    password: ['shadowsocks', 'trojan', 'hysteria2', 'tuic', 'anytls'].includes(protocol),
    auth: protocol === 'socks' || protocol === 'http',
    method: protocol === 'shadowsocks',
    vmessCipher: protocol === 'vmess',
    flow: protocol === 'vless',
    securityChoices: choices,
    sni: tlsOptions,
    insecure: tlsOptions && !reality,
    alpn: tlsOptions && !reality,
    fingerprint: tlsOptions && ['vmess', 'vless', 'trojan'].includes(protocol),
    reality,
    transport: protocol === 'vmess' || protocol === 'vless' || protocol === 'trojan',
    obfs: protocol === 'hysteria2',
    tuic: protocol === 'tuic',
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
// 与 core-mgr 的 is_valid_server 一致；IPv6 不带方括号
const SERVER = /^[^\s/\\@?#[\]]+$/
const REALITY_KEY = /^[A-Za-z0-9_-]{43}$/
const SHORT_ID = /^(?:[0-9a-f]{2}){0,8}$/i

export const manualNodeSchema = z
  .object({
    protocol: z.enum([
      'shadowsocks',
      'vmess',
      'vless',
      'trojan',
      'hysteria2',
      'tuic',
      'anytls',
      'socks',
      'http',
    ]),
    name: z.string().trim(),
    server: z.string().trim(),
    port: z.string().trim(),
    uuid: z.string().trim(),
    // 凭据不做 trim：空格可能是密码的一部分
    password: z.string(),
    username: z.string(),
    method: z.enum(SS_METHODS),
    vmessCipher: z.enum(VMESS_CIPHERS),
    vision: z.boolean(),
    security: z.enum(['none', 'tls', 'reality']),
    sni: z.string().trim(),
    insecure: z.boolean(),
    alpn: z.string().trim(),
    fingerprint: z.union([z.enum(FINGERPRINTS), z.literal('')]),
    publicKey: z.string().trim(),
    shortId: z.string().trim(),
    transport: z.enum(TRANSPORTS),
    path: z.string().trim(),
    host: z.string().trim(),
    serviceName: z.string().trim(),
    obfsPassword: z.string(),
    congestion: z.union([z.enum(TUIC_CONGESTION), z.literal('')]),
    udpRelay: z.union([z.enum(TUIC_UDP_RELAY), z.literal('')]),
  })
  .superRefine((v, ctx) => {
    const issue = (path: string, message: string) =>
      ctx.addIssue({ code: 'custom', path: [path], message: `node.manual.errors.${message}` })
    const f = fieldsOf(v.protocol, v.security)
    if (v.server === '') issue('server', 'required')
    else if (!SERVER.test(v.server)) issue('server', 'server')
    const port = Number(v.port)
    if (v.port === '') issue('port', 'required')
    else if (!Number.isInteger(port) || port < 1 || port > 65535) issue('port', 'port')
    if (f.uuid) {
      if (v.uuid === '') issue('uuid', 'required')
      else if (!UUID.test(v.uuid)) issue('uuid', 'uuid')
    }
    if (f.password && v.password === '') issue('password', 'required')
    if (f.auth && (v.username === '') !== (v.password === '')) {
      issue(v.username === '' ? 'username' : 'password', 'auth')
    }
    if (f.reality) {
      if (v.publicKey === '') issue('publicKey', 'required')
      else if (!REALITY_KEY.test(v.publicKey)) issue('publicKey', 'publicKey')
      if (!SHORT_ID.test(v.shortId)) issue('shortId', 'shortId')
    }
  })

export type ManualNodeForm = z.input<typeof manualNodeSchema>
export type ManualNodeValues = z.output<typeof manualNodeSchema>

export const MANUAL_NODE_DEFAULTS: ManualNodeForm = {
  protocol: 'shadowsocks',
  name: '',
  server: '',
  port: '',
  uuid: '',
  password: '',
  username: '',
  method: '2022-blake3-aes-128-gcm',
  vmessCipher: 'auto',
  vision: false,
  security: 'none',
  sni: '',
  insecure: false,
  alpn: '',
  fingerprint: '',
  publicKey: '',
  shortId: '',
  transport: 'tcp',
  path: '',
  host: '',
  serviceName: '',
  obfsPassword: '',
  congestion: '',
  udpRelay: '',
}

const enc = encodeURIComponent

/** `键=值` 参数，空值不写。解析器不把 `+` 当空格，所以不用 URLSearchParams。 */
function query(params: Record<string, string | boolean>): string {
  const parts = Object.entries(params)
    .filter(([, value]) => value !== '' && value !== false)
    .map(([key, value]) => `${key}=${value === true ? '1' : enc(value as string)}`)
  return parts.length > 0 ? `?${parts.join('&')}` : ''
}

function base64Utf8(text: string): string {
  let binary = ''
  for (const byte of new TextEncoder().encode(text)) binary += String.fromCharCode(byte)
  return btoa(binary)
}

/** Xray 分享链接标准里的传输层参数。 */
function transportParams(v: ManualNodeValues) {
  const webLike = v.transport === 'ws' || v.transport === 'h2' || v.transport === 'httpupgrade'
  return {
    type: v.transport === 'tcp' ? '' : v.transport,
    path: webLike ? v.path : '',
    host: webLike ? v.host : '',
    serviceName: v.transport === 'grpc' ? v.serviceName : '',
  }
}

/** v2rayN 第 2 版的 VMess JSON。gRPC 的服务名在 v2rayN 里放在 `path`。 */
function vmessLink(v: ManualNodeValues, tls: boolean, name: string): string {
  const grpc = v.transport === 'grpc'
  const json = {
    v: '2',
    ps: name,
    add: v.server,
    port: v.port,
    id: v.uuid,
    aid: '0',
    scy: v.vmessCipher,
    net: v.transport,
    type: 'none',
    host: grpc ? '' : v.host,
    path: grpc ? v.serviceName : v.path,
    tls: tls ? 'tls' : '',
    sni: tls ? v.sni : '',
    alpn: tls ? v.alpn : '',
    fp: tls ? v.fingerprint : '',
    allowInsecure: tls && v.insecure ? '1' : '0',
  }
  return `vmess://${base64Utf8(JSON.stringify(json))}`
}

/** 把校验过的表单拼成分享链接。 */
export function toShareLink(v: ManualNodeValues): string {
  const f = fieldsOf(v.protocol, v.security)
  const host = v.server.includes(':') ? `[${v.server}]` : v.server
  const at = `${host}:${v.port}`
  const fragment = v.name === '' ? '' : `#${enc(v.name)}`
  const tlsParams = {
    sni: f.sni ? v.sni : '',
    alpn: f.alpn ? v.alpn : '',
    fp: f.fingerprint ? v.fingerprint : '',
  }
  switch (v.protocol) {
    case 'shadowsocks':
      return `ss://${enc(`${v.method}:${v.password}`)}@${at}${fragment}`
    case 'vmess':
      return vmessLink(v, f.sni, v.name)
    case 'vless':
      return `vless://${enc(v.uuid)}@${at}${query({
        encryption: 'none',
        security: v.security,
        ...tlsParams,
        allowInsecure: f.insecure && v.insecure,
        pbk: f.reality ? v.publicKey : '',
        sid: f.reality ? v.shortId : '',
        flow: v.vision ? 'xtls-rprx-vision' : '',
        ...transportParams(v),
      })}${fragment}`
    case 'trojan':
      return `trojan://${enc(v.password)}@${at}${query({
        security: 'tls',
        ...tlsParams,
        allowInsecure: v.insecure,
        ...transportParams(v),
      })}${fragment}`
    case 'hysteria2':
      return `hysteria2://${enc(v.password)}@${at}/${query({
        sni: v.sni,
        alpn: v.alpn,
        insecure: v.insecure,
        obfs: v.obfsPassword === '' ? '' : 'salamander',
        'obfs-password': v.obfsPassword,
      })}${fragment}`
    case 'tuic':
      return `tuic://${enc(v.uuid)}:${enc(v.password)}@${at}${query({
        sni: v.sni,
        alpn: v.alpn,
        allow_insecure: v.insecure,
        congestion_control: v.congestion,
        udp_relay_mode: v.udpRelay,
      })}${fragment}`
    case 'anytls':
      return `anytls://${enc(v.password)}@${at}/${query({
        sni: v.sni,
        alpn: v.alpn,
        insecure: v.insecure,
      })}${fragment}`
    case 'socks':
    case 'http': {
      const auth = v.username === '' ? '' : `${enc(v.username)}:${enc(v.password)}@`
      const scheme = v.protocol === 'socks' ? 'socks5' : v.security === 'tls' ? 'https' : 'http'
      return `${scheme}://${auth}${at}${fragment}`
    }
  }
}
