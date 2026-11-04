// SPDX-License-Identifier: GPL-3.0-or-later
// @vitest-environment node
import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import {
  defaultSecurity,
  fieldsOf,
  MANUAL_NODE_DEFAULTS,
  manualNodeSchema,
  PROTOCOLS,
  toShareLink,
  type ManualNodeForm,
} from './manualNode'

// 与 core-mgr 的 link 测试共用：这里确认表单拼出这些链接，那边确认这些链接解析出预期的节点
const FIXTURE = new URL('../../../../tests/fixtures/node-links/manual.json', import.meta.url)

type Case = { case: string; form: Partial<ManualNodeForm>; link: string }
const cases = JSON.parse(readFileSync(FIXTURE, 'utf-8')) as Case[]

const UUID = 'bf000d23-0752-40b4-affe-68f7707a9661'

function errorsOf(form: Partial<ManualNodeForm>) {
  const result = manualNodeSchema.safeParse({
    ...MANUAL_NODE_DEFAULTS,
    server: 'node.example.com',
    port: '443',
    ...form,
  })
  return result.success
    ? {}
    : Object.fromEntries(result.error.issues.map((i) => [i.path.join('.'), i.message]))
}

describe('toShareLink', () => {
  it.each(cases)('$case', ({ form, link }) => {
    const values = manualNodeSchema.parse({ ...MANUAL_NODE_DEFAULTS, ...form })
    expect(toShareLink(values)).toBe(link)
  })

  it('covers every protocol in the fixture', () => {
    const seen = new Set(cases.map((c) => c.form.protocol))
    expect(PROTOCOLS.filter((p) => !seen.has(p))).toEqual([])
  })
})

describe('manualNodeSchema', () => {
  it('requires a valid server and port', () => {
    expect(errorsOf({ protocol: 'socks', server: '', port: '' })).toEqual({
      server: 'node.manual.errors.required',
      port: 'node.manual.errors.required',
    })
    for (const server of ['a b', 'a/b', 'user@host', '[::1]']) {
      expect(errorsOf({ server, protocol: 'socks' }).server).toBe('node.manual.errors.server')
    }
    for (const port of ['0', '65536', '44.3', 'abc']) {
      expect(errorsOf({ port, protocol: 'socks' }).port).toBe('node.manual.errors.port')
    }
  })

  it('requires the credential each protocol uses', () => {
    expect(errorsOf({ protocol: 'shadowsocks' }).password).toBe('node.manual.errors.required')
    expect(errorsOf({ protocol: 'trojan' }).password).toBe('node.manual.errors.required')
    expect(errorsOf({ protocol: 'vless', security: 'tls' }).uuid).toBe(
      'node.manual.errors.required',
    )
    expect(errorsOf({ protocol: 'vmess', uuid: 'not-a-uuid' }).uuid).toBe('node.manual.errors.uuid')
    // TUIC 两个都要
    expect(errorsOf({ protocol: 'tuic', uuid: UUID }).password).toBe('node.manual.errors.required')
    expect(errorsOf({ protocol: 'tuic', password: 'p' }).uuid).toBe('node.manual.errors.required')
    expect(errorsOf({ protocol: 'tuic', uuid: UUID, password: 'p' })).toEqual({})
  })

  it('treats proxy authentication as all or nothing', () => {
    expect(errorsOf({ protocol: 'socks' })).toEqual({})
    expect(errorsOf({ protocol: 'socks', username: 'u', password: 'p' })).toEqual({})
    expect(errorsOf({ protocol: 'http', username: 'u' }).password).toBe('node.manual.errors.auth')
    expect(errorsOf({ protocol: 'http', password: 'p' }).username).toBe('node.manual.errors.auth')
  })

  it('checks REALITY parameters only when REALITY is selected', () => {
    const reality = { protocol: 'vless', uuid: UUID, security: 'reality' } as const
    expect(errorsOf(reality).publicKey).toBe('node.manual.errors.required')
    expect(errorsOf({ ...reality, publicKey: 'short' }).publicKey).toBe(
      'node.manual.errors.publicKey',
    )
    const key = 'jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0'
    expect(errorsOf({ ...reality, publicKey: key })).toEqual({})
    expect(errorsOf({ ...reality, publicKey: key, shortId: 'abc' }).shortId).toBe(
      'node.manual.errors.shortId',
    )
    expect(errorsOf({ protocol: 'vless', uuid: UUID, security: 'tls', shortId: 'abc' })).toEqual({})
  })

  it('does not trim credentials: spaces can be part of a password', () => {
    const values = manualNodeSchema.parse({
      ...MANUAL_NODE_DEFAULTS,
      protocol: 'trojan',
      server: ' tj.example.com ',
      port: ' 443 ',
      password: ' p ',
    })
    expect(values.server).toBe('tj.example.com')
    expect(values.port).toBe('443')
    expect(values.password).toBe(' p ')
  })
})

describe('fieldsOf', () => {
  it('offers the security choices each protocol supports', () => {
    expect(fieldsOf('vless', 'tls').securityChoices).toEqual(['tls', 'reality', 'none'])
    expect(fieldsOf('vmess', 'none').securityChoices).toEqual(['none', 'tls'])
    expect(fieldsOf('http', 'none').securityChoices).toEqual(['none', 'tls'])
    for (const p of ['shadowsocks', 'trojan', 'hysteria2', 'tuic', 'anytls', 'socks'] as const) {
      expect(fieldsOf(p, 'none').securityChoices).toEqual([])
    }
  })

  it('defaults to a security level the protocol supports', () => {
    expect(defaultSecurity('vless')).toBe('tls')
    expect(defaultSecurity('vmess')).toBe('none')
    expect(defaultSecurity('trojan')).toBe('none')
  })

  it('shows TLS options only when TLS is on', () => {
    expect(fieldsOf('vless', 'none').sni).toBe(false)
    expect(fieldsOf('vless', 'tls').sni).toBe(true)
    expect(fieldsOf('trojan', 'none').sni).toBe(true)
    expect(fieldsOf('shadowsocks', 'tls').sni).toBe(false)
    // REALITY 不校验证书，也不用 ALPN
    expect(fieldsOf('vless', 'reality').sni).toBe(true)
    expect(fieldsOf('vless', 'reality').insecure).toBe(false)
    expect(fieldsOf('vless', 'reality').alpn).toBe(false)
    // HTTPS 代理的链接带不了 TLS 参数
    expect(fieldsOf('http', 'tls').sni).toBe(false)
  })
})
