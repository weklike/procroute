// SPDX-License-Identifier: GPL-3.0-or-later
// 展示层的凭据兜底脱敏（C-SEC-04）。
//
// 服务端保证日志里没有凭据；这里再挡一层：字段名看起来像凭据的，值一律显示为掩码，
// 万一服务端漏掉也不会出现在界面上。
const SENSITIVE =
  /pass(word|wd)?|pwd|secret|token|private[_-]?key|psk|pre[_-]?shared|uuid|credential|auth/i

export const MASK = '***'

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE.test(key)
}

/** 字段 → `k=v` 文本，敏感字段的值替换为掩码。 */
export function formatFields(fields: Readonly<Record<string, string>>): string {
  return Object.entries(fields)
    .map(([k, v]) => `${k}=${isSensitiveKey(k) ? MASK : v}`)
    .join(' ')
}
