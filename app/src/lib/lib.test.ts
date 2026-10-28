// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'

import i18n from '@/i18n'

import { ERROR_CODES, errorText } from './errors'
import { formatBytes, formatClock, formatDuration } from './format'

describe('formatBytes', () => {
  it('picks a unit and keeps one decimal below 10', () => {
    expect(formatBytes(0)).toBe('0 B')
    expect(formatBytes(1023)).toBe('1023 B')
    expect(formatBytes(1536)).toBe('1.5 KB')
    expect(formatBytes(12 * 1024)).toBe('12 KB')
    expect(formatBytes(8.6 * 1024 * 1024)).toBe('8.6 MB')
    expect(formatBytes(-5)).toBe('0 B')
  })
})

describe('formatDuration', () => {
  it('formats minutes and hours', () => {
    expect(formatDuration(0)).toBe('00:00')
    expect(formatDuration(65_000)).toBe('01:05')
    expect(formatDuration(3_725_000)).toBe('1:02:05')
  })
})

describe('formatClock', () => {
  it('pads every part', () => {
    const d = new Date(2026, 9, 28, 9, 5, 3, 7)
    expect(formatClock(d.getTime())).toBe('09:05:03.007')
  })
})

describe('errorText', () => {
  it('has a translation for every error code in both languages', () => {
    for (const lng of ['zh-CN', 'en-US']) {
      const t = i18n.getFixedT(lng)
      for (const code of Object.keys(ERROR_CODES)) {
        const text = t(`errors.${code}`)
        expect(text, `${lng} ${code}`).not.toBe(`errors.${code}`)
      }
    }
  })

  it('maps unknown errors to the transport message', () => {
    const t = i18n.getFixedT('zh-CN')
    expect(errorText(t, new Error('boom'))).toBe('无法连接到 ProcRoute 服务')
    expect(errorText(t, { code: 'profile.in_use', message: 'x' })).toBe('方案正在被会话使用')
    expect(errorText(t, { code: 'nope.nope', message: 'x' })).toBe('无法连接到 ProcRoute 服务')
  })
})
