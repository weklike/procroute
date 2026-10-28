// SPDX-License-Identifier: GPL-3.0-or-later
import { act, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { LogEvent } from '@/api/generated'
import { useFakeViewport } from '@/test/layout'
import { renderWithQuery } from '@/test/render'

type Handler = (payload: unknown) => void
let handler: Handler | undefined

vi.mock('@/api/client', async (orig) => ({
  ...(await orig<typeof import('@/api/client')>()),
  call: vi.fn(() => Promise.resolve({})),
  subscribe: vi.fn((_channel: string, h: Handler) => {
    handler = h
    return Promise.resolve(() => {})
  }),
}))

const { call } = await import('@/api/client')
const { formatFields, isSensitiveKey } = await import('./redact')
const { default: LogsPage } = await import('@/routes/LogsPage')

function log(level: LogEvent['level'], module: string, message: string, fields = {}): LogEvent {
  return { ts_ms: Date.UTC(2026, 9, 28, 2, 21, 3, 114), level, module, message, fields }
}

describe('redaction', () => {
  it('masks values of credential-looking fields', () => {
    expect(formatFields({ pid: '4120', password: 'hunter2', auth_token: 'abc' })).toBe(
      'pid=4120 password=*** auth_token=***',
    )
    for (const k of ['uuid', 'private_key', 'psk', 'secret', 'pwd', 'Token']) {
      expect(isSensitiveKey(k), k).toBe(true)
    }
    for (const k of ['pid', 'module', 'outbound', 'group', 'dst']) {
      expect(isSensitiveKey(k), k).toBe(false)
    }
  })
})

describe('LogsPage', () => {
  useFakeViewport()

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['requestAnimationFrame', 'cancelAnimationFrame'] })
    handler = undefined
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  async function mountWith(entries: LogEvent[]) {
    renderWithQuery(<LogsPage />)
    await act(async () => {
      await Promise.resolve()
    })
    act(() => {
      for (const e of entries) handler?.(e)
    })
    act(() => {
      vi.advanceTimersToNextFrame()
    })
  }

  it('subscribes to every level and filters by minimum level and module', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await mountWith([
      log('debug', 'intercept', '首个 SYN 暂存后归属成功'),
      log('info', 'relay', '流已改道', { pid: '4120' }),
      log('warn', 'core-mgr', 'sing-box 异常退出，正在重启'),
      log('error', 'relay', '本地 SOCKS 入口不可达'),
    ])
    expect(call).toHaveBeenCalledWith('log.subscribe', { min_level: 'debug' })
    const list = screen.getByRole('log', { name: '日志列表' })
    expect(within(list).getAllByRole('listitem')).toHaveLength(4)

    await user.click(screen.getByRole('button', { name: '警告' }))
    expect(within(list).getAllByRole('listitem')).toHaveLength(2)

    await user.click(screen.getByRole('button', { name: '全部' }))
    await user.selectOptions(screen.getByRole('combobox', { name: '模块' }), 'relay')
    const items = within(list).getAllByRole('listitem')
    expect(items).toHaveLength(2)
    expect(items[0]).toHaveTextContent('pid=4120')
  })

  it('searches messages and fields', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await mountWith([
      log('info', 'relay', '流已改道', { pid: '4120' }),
      log('info', 'procwatch', '子进程已纳入', { pid: '5012' }),
    ])
    await user.type(screen.getByRole('searchbox'), 'pid=5012')
    const items = within(screen.getByRole('log')).getAllByRole('listitem')
    expect(items).toHaveLength(1)
    expect(items[0]).toHaveTextContent('子进程已纳入')
  })

  it('never shows credential values even if the service leaked one', async () => {
    await mountWith([log('info', 'core-mgr', 'node updated', { password: 'hunter2' })])
    expect(screen.getByRole('log')).toHaveTextContent('password=***')
    expect(screen.queryByText(/hunter2/)).not.toBeInTheDocument()
  })

  it('renders thousands of lines with a bounded DOM', async () => {
    await mountWith(
      Array.from({ length: 2000 }, (_, i) => log('info', 'relay', `line ${i}`, { i: `${i}` })),
    )
    const items = within(screen.getByRole('log')).getAllByRole('listitem')
    expect(items.length).toBeGreaterThan(5)
    expect(items.length).toBeLessThan(70)
  })

  it('shows an empty state', async () => {
    await mountWith([])
    expect(screen.getByText('暂无日志')).toBeInTheDocument()
  })
})
