// SPDX-License-Identifier: GPL-3.0-or-later
import { act, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Profiler } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ConnEvent } from '@/api/generated'
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
const { activeConnections } = await import('./api')
const { default: ConnectionsPage } = await import('@/routes/ConnectionsPage')

function ev(id: number, over: Partial<ConnEvent> = {}): ConnEvent {
  return {
    conn_id: id,
    phase: 'opened',
    pid: 4120,
    process: id % 2 ? 'MyGame.exe' : 'firefox.exe',
    target: `203.0.113.${id % 250}:443`,
    network: id % 2 ? 'udp' : 'tcp',
    group: id % 2 ? 'game' : 'browser',
    outbound: id % 2 ? 'hk-auto' : 'us-01',
    upload_bytes: 1024,
    download_bytes: 2048,
    started_at_ms: 1_000_000 + id,
    ...over,
  }
}

describe('activeConnections', () => {
  it('keeps the latest state per connection and drops closed ones', () => {
    const rows = activeConnections([
      ev(1),
      ev(2),
      ev(1, { phase: 'updated', download_bytes: 9 }),
      ev(2, { phase: 'closed' }),
      ev(3),
    ])
    expect(rows.map((r) => r.conn_id)).toEqual([3, 1])
    expect(rows[1]?.download_bytes).toBe(9)
  })
})

describe('ConnectionsPage', () => {
  useFakeViewport()

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['requestAnimationFrame', 'cancelAnimationFrame'] })
    handler = undefined
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  async function mount() {
    let commits = 0
    renderWithQuery(
      <Profiler id="conn" onRender={() => (commits += 1)}>
        <ConnectionsPage />
      </Profiler>,
    )
    await act(async () => {
      await Promise.resolve()
    })
    return () => commits
  }

  function burst(events: ConnEvent[]) {
    act(() => {
      for (const e of events) handler?.(e)
    })
    act(() => {
      vi.advanceTimersToNextFrame()
    })
  }

  it('absorbs a burst of a thousand events with a bounded number of renders', async () => {
    const commits = await mount()
    expect(call).toHaveBeenCalledWith('conn.subscribe', {})
    const before = commits()
    burst(Array.from({ length: 1500 }, (_, i) => ev(i + 1)))

    // 一帧最多触发少量提交，而不是每个事件一次（C-CODE-10）
    expect(commits() - before).toBeLessThanOrEqual(3)
    expect(screen.getByText('活动连接').nextSibling).toHaveTextContent('1500')
    const table = screen.getByRole('table', { name: '连接' })
    const rows = within(table).getAllByRole('row')
    expect(rows.length).toBeGreaterThan(5)
    expect(rows.length).toBeLessThan(60)
  })

  it('filters by protocol and search text', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await mount()
    burst([ev(1), ev(2), ev(3, { process: 'launcher.exe' })])
    const table = screen.getByRole('table', { name: '连接' })
    expect(within(table).getAllByRole('row')).toHaveLength(4)

    await user.click(screen.getByRole('button', { name: 'UDP' }))
    expect(within(table).getAllByRole('row')).toHaveLength(3)

    await user.type(screen.getByRole('searchbox', { name: '搜索进程或目标地址' }), 'launcher')
    const rows = within(table).getAllByRole('row')
    expect(rows).toHaveLength(2)
    expect(rows[1]).toHaveTextContent('launcher.exe')
  })

  it('freezes the list while paused', async () => {
    const user = userEvent.setup({ advanceTimers: vi.advanceTimersByTime })
    await mount()
    burst([ev(1)])
    await user.click(screen.getByRole('button', { name: '暂停刷新' }))
    burst([ev(2), ev(3)])
    expect(screen.getByText('活动连接').nextSibling).toHaveTextContent('1')
    await user.click(screen.getByRole('button', { name: '已暂停 · 点击继续' }))
    expect(screen.getByText('活动连接').nextSibling).toHaveTextContent('3')
  })

  it('shows an empty state before any event', async () => {
    await mount()
    expect(screen.getByText('暂无被改道的连接')).toBeInTheDocument()
  })
})
