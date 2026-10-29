// SPDX-License-Identifier: GPL-3.0-or-later
// 外壳集成：托盘菜单随状态更新、托盘操作走会话 mutation、断开连接后不显示旧状态、开机自启开关。
import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SessionStatus } from '@/api/generated'
import { mockCall } from '@/test/ipc'
import { renderApp } from '@/test/render'

const shell = vi.hoisted(() => ({
  tray: null as ((id: string) => void) | null,
  connection: null as ((connected: boolean) => void) | null,
  autostart: false,
}))

vi.mock('@/api/shell', async (orig) => ({
  ...(await orig<typeof import('@/api/shell')>()),
  inShell: () => true,
  updateTray: vi.fn(() => Promise.resolve()),
  onTrayAction: vi.fn((cb: (id: string) => void) => {
    shell.tray = cb
    return Promise.resolve(() => {
      shell.tray = null
    })
  }),
  onServiceConnection: vi.fn((cb: (connected: boolean) => void) => {
    shell.connection = cb
    return Promise.resolve(() => {
      shell.connection = null
    })
  }),
  getAutostart: vi.fn(() => Promise.resolve(shell.autostart)),
  setAutostart: vi.fn((enabled: boolean) => {
    shell.autostart = enabled
    return Promise.resolve(enabled)
  }),
}))

vi.mock('@/api/client', async (orig) => ({
  ...(await orig<typeof import('@/api/client')>()),
  call: vi.fn(),
  subscribe: vi.fn(() => Promise.resolve(() => {})),
}))

const { call } = await import('@/api/client')
const { updateTray, setAutostart } = await import('@/api/shell')
type TrayModel = Parameters<typeof updateTray>[0]

const STOPPED: SessionStatus = {
  state: 'stopped',
  profile_id: null,
  profile_name: null,
  mode: null,
  components: { service: 'active', driver: 'inactive', kernel: 'inactive' },
  blocked_reason: null,
}
const running = (id: string, name: string): SessionStatus => ({
  ...STOPPED,
  state: 'running',
  profile_id: id,
  profile_name: name,
  mode: 'tun',
  components: { service: 'active', driver: 'inactive', kernel: 'active' },
})

const PROFILES = [
  { id: 'p1', name: '游戏加速', mode: 'tun' as const, group_count: 1, active: false },
  { id: 'p2', name: '浏览器', mode: 'tun' as const, group_count: 1, active: false },
]

function setup(initial: SessionStatus) {
  let status = initial
  const order: string[] = []
  const handlers = {
    'session.status': vi.fn(() => status),
    'session.start': vi.fn(({ profile_id }: { profile_id: string }) => {
      order.push(`start:${profile_id}`)
      const name = PROFILES.find((p) => p.id === profile_id)?.name ?? ''
      status = running(profile_id, name)
      return status
    }),
    'session.stop': vi.fn(() => {
      order.push('stop')
      status = STOPPED
      return status
    }),
    'profile.list': () => ({ profiles: PROFILES }),
    'profile.get': () => {
      throw { code: 'profile.not_found', message: 'x' }
    },
    'driver.status': () => ({ state: 'inactive' as const, version: null }),
  }
  mockCall(call, handlers)
  renderApp('/settings')
  return { handlers, order }
}

function lastTray(): TrayModel {
  const calls = vi.mocked(updateTray).mock.calls
  const last = calls.at(-1)
  if (!last) throw new Error('the tray was never updated')
  return last[0]
}

async function trayReady() {
  await waitFor(() => {
    expect(shell.tray).not.toBeNull()
  })
}

beforeEach(() => {
  vi.mocked(call).mockReset()
  vi.mocked(updateTray).mockClear()
  vi.mocked(setAutostart).mockClear()
  shell.autostart = false
})

describe('desktop shell', () => {
  it('keeps the tray menu in sync with the session', async () => {
    setup(STOPPED)
    await waitFor(() => {
      expect(lastTray().tooltip).toBe('ProcRoute：未启动会话')
    })
    expect(JSON.stringify(lastTray().items)).toContain('启动会话（游戏加速）')
  })

  it('starts the target profile from the tray and reflects it', async () => {
    const { handlers } = setup(STOPPED)
    await trayReady()
    await waitFor(() => {
      expect(lastTray().tooltip).toBe('ProcRoute：未启动会话')
    })
    act(() => shell.tray?.('session.start'))
    await waitFor(() => {
      expect(handlers['session.start']).toHaveBeenCalledWith({ profile_id: 'p1' })
    })
    await waitFor(() => {
      expect(lastTray().tooltip).toBe('ProcRoute：游戏加速')
    })
  })

  it('switching profiles stops the running session first', async () => {
    const { order } = setup(running('p1', '游戏加速'))
    await trayReady()
    await waitFor(() => {
      expect(lastTray().tooltip).toBe('ProcRoute：游戏加速')
    })
    act(() => shell.tray?.('profile:p2'))
    await waitFor(() => {
      expect(order).toEqual(['stop', 'start:p2'])
    })
    await waitFor(() => {
      expect(lastTray().tooltip).toBe('ProcRoute：浏览器')
    })
  })

  it('shows that the service is unreachable instead of stale state', async () => {
    const { handlers } = setup(running('p1', '游戏加速'))
    expect(await screen.findByText('游戏加速 · TUN 分流模式')).toBeInTheDocument()
    handlers['session.status'].mockImplementation(() => {
      throw new Error('pipe closed')
    })
    await waitFor(() => {
      expect(shell.connection).not.toBeNull()
    })
    act(() => shell.connection?.(false))
    expect(await screen.findByText('无法连接到 ProcRoute 服务')).toBeInTheDocument()
    expect(screen.queryByText('游戏加速 · TUN 分流模式')).not.toBeInTheDocument()
    await waitFor(() => {
      expect(lastTray().tooltip).toBe('ProcRoute：无法连接到服务')
    })
  })

  it('toggles start at sign-in', async () => {
    const user = userEvent.setup()
    setup(STOPPED)
    const section = await screen.findByRole('region', { name: '常规' })
    const toggle = await within(section).findByRole('switch', { name: '开机自启' })
    await waitFor(() => {
      expect(toggle).toBeEnabled()
    })
    expect(toggle).not.toBeChecked()
    await user.click(toggle)
    expect(setAutostart).toHaveBeenCalledWith(true)
    await waitFor(() => {
      expect(toggle).toBeChecked()
    })
  })
})
