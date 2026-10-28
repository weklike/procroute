// SPDX-License-Identifier: GPL-3.0-or-later
import { act, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { SessionStatus } from '@/api/generated'
import { mockCall } from '@/test/ipc'
import { renderApp } from '@/test/render'

type Handler = (payload: unknown) => void
const listeners = new Map<string, Handler>()

vi.mock('@/api/client', async (orig) => ({
  ...(await orig<typeof import('@/api/client')>()),
  call: vi.fn(),
  subscribe: vi.fn((channel: string, h: Handler) => {
    listeners.set(channel, h)
    return Promise.resolve(() => listeners.delete(channel))
  }),
}))

const { call } = await import('@/api/client')

const STOPPED: SessionStatus = {
  state: 'stopped',
  profile_id: null,
  profile_name: null,
  mode: null,
  components: { service: 'active', driver: 'inactive', kernel: 'inactive' },
  blocked_reason: null,
}
const RUNNING: SessionStatus = {
  state: 'running',
  profile_id: 'p1',
  profile_name: '游戏加速',
  mode: 'precise',
  components: { service: 'active', driver: 'active', kernel: 'active' },
  blocked_reason: null,
}
const BLOCKED: SessionStatus = {
  ...RUNNING,
  state: 'blocked',
  components: { service: 'active', driver: 'active', kernel: 'failed' },
  blocked_reason: 'kernel_crash_loop',
}

function setup(initial: SessionStatus) {
  const start = vi.fn(() => RUNNING)
  const stop = vi.fn(() => STOPPED)
  mockCall(call, {
    'session.status': () => initial,
    'session.start': start,
    'session.stop': stop,
    'profile.list': () => ({
      profiles: [{ id: 'p1', name: '游戏加速', mode: 'precise', group_count: 1, active: false }],
    }),
    'profile.get': () => {
      throw { code: 'profile.not_found', message: 'x' }
    },
  })
  renderApp('/settings')
  return { start, stop }
}

async function chips() {
  return within(await screen.findByRole('list', { name: '组件状态' }))
}

beforeEach(() => {
  vi.mocked(call).mockReset()
  listeners.clear()
})

describe('SessionBar', () => {
  it('shows a stopped session and starts the selected profile', async () => {
    const user = userEvent.setup()
    const { start } = setup(STOPPED)
    expect(await screen.findByText('未启动会话')).toBeInTheDocument()
    const c = await chips()
    expect(c.getByText('服务').nextSibling).toHaveTextContent('运行中')
    expect(c.getByText('驱动').nextSibling).toHaveTextContent('未加载')
    expect(c.getByText('内核').nextSibling).toHaveTextContent('未启动')

    await user.click(await screen.findByRole('button', { name: '启动会话' }))
    await waitFor(() => expect(start).toHaveBeenCalledWith({ profile_id: 'p1' }))
    expect(await screen.findByText('游戏加速 · 精确进程模式')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '停止会话' })).toBeInTheDocument()
  })

  it('shows a running session and stops it with one click', async () => {
    const user = userEvent.setup()
    const { stop } = setup(RUNNING)
    expect(await screen.findByText('游戏加速 · 精确进程模式')).toBeInTheDocument()
    const c = await chips()
    expect(c.getByText('驱动').nextSibling).toHaveTextContent('已加载')
    expect(c.getByText('内核').nextSibling).toHaveTextContent('运行中')
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: '停止会话' }))
    await waitFor(() => expect(stop).toHaveBeenCalled())
    expect(await screen.findByRole('button', { name: '启动会话' })).toBeInTheDocument()
  })

  it('announces fail-closed blocking with its reason', async () => {
    const user = userEvent.setup()
    const { start } = setup(BLOCKED)
    const alert = await screen.findByRole('alert')
    expect(alert).toHaveTextContent('目标进程网络已阻断')
    expect(alert).toHaveTextContent('1 分钟内异常退出 3 次')
    expect(alert).toHaveTextContent('不会走直连')
    expect((await chips()).getByText('内核').nextSibling).toHaveTextContent('已停止')
    // 阻断时停止按钮仍然可用
    expect(screen.getByRole('button', { name: '停止会话' })).toBeEnabled()
    await user.click(within(alert).getByRole('button', { name: '重新启动' }))
    await waitFor(() => expect(start).toHaveBeenCalledWith({ profile_id: 'p1' }))
  })

  it('follows session.status events pushed by the service', async () => {
    setup(RUNNING)
    expect(await screen.findByText('游戏加速 · 精确进程模式')).toBeInTheDocument()
    await waitFor(() => expect(listeners.has('session.status')).toBe(true))
    act(() => listeners.get('session.status')?.(BLOCKED))
    expect(await screen.findByRole('alert')).toHaveTextContent('目标进程网络已阻断')
  })
})

describe('DriverPanel', () => {
  it('only allows unloading the driver when no session is running', async () => {
    const user = userEvent.setup()
    const unload = vi.fn(() => ({ state: 'inactive' as const, version: '2.2.2' }))
    let session = RUNNING
    mockCall(call, {
      'session.status': () => session,
      'session.stop': () => (session = STOPPED),
      'driver.status': () => ({
        state: session === RUNNING ? 'active' : 'inactive',
        version: '2.2.2',
      }),
      'driver.unload': unload,
      'profile.list': () => ({ profiles: [] }),
    })
    renderApp('/settings')
    const panel = within(await screen.findByRole('region', { name: '拦截驱动' }))
    expect(await panel.findByText('会话运行中无法卸载，请先停止会话。')).toBeInTheDocument()
    expect(panel.getByRole('button', { name: '卸载驱动' })).toBeDisabled()

    // 会话停止后驱动在服务里仍是已加载（例如上一次会话残留）：可以一键卸载
    session = { ...STOPPED, components: { ...STOPPED.components, driver: 'active' } }
    mockCall(call, {
      'session.status': () => session,
      'driver.status': () => ({ state: 'active', version: '2.2.2' }),
      'driver.unload': unload,
      'profile.list': () => ({ profiles: [] }),
    })
    act(() => listeners.get('session.status')?.(session))
    const button = panel.getByRole('button', { name: '卸载驱动' })
    await waitFor(() => expect(button).toBeEnabled())
    await user.click(button)
    await waitFor(() => expect(unload).toHaveBeenCalled())
  })
})
