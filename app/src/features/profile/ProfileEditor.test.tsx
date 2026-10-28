// SPDX-License-Identifier: GPL-3.0-or-later
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Profile } from '@/api/generated'
import { mockCall } from '@/test/ipc'
import { renderWithQuery } from '@/test/render'

vi.mock('@/api/client', async (orig) => ({
  ...(await orig<typeof import('@/api/client')>()),
  call: vi.fn(),
  subscribe: vi.fn(() => Promise.resolve(() => {})),
}))

const { call, IpcError } = await import('@/api/client')
const { default: ProfileEditor } = await import('./ProfileEditor')
const { newProfile } = await import('./form')

const PROFILE: Profile = {
  schema_version: 1,
  id: 'p1',
  name: '游戏加速',
  mode: 'precise',
  fail_policy: 'block',
  dns: { strategy: 'sniff', hijack_port53: true },
  udp: { enabled: true, block_quic: false },
  groups: [
    {
      tag: 'game',
      outbound: 'hk-auto',
      include_children: true,
      match: [{ type: 'name', value: 'launcher.exe', recursive: false }],
    },
  ],
  exclude: [],
}

const NODES = {
  nodes: [],
  outbounds: [{ tag: 'hk-auto', kind: 'url_test' as const, members: [], current: null }],
  subscriptions: [],
}

function setup(save: (p: Profile) => { id: string } | Promise<{ id: string }>) {
  const onSaved = vi.fn()
  const saveSpy = vi.fn(save)
  mockCall(call, {
    'node.list': () => NODES,
    'profile.save': saveSpy,
    'process.list': () => ({
      processes: [
        { pid: 2216, name: 'steam.exe', path: 'C:\\Steam\\steam.exe', matched_group: null },
        { pid: 3388, name: 'launcher.exe', path: 'D:\\G\\launcher.exe', matched_group: 'game' },
      ],
    }),
  })
  renderWithQuery(
    <ProfileEditor profile={PROFILE} isNew={false} onSaved={onSaved} onDeleted={() => {}} />,
  )
  return { onSaved, saveSpy }
}

beforeEach(() => {
  vi.mocked(call).mockReset()
})

describe('ProfileEditor', () => {
  it('saves the edited profile through profile.save', async () => {
    const user = userEvent.setup()
    const { onSaved, saveSpy } = setup((p) => ({ id: p.id }))
    const name = screen.getByLabelText('方案名称')
    await user.clear(name)
    await user.type(name, '新名字')
    await user.click(screen.getByRole('button', { name: '保存方案' }))

    await waitFor(() => expect(onSaved).toHaveBeenCalledWith('p1'))
    expect(saveSpy).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'p1', name: '新名字', fail_policy: 'block' }),
    )
    expect(await screen.findByRole('status')).toHaveTextContent('已保存')
  })

  it('blocks submission when client-side validation fails', async () => {
    const user = userEvent.setup()
    const { saveSpy } = setup((p) => ({ id: p.id }))
    await user.clear(screen.getByLabelText('方案名称'))
    await user.click(screen.getByRole('button', { name: '保存方案' }))
    expect(await screen.findByText('不能为空')).toBeInTheDocument()
    expect(screen.getByLabelText('方案名称')).toHaveAttribute('aria-invalid', 'true')
    expect(saveSpy).not.toHaveBeenCalled()
  })

  it('shows server-side field issues on the matching field', async () => {
    const user = userEvent.setup()
    setup(() => {
      throw new IpcError('profile.invalid_schema', '1 issue', [
        { path: 'groups[0].tag', code: 'duplicate_tag', message: 'dup' },
      ])
    })
    await user.click(screen.getByRole('button', { name: '保存方案' }))
    expect(await screen.findByText('组标签重复')).toBeInTheDocument()
    expect(screen.getByLabelText('组标签')).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByRole('alert')).toHaveTextContent('服务端校验未通过')
  })

  it('asks for confirmation before taking over system DNS', async () => {
    const user = userEvent.setup()
    const { saveSpy } = setup((p) => ({ id: p.id }))
    const takeover = screen.getByRole('radio', { name: /接管系统 DNS/ })

    await user.click(takeover)
    let dialog = await screen.findByRole('dialog', { name: '确定接管系统 DNS？' })
    await user.click(within(dialog).getByRole('button', { name: '取消' }))
    expect(screen.getByRole('radio', { name: /域名嗅探/ })).toBeChecked()

    await user.click(takeover)
    dialog = await screen.findByRole('dialog', { name: '确定接管系统 DNS？' })
    await user.click(within(dialog).getByRole('button', { name: '确认开启' }))
    expect(takeover).toBeChecked()

    await user.click(screen.getByRole('button', { name: '保存方案' }))
    await waitFor(() =>
      expect(saveSpy).toHaveBeenCalledWith(
        expect.objectContaining({ dns: { strategy: 'system_takeover', hijack_port53: true } }),
      ),
    )
  })

  it('adds running processes as rules of a group', async () => {
    const user = userEvent.setup()
    const { saveSpy } = setup((p) => ({ id: p.id }))
    await user.click(screen.getByRole('button', { name: '添加进程' }))
    const dialog = await screen.findByRole('dialog', { name: '添加进程到 game 组' })
    // 已在方案中的进程不可再选
    expect(within(dialog).getByRole('checkbox', { name: /launcher\.exe/ })).toBeDisabled()
    await user.click(await within(dialog).findByRole('checkbox', { name: /steam\.exe/ }))
    await user.click(within(dialog).getByRole('button', { name: '添加 1 个' }))

    expect(screen.getByText('steam.exe')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '保存方案' }))
    await waitFor(() => expect(saveSpy).toHaveBeenCalled())
    expect(saveSpy.mock.calls[0]?.[0].groups[0]?.match).toEqual([
      { type: 'name', value: 'launcher.exe', recursive: false },
      { type: 'name', value: 'steam.exe', recursive: false },
    ])
  })

  it('requires at least one rule per group', async () => {
    const user = userEvent.setup()
    const { saveSpy } = setup((p) => ({ id: p.id }))
    await user.click(screen.getByRole('button', { name: '删除规则 launcher.exe' }))
    await user.click(screen.getByRole('button', { name: '保存方案' }))
    expect(await screen.findByText('至少需要一条规则')).toBeInTheDocument()
    expect(saveSpy).not.toHaveBeenCalled()
  })
})

describe('newProfile', () => {
  it('starts fail-closed with DNS sniffing', () => {
    const p = newProfile('x')
    expect(p.fail_policy).toBe('block')
    expect(p.dns.strategy).toBe('sniff')
    expect(p.mode).toBe('precise')
  })
})
