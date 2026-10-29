// SPDX-License-Identifier: GPL-3.0-or-later
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { LatencyResult, NodeInfo } from '@/api/generated'
import { mockCall } from '@/test/ipc'
import { useFakeViewport } from '@/test/layout'
import { renderWithQuery } from '@/test/render'

vi.mock('@/api/client', async (orig) => ({
  ...(await orig<typeof import('@/api/client')>()),
  call: vi.fn(),
  subscribe: vi.fn(() => Promise.resolve(() => {})),
}))

const { call } = await import('@/api/client')
const { default: ImportLinksDialog } = await import('./ImportLinksDialog')
const { default: AddSubscriptionDialog } = await import('./AddSubscriptionDialog')
const { default: NodeTable } = await import('./NodeTable')

beforeEach(() => {
  vi.mocked(call).mockReset()
})

describe('ImportLinksDialog', () => {
  it('sends the links once and clears them from the screen', async () => {
    const user = userEvent.setup()
    const importSpy = vi.fn(() => ({
      added: 1,
      skipped: 1,
      issues: [
        { line: 2, reason: 'unsupported_protocol' },
        { line: 0, reason: 'some_future_code' },
      ],
    }))
    mockCall(call, {
      'node.import': importSpy,
      'node.list': () => ({ nodes: [], outbounds: [], subscriptions: [] }),
    })
    renderWithQuery(<ImportLinksDialog />)

    await user.click(screen.getByRole('button', { name: '导入分享链接' }))
    const dialog = await screen.findByRole('dialog')
    const box = within(dialog).getByLabelText('分享链接')
    await user.type(box, 'anytls://secret-password@hk.example.net:443#HK{enter}bogus')
    await user.click(within(dialog).getByRole('button', { name: '导入' }))

    expect(importSpy).toHaveBeenCalledWith({
      kind: 'share_links',
      text: 'anytls://secret-password@hk.example.net:443#HK\nbogus',
    })
    // 凭据只写不读：提交后输入框立即清空，结果里只有数量与行号
    expect(box).toHaveValue('')
    const status = await within(dialog).findByRole('status')
    expect(status).toHaveTextContent('新增 1 个，跳过 1 个')
    // 原因代码按 i18n 翻译；整段输入的问题没有行号；未知代码原样显示
    expect(within(status).getByText('第 2 行：不支持的协议')).toBeInTheDocument()
    expect(within(status).getByText('some_future_code')).toBeInTheDocument()
    expect(dialog).not.toHaveTextContent('secret-password')
  })

  it('requires at least one link', async () => {
    const user = userEvent.setup()
    const importSpy = vi.fn()
    mockCall(call, { 'node.import': importSpy })
    renderWithQuery(<ImportLinksDialog />)
    await user.click(screen.getByRole('button', { name: '导入分享链接' }))
    await user.click(
      within(await screen.findByRole('dialog')).getByRole('button', { name: '导入' }),
    )
    expect(await screen.findByText('请粘贴至少一条分享链接')).toBeInTheDocument()
    expect(importSpy).not.toHaveBeenCalled()
  })
})

describe('AddSubscriptionDialog', () => {
  it('validates the URL and submits a subscription', async () => {
    const user = userEvent.setup()
    const importSpy = vi.fn(() => ({ added: 0, skipped: 0, issues: [] }))
    mockCall(call, {
      'node.import': importSpy,
      'node.list': () => ({ nodes: [], outbounds: [], subscriptions: [] }),
    })
    renderWithQuery(<AddSubscriptionDialog />)
    await user.click(screen.getByRole('button', { name: '添加订阅' }))
    const dialog = await screen.findByRole('dialog')
    await user.type(within(dialog).getByLabelText('名称'), '我的订阅')
    await user.type(within(dialog).getByLabelText('订阅地址'), 'ftp://nope')
    await user.click(within(dialog).getByRole('button', { name: '添加' }))
    expect(await within(dialog).findByText(/http:\/\/ 或 https:\/\//)).toBeInTheDocument()
    expect(importSpy).not.toHaveBeenCalled()

    const url = within(dialog).getByLabelText('订阅地址')
    await user.clear(url)
    await user.type(url, 'https://sub.example.com/s?token=abc')
    await user.click(within(dialog).getByRole('button', { name: '添加' }))
    await waitFor(() =>
      expect(importSpy).toHaveBeenCalledWith({
        kind: 'subscription',
        name: '我的订阅',
        url: 'https://sub.example.com/s?token=abc',
      }),
    )
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
  })
})

describe('NodeTable', () => {
  useFakeViewport()

  const nodes: NodeInfo[] = Array.from({ length: 1000 }, (_, i) => ({
    id: `n${i}`,
    name: `节点 ${i}`,
    protocol: 'trojan',
    server: `n${i}.example.net:443`,
    subscription_id: null,
    credential: 'set',
  }))

  it('virtualizes large lists and shows latency tones', () => {
    const latencies = new Map<string, LatencyResult>([
      ['n0', { id: 'n0', latency_ms: 42, timed_out: false }],
      ['n1', { id: 'n1', latency_ms: null, timed_out: true }],
    ])
    renderWithQuery(
      <NodeTable
        nodes={nodes}
        outbounds={[{ tag: 'hk-auto', kind: 'url_test', members: ['n0', 'n1'], current: 'n0' }]}
        latencies={latencies}
      />,
    )
    const table = screen.getByRole('table', { name: '全部节点' })
    const rows = within(table).getAllByRole('row')
    // 表头 + 可视区域内的少量行，而不是 1000 行
    expect(rows.length).toBeGreaterThan(5)
    expect(rows.length).toBeLessThan(60)
    expect(within(table).getByText('42 ms')).toHaveClass('text-brand')
    expect(within(table).getByText('超时')).toHaveClass('text-destructive')
    expect(within(table).getAllByText('hk-auto')).toHaveLength(2)
  })

  it('shows an empty state', () => {
    renderWithQuery(<NodeTable nodes={[]} outbounds={[]} latencies={new Map()} />)
    expect(screen.getByText(/还没有节点/)).toBeInTheDocument()
  })
})
