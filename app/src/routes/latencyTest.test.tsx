// SPDX-License-Identifier: GPL-3.0-or-later
// 节点测速：测速地址由用户在设置里填写，没有地址时不能测（C-SEC-08、C-SEC-09）。走内存模拟服务。
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it } from 'vitest'

import { useUiStore } from '@/stores/ui'
import { useFakeViewport } from '@/test/layout'
import { renderApp } from '@/test/render'

beforeEach(() => {
  useUiStore.setState({ latencyTestUrl: '' })
})

describe('latency test URL', () => {
  useFakeViewport()

  it('is saved from the settings page after validation', async () => {
    const user = userEvent.setup()
    renderApp('/settings')
    const input = await screen.findByLabelText('测速地址')
    expect(input).toHaveValue('')

    // 纯 http 不行：内核会把它换成内置的默认地址
    await user.type(input, 'http://probe.example/generate_204')
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByText(/请填写以 https:\/\/ 开头的地址/)).toBeInTheDocument()
    expect(useUiStore.getState().latencyTestUrl).toBe('')

    await user.clear(input)
    await user.type(input, '  https://127.0.0.1:8080/generate_204 ')
    await user.click(screen.getByRole('button', { name: '保存' }))
    expect(await screen.findByRole('status')).toHaveTextContent('已保存')
    expect(useUiStore.getState().latencyTestUrl).toBe('https://127.0.0.1:8080/generate_204')
  })

  it('is required before nodes can be tested', async () => {
    renderApp('/nodes')
    const button = await screen.findByRole('button', { name: '全部测速' })
    await waitFor(() => {
      expect(screen.getByText(/测速前先在设置中填写测速地址/)).toBeInTheDocument()
    })
    expect(button).toBeDisabled()
    expect(screen.getByRole('link', { name: '前往设置' })).toHaveAttribute('href', '/settings')
  })

  it('tests every node through the configured URL', async () => {
    const user = userEvent.setup()
    useUiStore.setState({ latencyTestUrl: 'https://127.0.0.1:8080/generate_204' })
    renderApp('/nodes')
    const button = await screen.findByRole('button', { name: '全部测速' })
    await waitFor(() => {
      expect(button).toBeEnabled()
    })
    expect(screen.queryByText(/测速前先在设置中填写测速地址/)).not.toBeInTheDocument()
    const table = screen.getByRole('table', { name: '全部节点' })
    expect(within(table).getAllByText('未测速').length).toBeGreaterThan(0)
    await user.click(button)
    await waitFor(() => {
      expect(within(table).queryByText('未测速')).not.toBeInTheDocument()
    })
    expect(within(table).getAllByText(/^\d+ ms$/).length).toBeGreaterThan(0)
  })
})
