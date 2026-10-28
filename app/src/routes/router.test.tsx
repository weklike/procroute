// SPDX-License-Identifier: GPL-3.0-or-later
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import { renderApp } from '@/test/render'

describe('routes', () => {
  it.each([
    ['/profiles', '方案'],
    ['/nodes', '节点'],
    ['/connections', '连接'],
    ['/logs', '日志'],
    ['/settings', '设置'],
  ])('%s renders its page', async (path, heading) => {
    renderApp(path)
    expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeInTheDocument()
  })

  it('redirects / to the profiles page', async () => {
    const { router } = renderApp('/')
    await waitFor(() => {
      expect(router.state.location.pathname).toBe('/profiles')
    })
  })

  it('navigates with the sidebar and marks the current page', async () => {
    renderApp('/profiles')
    const nav = await screen.findByRole('navigation', { name: '主导航' })
    await userEvent.click(within(nav).getByRole('link', { name: '日志' }))
    expect(await screen.findByRole('heading', { level: 1, name: '日志' })).toBeInTheDocument()
    expect(within(nav).getByRole('link', { name: '日志' })).toHaveAttribute('aria-current', 'page')
  })
})
