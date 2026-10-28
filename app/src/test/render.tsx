// SPDX-License-Identifier: GPL-3.0-or-later
// 测试辅助：带 QueryClient 与内存路由的渲染。
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createMemoryHistory, RouterProvider } from '@tanstack/react-router'
import { render, type RenderResult } from '@testing-library/react'
import type { ReactElement } from 'react'

import { createAppRouter } from '@/routes/router'

export function testQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity }, mutations: { retry: false } },
  })
}

/** 渲染单个组件，提供独立的 QueryClient。 */
export function renderWithQuery(ui: ReactElement, client = testQueryClient()): RenderResult {
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>)
}

/** 从指定路径渲染整个应用。 */
export function renderApp(path: string, client = testQueryClient()) {
  const router = createAppRouter(createMemoryHistory({ initialEntries: [path] }))
  const result = render(
    <QueryClientProvider client={client}>
      <RouterProvider router={router} />
    </QueryClientProvider>,
  )
  return { ...result, router }
}
