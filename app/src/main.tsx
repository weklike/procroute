// SPDX-License-Identifier: GPL-3.0-or-later
import './index.css'
import './i18n'

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import App from './App'

const queryClient = new QueryClient({
  defaultOptions: {
    // IPC 走本机命名管道，失败多半是服务状态问题，不做盲目重试
    queries: { retry: 1, refetchOnWindowFocus: false },
  },
})

const root = document.getElementById('root')
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <App />
      </QueryClientProvider>
    </StrictMode>,
  )
}
