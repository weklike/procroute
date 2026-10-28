// SPDX-License-Identifier: GPL-3.0-or-later
import { RouterProvider } from '@tanstack/react-router'

import { createAppRouter } from './routes/router'

const router = createAppRouter()

/** 应用根：路由。QueryClientProvider 在 main.tsx。 */
export default function App() {
  return <RouterProvider router={router} />
}
