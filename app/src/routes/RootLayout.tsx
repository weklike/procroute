// SPDX-License-Identifier: GPL-3.0-or-later
import { Outlet } from '@tanstack/react-router'

import AppNav from '@/components/AppNav'
import { useApplyTheme } from '@/hooks/useApplyTheme'

/** 外壳：左侧导航 + 右侧页面。 */
export default function RootLayout() {
  useApplyTheme()
  return (
    <div className="flex min-h-screen">
      <AppNav />
      <div className="flex min-w-0 flex-1 flex-col">
        <main className="flex min-h-0 flex-1 flex-col gap-5 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
