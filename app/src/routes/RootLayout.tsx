// SPDX-License-Identifier: GPL-3.0-or-later
import { Outlet } from '@tanstack/react-router'

import AppNav from '@/components/AppNav'
import SessionBar from '@/features/session/SessionBar'
import { useApplyTheme } from '@/hooks/useApplyTheme'

/** 外壳：左侧导航 + 顶部会话条 + 页面。 */
export default function RootLayout() {
  useApplyTheme()
  return (
    <div className="flex min-h-screen">
      <AppNav />
      <div className="flex min-w-0 flex-1 flex-col">
        <SessionBar />
        <main className="flex min-h-0 flex-1 flex-col gap-5 p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
