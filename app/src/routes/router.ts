// SPDX-License-Identifier: GPL-3.0-or-later
// 路由表（T-060）：方案 / 节点 / 连接 / 日志 / 设置。代码方式定义，避免引入文件路由的生成步骤。
import {
  createRootRoute,
  createRoute,
  createRouter,
  redirect,
  type RouterHistory,
} from '@tanstack/react-router'

import ConnectionsPage from './ConnectionsPage'
import LogsPage from './LogsPage'
import NodesPage from './NodesPage'
import ProfilesPage from './ProfilesPage'
import RootLayout from './RootLayout'
import SettingsPage from './SettingsPage'

const rootRoute = createRootRoute({ component: RootLayout })

const indexRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/',
  beforeLoad: () => {
    // TanStack Router 约定用 throw 触发重定向
    throw redirect({ to: '/profiles' })
  },
})

export const ROUTES = [
  createRoute({ getParentRoute: () => rootRoute, path: '/profiles', component: ProfilesPage }),
  createRoute({ getParentRoute: () => rootRoute, path: '/nodes', component: NodesPage }),
  createRoute({
    getParentRoute: () => rootRoute,
    path: '/connections',
    component: ConnectionsPage,
  }),
  createRoute({ getParentRoute: () => rootRoute, path: '/logs', component: LogsPage }),
  createRoute({ getParentRoute: () => rootRoute, path: '/settings', component: SettingsPage }),
] as const

const routeTree = rootRoute.addChildren([indexRoute, ...ROUTES])

/** 创建路由器。测试里传入内存历史。 */
export function createAppRouter(history?: RouterHistory) {
  return createRouter({
    routeTree,
    history,
    // 未知路径回到方案页
    defaultNotFoundComponent: () => null,
    notFoundMode: 'root',
  })
}

declare module '@tanstack/react-router' {
  interface Register {
    router: ReturnType<typeof createAppRouter>
  }
}
