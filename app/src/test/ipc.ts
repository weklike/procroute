// SPDX-License-Identifier: GPL-3.0-or-later
// 测试辅助：给被 vi.mock 替换的 `call` 装上按方法名分派的实现。
//
// 用法（vi.mock 必须写在测试文件里，才能被提升到导入之前）：
//   vi.mock('@/api/client', async (orig) => ({ ...(await orig()), call: vi.fn(), subscribe: vi.fn() }))
//   const { call } = await import('@/api/client')
//   mockCall(call, { 'profile.list': () => ({ profiles: [] }) })
import { vi, type Mock } from 'vitest'

import type { IpcMethod, IpcRequest, IpcResult } from '@/api/generated'

export type Handlers = {
  [M in IpcMethod]?: (params: IpcRequest[M]) => IpcResult[M] | Promise<IpcResult[M]>
}

type CallFn = <M extends IpcMethod>(method: M, params: IpcRequest[M]) => Promise<IpcResult[M]>

export function mockCall(call: CallFn, handlers: Handlers): Mock {
  const mocked = vi.mocked(call) as unknown as Mock
  mocked.mockImplementation(async (method: IpcMethod, params: unknown) => {
    const h = handlers[method] as ((p: unknown) => unknown) | undefined
    if (!h) throw { code: 'ipc.unknown_method', message: `unmocked ${method}` }
    return h(params)
  })
  return mocked
}
