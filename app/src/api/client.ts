// SPDX-License-Identifier: GPL-3.0-or-later
// 手写的 IPC 薄封装（T-041）。同目录的 generated.ts 是生成文件，禁止手改（C-ARCH-04）。
//
// 只有 features/<领域>/api.ts 与 hooks/ 可以导入本文件；组件禁止直接调用（C-CODE-09，lint 强制）。
//
// 开发构建里、且不在 Tauri 里运行时（`pnpm -C app dev` 用浏览器打开、或单元测试），改用 ./mock
// 里的内存模拟服务，方便在开发机上做界面而不连真实服务；`VITE_IPC_MOCK=1 pnpm -C app tauri dev`
// 在桌面外壳里也用它（开发机上不运行服务，AGENTS 第 8 节第 5 条）。生产构建中 `import.meta.env.DEV`
// 为常量 false，模拟服务连同示例数据被整体剔除，不会随安装包分发（C-SEC-09）。
import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

import type {
  ErrorCode,
  FieldIssue,
  IpcChannel,
  IpcEvent,
  IpcMethod,
  IpcRequest,
  IpcResult,
} from './generated'
import type { MockService } from './mock/service'

/** Tauri 后端里转发 IPC 请求的命令名。 */
export const IPC_COMMAND = 'ipc_call'

/**
 * 事件通道名 → Tauri 事件名。
 * Tauri 的事件名只允许字母、数字、`-`、`/`、`:`、`_`，所以把 `.` 换成 `:` 并加 `ipc:` 前缀，
 * 例如 `conn.subscribe` → `ipc:conn:subscribe`。Tauri 后端发事件时必须用同样的规则。
 */
export function tauriEventName(channel: IpcChannel): string {
  return `ipc:${channel.replaceAll('.', ':')}`
}

let mockService: Promise<MockService> | null = null

function shouldUseMock(): boolean {
  return import.meta.env.DEV && (!isTauri() || import.meta.env.VITE_IPC_MOCK === '1')
}

/** 浏览器开发与测试用的模拟服务；首次使用时创建。 */
function mock(): Promise<MockService> {
  // 动态 import 必须直接放在 `import.meta.env.DEV` 的分支里：生产构建中它是常量 false，打包器才能
  // 把整个模拟服务（含示例数据）剔除。只在 shouldUseMock() 里判断不够，模块仍会被打进安装包。
  mockService ??= import.meta.env.DEV
    ? import('./mock/service').then((m) => m.createMockService())
    : Promise.reject(new Error('the mock service only exists in development builds'))
  return mockService
}

/** 单次请求：方法名 + 入参 → 结果；失败统一抛出 IpcError。 */
export async function call<M extends IpcMethod>(
  method: M,
  params: IpcRequest[M],
): Promise<IpcResult[M]> {
  try {
    if (shouldUseMock()) return await (await mock()).call(method, params)
    return await invoke<IpcResult[M]>(IPC_COMMAND, { method, params })
  } catch (e) {
    throw IpcError.from(e)
  }
}

/** 订阅事件通道。返回的取消函数必须在组件卸载时调用（C-CODE-10）。 */
export async function subscribe<E extends IpcChannel>(
  channel: E,
  onEvent: (payload: IpcEvent[E]) => void,
): Promise<UnlistenFn> {
  if (shouldUseMock()) return (await mock()).subscribe(channel, onEvent)
  return listen<IpcEvent[E]>(tauriEventName(channel), (e) => {
    onEvent(e.payload)
  })
}

/** `ipc.transport`：没能从服务拿到结构化错误（例如 Tauri 后端本身出错）。 */
export type ClientErrorCode = ErrorCode | 'ipc.transport'

export class IpcError extends Error {
  readonly code: ClientErrorCode
  /** 逐字段的校验问题；表单据此把错误标到对应字段上。 */
  readonly fields: readonly FieldIssue[]

  constructor(code: ClientErrorCode, message: string, fields: readonly FieldIssue[] = []) {
    super(message)
    this.name = 'IpcError'
    this.code = code
    this.fields = fields
  }

  static from(e: unknown): IpcError {
    if (e instanceof IpcError) return e
    if (isStructured(e)) return new IpcError(e.code, e.message, fieldsOf(e))
    return new IpcError('ipc.transport', e instanceof Error ? e.message : String(e))
  }
}

function isStructured(e: unknown): e is { code: ErrorCode; message: string } {
  if (typeof e !== 'object' || e === null) return false
  const o = e as Record<string, unknown>
  return typeof o.code === 'string' && o.code.includes('.') && typeof o.message === 'string'
}

function fieldsOf(e: object): FieldIssue[] {
  const fields = (e as { fields?: unknown }).fields
  if (!Array.isArray(fields)) return []
  return fields.filter(
    (f): f is FieldIssue =>
      typeof f === 'object' &&
      f !== null &&
      typeof (f as Record<string, unknown>).path === 'string' &&
      typeof (f as Record<string, unknown>).code === 'string',
  )
}
