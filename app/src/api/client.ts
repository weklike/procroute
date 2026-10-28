// SPDX-License-Identifier: GPL-3.0-or-later
// 手写的 IPC 薄封装（T-041）。同目录的 generated.ts 是生成文件，禁止手改（C-ARCH-04）。
//
// 只有 features/<领域>/api.ts 与 hooks/ 可以导入本文件；组件禁止直接调用（C-CODE-09，lint 强制）。
import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

import type { ErrorCode, IpcChannel, IpcEvent, IpcMethod, IpcRequest, IpcResult } from './generated'

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

/** 单次请求：方法名 + 入参 → 结果；失败统一抛出 IpcError。 */
export async function call<M extends IpcMethod>(
  method: M,
  params: IpcRequest[M],
): Promise<IpcResult[M]> {
  try {
    return await invoke<IpcResult[M]>(IPC_COMMAND, { method, params })
  } catch (e) {
    throw IpcError.from(e)
  }
}

/** 订阅事件通道。返回的取消函数必须在组件卸载时调用（C-CODE-10）。 */
export function subscribe<E extends IpcChannel>(
  channel: E,
  onEvent: (payload: IpcEvent[E]) => void,
): Promise<UnlistenFn> {
  return listen<IpcEvent[E]>(tauriEventName(channel), (e) => {
    onEvent(e.payload)
  })
}

/** `ipc.transport`：没能从服务拿到结构化错误（例如 Tauri 后端本身出错）。 */
export type ClientErrorCode = ErrorCode | 'ipc.transport'

export class IpcError extends Error {
  readonly code: ClientErrorCode

  constructor(code: ClientErrorCode, message: string) {
    super(message)
    this.name = 'IpcError'
    this.code = code
  }

  static from(e: unknown): IpcError {
    if (e instanceof IpcError) return e
    if (isStructured(e)) return new IpcError(e.code, e.message)
    return new IpcError('ipc.transport', e instanceof Error ? e.message : String(e))
  }
}

function isStructured(e: unknown): e is { code: ErrorCode; message: string } {
  if (typeof e !== 'object' || e === null) return false
  const o = e as Record<string, unknown>
  return typeof o.code === 'string' && o.code.includes('.') && typeof o.message === 'string'
}
