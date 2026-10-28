// SPDX-License-Identifier: GPL-3.0-or-later
// 把 IPC 错误翻译成界面文案：按错误码取 i18n 资源，不直接显示服务端的 message（C-UI-04）。
import type { TFunction } from 'i18next'

import type { ErrorCode } from '@/api/generated'

/** 全部错误码。用 Record 保证与生成的 ErrorCode 一一对应：新增错误码时这里会编译失败。 */
export const ERROR_CODES: Record<ErrorCode | 'ipc.transport', true> = {
  'ipc.transport': true,
  'ipc.version_mismatch': true,
  'ipc.invalid_request': true,
  'ipc.payload_too_large': true,
  'ipc.unauthorized': true,
  'ipc.unknown_method': true,
  'ipc.invalid_params': true,
  'session.already_running': true,
  'session.not_running': true,
  'session.fail_closed_unsupported': true,
  'profile.not_found': true,
  'profile.invalid_schema': true,
  'profile.in_use': true,
  'node.not_found': true,
  'node.import_failed': true,
  'driver.not_loaded': true,
  'driver.load_failed': true,
  'driver.busy': true,
  'kernel.unavailable': true,
  'internal.error': true,
}

function codeOf(e: unknown): string {
  if (typeof e === 'object' && e !== null && 'code' in e) {
    const code = (e as { code: unknown }).code
    if (typeof code === 'string' && code in ERROR_CODES) return code
  }
  return 'ipc.transport'
}

/** 任意错误 → 本地化文案。 */
export function errorText(t: TFunction, e: unknown): string {
  return t(`errors.${codeOf(e)}`)
}
