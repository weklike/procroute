// SPDX-License-Identifier: GPL-3.0-or-later
// 设置领域：诊断包导出（T-112）。报告由服务生成并脱敏（C-SEC-04），外壳直接存进「下载」文件夹，
// 界面只拿到保存路径。不在桌面外壳里时不可用。
import { useMutation } from '@tanstack/react-query'
import type { TFunction } from 'i18next'

import { DiagSaveError, exportDiagnostics, inShell } from '@/api/shell'
import { errorText } from '@/lib/errors'

/** 导出诊断包；`available` 为 false 时（不在桌面外壳里）界面不显示入口。 */
export function useExportDiagnostics() {
  const mutation = useMutation({ mutationFn: () => exportDiagnostics() })
  return { available: inShell(), mutation }
}

/** 导出失败的文案：存盘失败单独说明，其余按服务的错误码翻译。 */
export function diagnosticsErrorText(t: TFunction, e: unknown): string {
  return e instanceof DiagSaveError ? t('settings.diagSaveFailed') : errorText(t, e)
}
