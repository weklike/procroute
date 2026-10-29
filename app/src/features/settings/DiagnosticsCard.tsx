// SPDX-License-Identifier: GPL-3.0-or-later
// 诊断包导出（T-112）：一个按钮，导出后显示保存路径（纯文本，可选中复制）。
import { useTranslation } from 'react-i18next'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

import { diagnosticsErrorText, useExportDiagnostics } from './api'

export default function DiagnosticsCard() {
  const { t } = useTranslation()
  const { available, mutation } = useExportDiagnostics()
  if (!available) return null

  return (
    <section
      aria-labelledby="settings-diag"
      className="bg-card flex max-w-2xl flex-col gap-3 rounded-xl border p-5"
    >
      <h2 id="settings-diag" className="text-[15px] font-semibold">
        {t('settings.diagTitle')}
      </h2>
      <p className="text-muted-foreground text-[13px]">{t('settings.diagHint')}</p>
      <div>
        <Button variant="outline" disabled={mutation.isPending} onClick={() => mutation.mutate()}>
          {mutation.isPending ? t('settings.diagExporting') : t('settings.diagExport')}
        </Button>
      </div>
      {mutation.isSuccess ? (
        <p role="status" className="text-[13px]">
          {t('settings.diagSaved')}{' '}
          <span className="font-mono break-all select-all">{mutation.data}</span>
        </p>
      ) : null}
      {mutation.isError ? (
        <Alert variant="destructive">
          <AlertDescription>{diagnosticsErrorText(t, mutation.error)}</AlertDescription>
        </Alert>
      ) : null}
    </section>
  )
}
