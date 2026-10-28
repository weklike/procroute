// SPDX-License-Identifier: GPL-3.0-or-later
// fail-closed 触发时必须明确提示「目标进程网络已阻断」及原因，禁止静默（C-UI-02）。
import { Link } from '@tanstack/react-router'
import { ShieldAlert } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import type { BlockedReason } from '@/api/generated'
import { Button } from '@/components/ui/button'

type Props = {
  reason: BlockedReason | null
  onRestart: () => void
  restarting: boolean
}

export default function BlockedBanner({ reason, onRestart, restarting }: Props) {
  const { t } = useTranslation()
  return (
    <div
      role="alert"
      className="border-destructive bg-destructive-muted flex flex-wrap items-center gap-3 border-b px-6 py-3"
    >
      <ShieldAlert aria-hidden="true" className="text-destructive size-5 shrink-0" />
      <div className="flex min-w-0 flex-[1_1_20rem] flex-col">
        <strong className="text-destructive">{t('session.blocked.title')}</strong>
        <span className="text-[13px]">
          {reason ? t(`session.blocked.reasons.${reason}`) : t('session.blocked.unknown')}
        </span>
      </div>
      <Button asChild variant="outline" size="sm">
        <Link to="/logs">{t('session.blocked.viewLogs')}</Link>
      </Button>
      <Button size="sm" disabled={restarting} onClick={onRestart}>
        {t('session.blocked.restart')}
      </Button>
    </div>
  )
}
