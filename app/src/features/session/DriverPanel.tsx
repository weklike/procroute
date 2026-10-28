// SPDX-License-Identifier: GPL-3.0-or-later
// 拦截驱动状态与一键卸载（C-UI-01）。会话运行中禁止卸载，服务也会拒绝（C-DRV-02）。
import { useTranslation } from 'react-i18next'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { errorText } from '@/lib/errors'

import { useDriverStatus, useSessionStatus, useUnloadDriver } from './api'

export default function DriverPanel() {
  const { t } = useTranslation()
  const driver = useDriverStatus()
  const session = useSessionStatus()
  const unload = useUnloadDriver()
  const sessionRunning = (session.data?.state ?? 'stopped') !== 'stopped'
  const state = driver.data?.state ?? 'inactive'

  return (
    <section
      aria-labelledby="settings-driver"
      className="bg-card flex max-w-2xl flex-col gap-3 rounded-xl border p-5"
    >
      <h2 id="settings-driver" className="text-[15px] font-semibold">
        {t('settings.driverTitle')}
      </h2>
      <div className="flex flex-wrap items-center gap-3">
        <div className="mr-auto flex flex-col">
          <span className="font-medium">
            {t('settings.driverName', { version: driver.data?.version ?? '' })}
          </span>
          <span className="text-muted-foreground text-[13px]">{t('settings.driverHint')}</span>
        </div>
        <span className="text-[13px] font-semibold">{t(`session.states.driver.${state}`)}</span>
        <Button
          variant="outline"
          disabled={sessionRunning || state === 'inactive' || unload.isPending}
          onClick={() => unload.mutate()}
        >
          {t('settings.unloadDriver')}
        </Button>
      </div>
      {sessionRunning ? (
        <p className="text-muted-foreground text-[13px]">{t('settings.unloadBlocked')}</p>
      ) : null}
      {unload.isError ? (
        <Alert variant="destructive">
          <AlertDescription>{errorText(t, unload.error)}</AlertDescription>
        </Alert>
      ) : null}
      <p className="bg-warning-muted rounded-lg p-3 text-[13px]">{t('settings.antiCheatHint')}</p>
    </section>
  )
}
