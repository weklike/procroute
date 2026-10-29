// SPDX-License-Identifier: GPL-3.0-or-later
// 顶部会话条：当前方案、三个组件的状态，以及启动 / 停止会话。
// 启动会话会改变网络行为，入口明确且停止按钮始终可一键撤销（C-UI-01）。
import { Play, Square } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { useProfiles } from '@/features/profile/api'
import { errorText } from '@/lib/errors'
import { useUiStore } from '@/stores/ui'

import { useSessionActivity, useSessionStatus, useStartSession, useStopSession } from './api'
import BlockedBanner from './BlockedBanner'
import ComponentChips from './ComponentChips'

export default function SessionBar() {
  const { t } = useTranslation()
  const status = useSessionStatus()
  const profiles = useProfiles()
  const selected = useUiStore((s) => s.selectedProfileId)
  const start = useStartSession()
  const stop = useStopSession()
  // 托盘菜单也能启停会话：进度与错误按共同的 mutation key 汇总
  const activity = useSessionActivity()
  const s = status.data
  const list = profiles.data?.profiles ?? []
  const target = list.find((p) => p.id === selected) ?? list[0]
  const busy = activity.busy
  const failure = activity.error ?? status.error

  if (!s) {
    return (
      <header className="bg-card text-muted-foreground border-b px-6 py-3 text-sm">
        {status.isError ? errorText(t, status.error) : t('common.loading')}
      </header>
    )
  }

  const running = s.state !== 'stopped'
  return (
    <>
      <header className="bg-card flex flex-wrap items-center gap-4 border-b px-6 py-3">
        <div className="mr-auto flex flex-col">
          <span className="text-muted-foreground text-xs">{t('session.current')}</span>
          <span className="text-[15px] font-semibold">
            {running && s.profile_name
              ? `${s.profile_name} · ${t(`profile.modeNames.${s.mode ?? 'precise'}`)}`
              : t('session.none')}
          </span>
        </div>
        <ComponentChips status={s.components} />
        {running ? (
          <Button
            variant="outline"
            disabled={busy || s.state === 'stopping'}
            onClick={() => stop.mutate()}
          >
            <Square aria-hidden="true" />
            {s.state === 'stopping' || busy ? t('session.stopping') : t('session.stop')}
          </Button>
        ) : (
          <Button
            disabled={busy || !target}
            title={target ? undefined : t('session.noProfile')}
            onClick={() => target && start.mutate(target.id)}
          >
            <Play aria-hidden="true" />
            {busy ? t('session.starting') : t('session.start')}
          </Button>
        )}
      </header>
      {s.state === 'blocked' ? (
        <BlockedBanner
          reason={s.blocked_reason}
          restarting={busy}
          onRestart={() => s.profile_id && start.mutate(s.profile_id)}
        />
      ) : null}
      {failure && !busy ? (
        <Alert variant="destructive" className="rounded-none border-x-0 border-t-0">
          <AlertDescription>{errorText(t, failure)}</AlertDescription>
        </Alert>
      ) : null}
    </>
  )
}
