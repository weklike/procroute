// SPDX-License-Identifier: GPL-3.0-or-later
// 桌面外壳领域：与服务的连接状态、托盘菜单、开机自启。不在 Tauri 里运行时全部是空操作。
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useEffectEvent, useMemo } from 'react'
import { useTranslation } from 'react-i18next'

import {
  getAutostart,
  inShell,
  onServiceConnection,
  onTrayAction,
  setAutostart,
  updateTray,
} from '@/api/shell'
import { useProfiles } from '@/features/profile/api'
import { useSessionStatusQuery, useStartSession, useStopSession } from '@/features/session/api'
import { useUiStore } from '@/stores/ui'

import { planTrayAction, trayModel } from './tray'

const autostartKey = ['shell', 'autostart'] as const

/**
 * 接住异步建立的事件订阅，返回给 effect 的清理函数：卸载（含严格模式下的模拟卸载）时取消；
 * 订阅建立之前就卸载了，则建立后立刻取消。
 */
function keepUntilCleanup(pending: Promise<() => void>): () => void {
  let disposed = false
  let unlisten: (() => void) | null = null
  pending.then(
    (fn) => {
      if (disposed) fn()
      else unlisten = fn
    },
    () => {
      // 外壳不可用时没有事件可收
    },
  )
  return () => {
    disposed = true
    unlisten?.()
  }
}

/**
 * 与服务的连接断开时清空全部服务端数据（界面如实显示「无法连接到服务」，而不是旧状态，C-UI-02）；
 * 重新连上后全部重新获取。
 */
export function useServiceConnectionSync() {
  const qc = useQueryClient()
  const onChange = useEffectEvent((connected: boolean) => {
    if (connected) void qc.invalidateQueries()
    else void qc.resetQueries()
  })
  useEffect(() => keepUntilCleanup(onServiceConnection((c) => onChange(c))), [])
}

/** 把会话状态与方案列表同步到托盘菜单，并执行托盘上的会话操作。 */
export function useTrayBridge() {
  const { t } = useTranslation()
  const status = useSessionStatusQuery()
  const profiles = useProfiles()
  const selected = useUiStore((s) => s.selectedProfileId)
  const selectProfile = useUiStore((s) => s.selectProfile)
  const start = useStartSession()
  const stop = useStopSession()

  const current = status.isError ? undefined : status.data
  const list = useMemo(() => profiles.data?.profiles ?? [], [profiles.data])
  const target = list.find((p) => p.id === selected) ?? list[0]
  const model = useMemo(() => trayModel(t, current, list, target), [t, current, list, target])

  useEffect(() => {
    updateTray(model).catch(() => {
      // 托盘不可用（例如资源管理器重启中）时等下次状态变化再试
    })
  }, [model])

  const onAction = useEffectEvent((id: string) => {
    const plan = planTrayAction(id, current, target)
    if (!plan) return
    if (plan.kind === 'stop') {
      stop.mutate()
      return
    }
    selectProfile(plan.profileId)
    if (plan.kind === 'start') start.mutate(plan.profileId)
    else stop.mutate(undefined, { onSuccess: () => start.mutate(plan.profileId) })
  })
  useEffect(() => keepUntilCleanup(onTrayAction((id) => onAction(id))), [])
}

/** 开机自启开关；`available` 为 false 时（不在桌面外壳里）界面不显示它。 */
export function useAutostart() {
  const qc = useQueryClient()
  const available = inShell()
  const query = useQuery({
    queryKey: autostartKey,
    queryFn: () => getAutostart(),
    enabled: available,
  })
  const mutation = useMutation({
    mutationFn: (enabled: boolean) => setAutostart(enabled),
    onSuccess: (enabled) => qc.setQueryData(autostartKey, enabled),
  })
  return { available, query, mutation }
}
