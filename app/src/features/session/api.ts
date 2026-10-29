// SPDX-License-Identifier: GPL-3.0-or-later
// 会话与驱动的 Query / Mutation hook。服务端状态只放在 Query 缓存里（C-CODE-09）。
import {
  useIsMutating,
  useMutation,
  useMutationState,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { useEffect } from 'react'

import { call, subscribe } from '@/api/client'
import type { DriverStatus, SessionStatus } from '@/api/generated'

export const sessionKeys = {
  status: ['session', 'status'] as const,
  driver: ['driver', 'status'] as const,
  /** 启动与停止会话共用的 mutation 前缀：会话条与托盘菜单触发的操作统一显示进度与错误。 */
  mutation: ['session'] as const,
}

/**
 * 会话状态：先查一次，之后由服务推送的 `session.status` 事件更新缓存。
 * 该事件频率很低，直接写缓存即可，不需要环形缓冲。
 */
export function useSessionStatus() {
  const qc = useQueryClient()
  useEffect(() => {
    let disposed = false
    let unlisten: (() => void) | null = null
    subscribe('session.status', (s) => {
      qc.setQueryData<SessionStatus>(sessionKeys.status, s)
      qc.setQueryData<DriverStatus>(sessionKeys.driver, (d) =>
        d ? { ...d, state: s.components.driver } : d,
      )
    }).then(
      (fn) => {
        if (disposed) fn()
        else unlisten = fn
      },
      () => {
        // 订阅失败时只依赖查询结果
      },
    )
    return () => {
      disposed = true
      unlisten?.()
    }
  }, [qc])
  return useQuery({ queryKey: sessionKeys.status, queryFn: () => call('session.status', {}) })
}

/** 只读会话状态缓存，不另建事件订阅（订阅由 useSessionStatus 负责，会话条始终挂载）。 */
export function useSessionStatusQuery() {
  return useQuery({ queryKey: sessionKeys.status, queryFn: () => call('session.status', {}) })
}

function useSessionMutation<P>(action: 'start' | 'stop', fn: (p: P) => Promise<SessionStatus>) {
  const qc = useQueryClient()
  return useMutation({
    mutationKey: [...sessionKeys.mutation, action],
    mutationFn: fn,
    onSuccess: (s) => {
      qc.setQueryData(sessionKeys.status, s)
      void qc.invalidateQueries({ queryKey: ['profile'] })
      void qc.invalidateQueries({ queryKey: sessionKeys.driver })
    },
  })
}

export function useStartSession() {
  return useSessionMutation('start', (profileId: string) =>
    call('session.start', { profile_id: profileId }),
  )
}

export function useStopSession() {
  return useSessionMutation('stop', () => call('session.stop', {}))
}

/**
 * 会话启停是否正在进行，以及最近一次启停的失败（成功后清除）。
 * 会话条的按钮与托盘菜单各自持有 mutation，这里按共同的 key 汇总。
 */
export function useSessionActivity(): { busy: boolean; error: unknown } {
  const busy = useIsMutating({ mutationKey: sessionKeys.mutation }) > 0
  const states = useMutationState({
    filters: { mutationKey: sessionKeys.mutation },
    select: (m) => ({ status: m.state.status, error: m.state.error, at: m.state.submittedAt }),
  })
  const last = states.reduce<(typeof states)[number] | undefined>(
    (latest, s) => (latest === undefined || s.at >= latest.at ? s : latest),
    undefined,
  )
  return { busy, error: last?.status === 'error' ? last.error : null }
}

export function useDriverStatus() {
  return useQuery({ queryKey: sessionKeys.driver, queryFn: () => call('driver.status', {}) })
}

export function useUnloadDriver() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: () => call('driver.unload', {}),
    onSuccess: (d) => qc.setQueryData(sessionKeys.driver, d),
  })
}
