// SPDX-License-Identifier: GPL-3.0-or-later
// 会话与驱动的 Query / Mutation hook。服务端状态只放在 Query 缓存里（C-CODE-09）。
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'

import { call, subscribe } from '@/api/client'
import type { DriverStatus, SessionStatus } from '@/api/generated'

export const sessionKeys = {
  status: ['session', 'status'] as const,
  driver: ['driver', 'status'] as const,
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

function useSessionMutation<P>(fn: (p: P) => Promise<SessionStatus>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (s) => {
      qc.setQueryData(sessionKeys.status, s)
      void qc.invalidateQueries({ queryKey: ['profile'] })
      void qc.invalidateQueries({ queryKey: sessionKeys.driver })
    },
  })
}

export function useStartSession() {
  return useSessionMutation((profileId: string) => call('session.start', { profile_id: profileId }))
}

export function useStopSession() {
  return useSessionMutation(() => call('session.stop', {}))
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
