// SPDX-License-Identifier: GPL-3.0-or-later
// 连接领域：实时连接事件经环形缓冲按帧批量刷新（C-CODE-10），再按 conn_id 归并成「当前连接」。
import { useEffect, useMemo } from 'react'

import { call } from '@/api/client'
import type { ConnEvent } from '@/api/generated'
import { DEFAULT_CAP, useIpcSubscription } from '@/hooks/useIpcSubscription'

export const CONN_EVENT_CAP = DEFAULT_CAP

/** 把事件序列归并成仍然活动的连接，按开始时间从新到旧排列。 */
export function activeConnections(events: readonly ConnEvent[]): ConnEvent[] {
  const latest = new Map<number, ConnEvent>()
  for (const e of events) {
    if (e.phase === 'closed') latest.delete(e.conn_id)
    else latest.set(e.conn_id, e)
  }
  return [...latest.values()].sort(
    (a, b) => b.started_at_ms - a.started_at_ms || b.conn_id - a.conn_id,
  )
}

/** 订阅连接事件并返回当前活动的连接。 */
export function useConnections(): ConnEvent[] {
  useEffect(() => {
    // 通知服务开始推送；失败时列表保持为空，服务状态由会话条展示
    call('conn.subscribe', {}).catch(() => {})
  }, [])
  const events = useIpcSubscription('conn.subscribe', CONN_EVENT_CAP)
  return useMemo(() => activeConnections(events), [events])
}
