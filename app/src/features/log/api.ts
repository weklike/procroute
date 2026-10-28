// SPDX-License-Identifier: GPL-3.0-or-later
// 日志领域：日志事件经环形缓冲按帧批量刷新（C-CODE-10）。
import { useEffect } from 'react'

import { call } from '@/api/client'
import type { LogEvent, LogLevel } from '@/api/generated'
import { DEFAULT_CAP, useIpcSubscription } from '@/hooks/useIpcSubscription'

export const LOG_CAP = DEFAULT_CAP

export const LEVELS: readonly LogLevel[] = ['debug', 'info', 'warn', 'error']

/** 级别从低到高的序号，用于「不低于某级别」的过滤。 */
export function levelRank(level: LogLevel): number {
  return LEVELS.indexOf(level)
}

/** 订阅全部级别的日志，过滤在界面上做，切换级别不必重新订阅。 */
export function useLogs(): LogEvent[] {
  useEffect(() => {
    call('log.subscribe', { min_level: 'debug' }).catch(() => {})
  }, [])
  return useIpcSubscription('log.subscribe', LOG_CAP)
}
