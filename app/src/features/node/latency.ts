// SPDX-License-Identifier: GPL-3.0-or-later
import type { LatencyResult } from '@/api/generated'

export type LatencyTone = 'good' | 'slow' | 'bad' | 'none'

/** 延迟分档：100 ms 以下为好，300 ms 以下为慢，超时或失败为差（设计稿的配色约定）。 */
export function latencyTone(r: LatencyResult | undefined): LatencyTone {
  if (!r) return 'none'
  if (r.timed_out || r.latency_ms === null) return 'bad'
  return r.latency_ms < 100 ? 'good' : r.latency_ms < 300 ? 'slow' : 'bad'
}

/** 各档对应的主题色类名（不写死颜色值）。 */
export const TONE_CLASS: Record<LatencyTone, string> = {
  good: 'text-brand',
  slow: 'text-warning',
  bad: 'text-destructive',
  none: 'text-muted-foreground',
}
