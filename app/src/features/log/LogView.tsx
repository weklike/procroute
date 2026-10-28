// SPDX-License-Identifier: GPL-3.0-or-later
// 日志列表：虚拟化渲染（C-CODE-10），消息与字段按纯文本渲染（C-SEC-10），敏感字段打码（C-SEC-04）。
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'

import type { LogEvent, LogLevel } from '@/api/generated'
import { formatClock } from '@/lib/format'
import { cn } from '@/lib/utils'

import { formatFields } from './redact'

const ROW_HEIGHT = 34

const LEVEL_CLASS: Record<LogLevel, { text: string; row: string }> = {
  debug: { text: 'text-muted-foreground', row: '' },
  info: { text: 'text-brand', row: '' },
  warn: { text: 'text-warning', row: 'bg-warning-muted' },
  error: { text: 'text-destructive', row: 'bg-destructive-muted' },
}

type Props = { entries: readonly LogEvent[]; emptyText: string }

export default function LogView({ entries, emptyText }: Props) {
  const { t } = useTranslation()
  const parent = useRef<HTMLDivElement>(null)
  const virt = useVirtualizer({
    count: entries.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 16,
  })

  if (entries.length === 0) {
    return <p className="bg-card text-muted-foreground rounded-xl border p-4">{emptyText}</p>
  }
  return (
    <div
      ref={parent}
      // 高频追加的列表不做朗读，避免屏幕阅读器被刷屏
      role="log"
      aria-live="off"
      aria-label={t('log.list')}
      className="bg-card min-h-64 flex-1 overflow-auto rounded-xl border"
    >
      <ol className="relative min-w-[52rem]" style={{ height: virt.getTotalSize() }}>
        {virt.getVirtualItems().map((v) => {
          const e = entries[v.index]
          if (!e) return null
          const cls = LEVEL_CLASS[e.level]
          return (
            <li
              key={v.key}
              className={cn(
                'absolute inset-x-0 flex items-baseline gap-3 border-b px-4 py-1.5 font-mono text-[12.5px]',
                cls.row,
              )}
              style={{ height: v.size, transform: `translateY(${v.start}px)` }}
            >
              <span className="text-muted-foreground w-24 shrink-0 tabular-nums">
                {formatClock(e.ts_ms)}
              </span>
              <span className={cn('w-14 shrink-0 font-semibold uppercase', cls.text)}>
                {e.level}
              </span>
              <span className="w-24 shrink-0 truncate">{e.module}</span>
              <span className="min-w-0 flex-1 truncate font-sans text-[13px]">
                {e.message}{' '}
                <span className="text-muted-foreground font-mono text-[12.5px]">
                  {formatFields(e.fields)}
                </span>
              </span>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
