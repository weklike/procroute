// SPDX-License-Identifier: GPL-3.0-or-later
// 连接面板（设计文档 13.4）：TanStack Virtual 虚拟化，只渲染可视行（C-CODE-10）；
// 进程名、目标地址等外部数据按纯文本渲染（C-SEC-10）。
import { useVirtualizer } from '@tanstack/react-virtual'
import { useRef } from 'react'
import { useTranslation } from 'react-i18next'

import type { ConnEvent } from '@/api/generated'
import { Badge } from '@/components/ui/badge'
import { useNow } from '@/hooks/useNow'
import { formatBytes, formatDuration } from '@/lib/format'
import { cn } from '@/lib/utils'

const ROW_HEIGHT = 48
const GRID =
  'grid grid-cols-[minmax(9rem,1.2fr)_minmax(11rem,1.6fr)_4.5rem_minmax(6rem,1fr)_5.5rem_5.5rem_5rem] items-center gap-3'

type Props = { rows: readonly ConnEvent[]; emptyText: string }

export default function ConnTable({ rows, emptyText }: Props) {
  const { t } = useTranslation()
  const parent = useRef<HTMLDivElement>(null)
  const now = useNow()
  const virt = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
    getItemKey: (i) => rows[i]?.conn_id ?? i,
  })

  return (
    <div
      role="table"
      aria-label={t('pages.connections.title')}
      aria-rowcount={rows.length + 1}
      className="bg-card flex min-h-0 flex-1 flex-col overflow-x-auto rounded-xl border text-[13px]"
    >
      <div
        role="row"
        className={cn(GRID, 'text-muted-foreground min-w-[56rem] border-b px-4 py-2.5')}
      >
        <span role="columnheader">{t('conn.columns.process')}</span>
        <span role="columnheader">{t('conn.columns.target')}</span>
        <span role="columnheader">{t('conn.columns.protocol')}</span>
        <span role="columnheader">{t('conn.columns.outbound')}</span>
        <span role="columnheader" className="text-right">
          {t('conn.columns.upload')}
        </span>
        <span role="columnheader" className="text-right">
          {t('conn.columns.download')}
        </span>
        <span role="columnheader" className="text-right">
          {t('conn.columns.duration')}
        </span>
      </div>
      {rows.length === 0 ? (
        <p className="text-muted-foreground p-4">{emptyText}</p>
      ) : (
        <div ref={parent} className="min-h-64 min-w-[56rem] flex-1 overflow-y-auto">
          <div role="rowgroup" className="relative" style={{ height: virt.getTotalSize() }}>
            {virt.getVirtualItems().map((v) => {
              const r = rows[v.index]
              if (!r) return null
              return (
                <div
                  key={v.key}
                  role="row"
                  aria-rowindex={v.index + 2}
                  className={cn(GRID, 'absolute inset-x-0 border-b px-4')}
                  style={{ height: v.size, transform: `translateY(${v.start}px)` }}
                >
                  <span role="cell" className="flex min-w-0 flex-col">
                    <span className="truncate font-medium">{r.process}</span>
                    <span className="text-muted-foreground text-xs">
                      {t('conn.pid', { pid: r.pid })}
                    </span>
                  </span>
                  <span role="cell" className="truncate font-mono text-[12.5px]">
                    {r.target}
                  </span>
                  <span role="cell">
                    <Badge variant="secondary">{t(`conn.protocols.${r.network}`)}</Badge>
                  </span>
                  <span role="cell" className="truncate font-mono text-[12.5px]">
                    {r.outbound}
                  </span>
                  <span role="cell" className="text-right tabular-nums">
                    {formatBytes(r.upload_bytes)}
                  </span>
                  <span role="cell" className="text-right tabular-nums">
                    {formatBytes(r.download_bytes)}
                  </span>
                  <span role="cell" className="text-muted-foreground text-right tabular-nums">
                    {formatDuration(now - r.started_at_ms)}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
