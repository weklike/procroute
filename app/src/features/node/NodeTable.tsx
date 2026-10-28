// SPDX-License-Identifier: GPL-3.0-or-later
// 全部节点（虚拟化列表）：订阅可能带来上千个节点（C-CODE-10）。节点名等外部数据按纯文本渲染（C-SEC-10）。
import { useVirtualizer } from '@tanstack/react-virtual'
import { useMemo, useRef } from 'react'
import { useTranslation } from 'react-i18next'

import type { LatencyResult, NodeInfo, OutboundInfo } from '@/api/generated'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

import { latencyTone, TONE_CLASS } from './latency'

const ROW_HEIGHT = 44
const GRID =
  'grid grid-cols-[minmax(8rem,1.2fr)_8rem_minmax(10rem,1.5fr)_minmax(6rem,1fr)_6rem] gap-3'

type Props = {
  nodes: NodeInfo[]
  outbounds: OutboundInfo[]
  latencies: ReadonlyMap<string, LatencyResult>
}

export default function NodeTable({ nodes, outbounds, latencies }: Props) {
  const { t } = useTranslation()
  const parent = useRef<HTMLDivElement>(null)
  const memberOf = useMemo(() => {
    const m = new Map<string, string[]>()
    for (const o of outbounds) {
      for (const id of o.members) m.set(id, [...(m.get(id) ?? []), o.tag])
    }
    return m
  }, [outbounds])
  const virt = useVirtualizer({
    count: nodes.length,
    getScrollElement: () => parent.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 12,
  })

  if (nodes.length === 0) {
    return <p className="text-muted-foreground p-4 text-sm">{t('node.noNodes')}</p>
  }

  const latencyText = (r: LatencyResult | undefined) =>
    !r
      ? t('node.latency.untested')
      : r.timed_out || r.latency_ms === null
        ? t('node.latency.timeout')
        : t('node.latency.ms', { ms: r.latency_ms })

  return (
    <div
      role="table"
      aria-label={t('node.nodesTitle')}
      aria-rowcount={nodes.length + 1}
      className="bg-card overflow-x-auto rounded-xl border text-[13px]"
    >
      <div
        role="row"
        className={cn(GRID, 'text-muted-foreground min-w-[48rem] border-b px-4 py-2.5')}
      >
        <span role="columnheader">{t('node.columns.name')}</span>
        <span role="columnheader">{t('node.columns.protocol')}</span>
        <span role="columnheader">{t('node.columns.server')}</span>
        <span role="columnheader">{t('node.columns.outbound')}</span>
        <span role="columnheader" className="text-right">
          {t('node.columns.latency')}
        </span>
      </div>
      <div ref={parent} className="max-h-[28rem] min-w-[48rem] overflow-y-auto">
        <div role="rowgroup" className="relative" style={{ height: virt.getTotalSize() }}>
          {virt.getVirtualItems().map((v) => {
            const n = nodes[v.index]
            if (!n) return null
            const r = latencies.get(n.id)
            return (
              <div
                key={n.id}
                role="row"
                aria-rowindex={v.index + 2}
                className={cn(GRID, 'absolute inset-x-0 items-center border-b px-4')}
                style={{ height: v.size, transform: `translateY(${v.start}px)` }}
              >
                <span role="cell" className="truncate font-medium">
                  {n.name}
                </span>
                <span role="cell">
                  <Badge variant="secondary">{t(`node.protocols.${n.protocol}`)}</Badge>
                </span>
                <span role="cell" className="truncate font-mono text-[12.5px]">
                  {n.server}
                </span>
                <span role="cell" className="truncate font-mono text-[12.5px]">
                  {(memberOf.get(n.id) ?? []).join(', ')}
                </span>
                <span
                  role="cell"
                  className={cn(
                    'text-right font-semibold tabular-nums',
                    TONE_CLASS[latencyTone(r)],
                  )}
                >
                  {latencyText(r)}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
