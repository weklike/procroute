// SPDX-License-Identifier: GPL-3.0-or-later
import { Search } from 'lucide-react'
import { useDeferredValue, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import type { ConnEvent, Network } from '@/api/generated'
import NativeSelect from '@/components/NativeSelect'
import PageHeader from '@/components/PageHeader'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { CONN_EVENT_CAP, useConnections } from '@/features/conn/api'
import ConnTable from '@/features/conn/ConnTable'
import { formatBytes } from '@/lib/format'
import { cn } from '@/lib/utils'

type Proto = 'all' | Network

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-card flex flex-col gap-0.5 rounded-xl border px-4 py-3">
      <span className="text-muted-foreground text-xs">{label}</span>
      <span className="text-[22px] font-semibold tabular-nums">{value}</span>
    </div>
  )
}

export default function ConnectionsPage() {
  const { t } = useTranslation()
  const live = useConnections()
  // 暂停时冻结当时的快照；事件仍在后台进入环形缓冲
  const [frozen, setFrozen] = useState<ConnEvent[] | null>(null)
  const [query, setQuery] = useState('')
  const [group, setGroup] = useState('')
  const [proto, setProto] = useState<Proto>('all')
  const all = frozen ?? live
  const q = useDeferredValue(query.trim().toLowerCase())

  const groups = useMemo(() => [...new Set(all.map((c) => c.group))].sort(), [all])
  const rows = useMemo(
    () =>
      all.filter(
        (c) =>
          (proto === 'all' || c.network === proto) &&
          (group === '' || c.group === group) &&
          (q === '' || c.process.toLowerCase().includes(q) || c.target.toLowerCase().includes(q)),
      ),
    [all, proto, group, q],
  )
  const totals = useMemo(
    () =>
      all.reduce((acc, c) => ({ up: acc.up + c.upload_bytes, down: acc.down + c.download_bytes }), {
        up: 0,
        down: 0,
      }),
    [all],
  )

  return (
    <>
      <PageHeader
        title={t('pages.connections.title')}
        hint={t('pages.connections.hint')}
        actions={
          <Button
            variant="outline"
            aria-pressed={frozen !== null}
            className={cn(frozen && 'border-warning bg-warning-muted')}
            onClick={() => setFrozen(frozen ? null : live)}
          >
            {frozen ? t('conn.paused') : t('conn.pause')}
          </Button>
        }
      />
      <div className="grid grid-cols-[repeat(auto-fit,minmax(11rem,1fr))] gap-3">
        <Stat label={t('conn.activeCount')} value={all.length.toString()} />
        <Stat label={t('conn.upload')} value={formatBytes(totals.up)} />
        <Stat label={t('conn.download')} value={formatBytes(totals.down)} />
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex flex-[1_1_16rem] items-center">
          <Search aria-hidden="true" className="text-muted-foreground absolute left-3 size-4" />
          <Input
            type="search"
            aria-label={t('conn.search')}
            placeholder={t('conn.search')}
            className="pl-9"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <label className="flex items-center gap-2 text-[13px]">
          {t('conn.group')}
          <NativeSelect value={group} onChange={(e) => setGroup(e.target.value)}>
            <option value="">{t('common.all')}</option>
            {groups.map((g) => (
              <option key={g} value={g}>
                {g}
              </option>
            ))}
          </NativeSelect>
        </label>
        <div
          role="group"
          aria-label={t('conn.protocol')}
          className="bg-muted inline-flex gap-0.5 rounded-lg p-1"
        >
          {(['all', 'tcp', 'udp'] as const).map((p) => (
            <button
              key={p}
              type="button"
              aria-pressed={proto === p}
              onClick={() => setProto(p)}
              className={cn(
                'h-7 rounded-md px-3 text-[13px] font-medium',
                proto === p ? 'bg-card shadow-xs' : 'text-muted-foreground',
              )}
            >
              {t(`conn.protocols.${p}`)}
            </button>
          ))}
        </div>
      </div>
      <ConnTable rows={rows} emptyText={all.length === 0 ? t('conn.empty') : t('conn.noMatch')} />
      <span className="text-muted-foreground text-xs">
        {t('conn.footer', { cap: CONN_EVENT_CAP })}
      </span>
    </>
  )
}
