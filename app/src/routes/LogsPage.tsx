// SPDX-License-Identifier: GPL-3.0-or-later
import { Search } from 'lucide-react'
import { useDeferredValue, useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import type { LogLevel } from '@/api/generated'
import NativeSelect from '@/components/NativeSelect'
import PageHeader from '@/components/PageHeader'
import { Input } from '@/components/ui/input'
import { LEVELS, levelRank, LOG_CAP, useLogs } from '@/features/log/api'
import LogView from '@/features/log/LogView'
import { formatFields } from '@/features/log/redact'
import { cn } from '@/lib/utils'

type LevelFilter = 'all' | LogLevel

export default function LogsPage() {
  const { t } = useTranslation()
  const logs = useLogs()
  const [level, setLevel] = useState<LevelFilter>('all')
  const [module, setModule] = useState('')
  const [query, setQuery] = useState('')
  const q = useDeferredValue(query.trim().toLowerCase())

  const modules = useMemo(() => [...new Set(logs.map((l) => l.module))].sort(), [logs])
  const shown = useMemo(() => {
    const min = level === 'all' ? 0 : levelRank(level)
    return logs.filter(
      (l) =>
        levelRank(l.level) >= min &&
        (module === '' || l.module === module) &&
        (q === '' ||
          l.message.toLowerCase().includes(q) ||
          formatFields(l.fields).toLowerCase().includes(q)),
    )
  }, [logs, level, module, q])

  return (
    <>
      <PageHeader title={t('pages.logs.title')} hint={t('pages.logs.hint')} />
      <div className="flex flex-wrap items-center gap-3">
        <div
          role="group"
          aria-label={t('log.levelFilter')}
          className="bg-muted inline-flex gap-0.5 rounded-lg p-1"
        >
          {(['all', ...LEVELS] as const).map((l) => (
            <button
              key={l}
              type="button"
              aria-pressed={level === l}
              onClick={() => setLevel(l)}
              className={cn(
                'h-7 rounded-md px-3 text-[13px] font-medium',
                level === l ? 'bg-card shadow-xs' : 'text-muted-foreground',
              )}
            >
              {t(`log.levels.${l}`)}
            </button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-[13px]">
          {t('log.module')}
          <NativeSelect value={module} onChange={(e) => setModule(e.target.value)}>
            <option value="">{t('common.all')}</option>
            {modules.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </NativeSelect>
        </label>
        <div className="relative flex flex-[1_1_15rem] items-center">
          <Search aria-hidden="true" className="text-muted-foreground absolute left-3 size-4" />
          <Input
            type="search"
            aria-label={t('log.search')}
            placeholder={t('log.search')}
            className="pl-9"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
      </div>
      <LogView entries={shown} emptyText={logs.length === 0 ? t('log.empty') : t('log.noMatch')} />
      <span className="text-muted-foreground text-xs">{t('log.footer', { cap: LOG_CAP })}</span>
    </>
  )
}
