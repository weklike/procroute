// SPDX-License-Identifier: GPL-3.0-or-later
// 「添加进程」对话框（设计稿 AddProcess）：从运行中的进程挑选，或手动输入规则。
import { useMemo, useState } from 'react'
import { useTranslation } from 'react-i18next'

import type { MatchRule, MatchType, ProcessInfo } from '@/api/generated'
import NativeSelect from '@/components/NativeSelect'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { cn } from '@/lib/utils'

import { useProcesses } from './api'
import { makeRule, MATCH_TYPES, parentDir } from './form'

type By = 'name' | 'path' | 'dir'
type Tab = 'running' | 'manual'

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  hint?: string
  onAdd: (rules: MatchRule[]) => void
}

function toRule(p: ProcessInfo, by: By): MatchRule {
  if (by === 'name') return makeRule('name', p.name)
  if (by === 'path') return makeRule('path', p.path)
  return makeRule('dir', parentDir(p.path))
}

export default function AddRuleDialog({ open, onOpenChange, title, hint, onAdd }: Props) {
  const { t } = useTranslation()
  const [tab, setTab] = useState<Tab>('running')
  const [query, setQuery] = useState('')
  const [picked, setPicked] = useState<ReadonlySet<number>>(new Set())
  const [by, setBy] = useState<By>('name')
  const [manualType, setManualType] = useState<MatchType>('glob')
  const [manualValue, setManualValue] = useState('')
  const processes = useProcesses(open)

  const shown = useMemo(() => {
    const q = query.trim().toLowerCase()
    const all = processes.data?.processes ?? []
    return q === ''
      ? all
      : all.filter((p) => p.name.toLowerCase().includes(q) || p.path.toLowerCase().includes(q))
  }, [processes.data, query])

  const close = (next: boolean) => {
    onOpenChange(next)
    if (!next) {
      setPicked(new Set())
      setQuery('')
      setManualValue('')
    }
  }

  const toggle = (pid: number) => {
    const next = new Set(picked)
    if (!next.delete(pid)) next.add(pid)
    setPicked(next)
  }

  const add = () => {
    const rules =
      tab === 'running'
        ? (processes.data?.processes ?? [])
            .filter((p) => picked.has(p.pid))
            .map((p) => toRule(p, by))
        : [makeRule(manualType, manualValue.trim())]
    // 同名进程只加一次
    const unique = rules.filter(
      (r, i) => rules.findIndex((x) => x.type === r.type && x.value === r.value) === i,
    )
    onAdd(unique)
    close(false)
  }

  const canAdd = tab === 'running' ? picked.size > 0 : manualValue.trim() !== ''

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          {hint ? <DialogDescription>{hint}</DialogDescription> : null}
        </DialogHeader>
        <div
          role="tablist"
          aria-label={title}
          className="bg-muted inline-flex gap-0.5 self-start rounded-lg p-1"
        >
          {(['running', 'manual'] as const).map((id) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={tab === id}
              onClick={() => setTab(id)}
              className={cn(
                'h-8 rounded-md px-3 text-[13px] font-medium',
                tab === id ? 'bg-card shadow-xs' : 'text-muted-foreground',
              )}
            >
              {t(`profile.add.tabs.${id}`)}
            </button>
          ))}
        </div>
        {tab === 'running' ? (
          <RunningTab
            processes={shown}
            query={query}
            onQuery={setQuery}
            picked={picked}
            onToggle={toggle}
            by={by}
            onBy={setBy}
          />
        ) : (
          <div role="tabpanel" className="grid gap-3 sm:grid-cols-[10rem_1fr]">
            <div className="flex flex-col gap-2">
              <Label htmlFor="rule-type">{t('profile.add.ruleType')}</Label>
              <NativeSelect
                id="rule-type"
                value={manualType}
                onChange={(e) => setManualType(e.target.value as MatchType)}
              >
                {MATCH_TYPES.map((m) => (
                  <option key={m} value={m}>
                    {t(`profile.ruleTypes.${m}`)}
                  </option>
                ))}
              </NativeSelect>
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="rule-value">{t('profile.add.ruleValue')}</Label>
              <Input
                id="rule-value"
                className="font-mono"
                value={manualValue}
                onChange={(e) => setManualValue(e.target.value)}
              />
            </div>
          </div>
        )}
        <DialogFooter className="items-center">
          {tab === 'running' ? (
            <span className="text-muted-foreground mr-auto text-[13px]">
              {t('profile.add.selected', { count: picked.size })}
            </span>
          ) : null}
          <Button variant="outline" onClick={() => close(false)}>
            {t('common.cancel')}
          </Button>
          <Button disabled={!canAdd} onClick={add}>
            {tab === 'running'
              ? t('profile.add.addSelected', { count: picked.size })
              : t('profile.add.addRule')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

type RunningProps = {
  processes: ProcessInfo[]
  query: string
  onQuery: (q: string) => void
  picked: ReadonlySet<number>
  onToggle: (pid: number) => void
  by: By
  onBy: (by: By) => void
}

function RunningTab({ processes, query, onQuery, picked, onToggle, by, onBy }: RunningProps) {
  const { t } = useTranslation()
  return (
    <div role="tabpanel" className="flex flex-col gap-3">
      <Input
        type="search"
        aria-label={t('profile.add.search')}
        placeholder={t('profile.add.search')}
        value={query}
        onChange={(e) => onQuery(e.target.value)}
      />
      <ul className="max-h-72 overflow-y-auto rounded-lg border">
        {processes.length === 0 ? (
          <li className="text-muted-foreground p-3 text-sm">{t('profile.add.noProcesses')}</li>
        ) : null}
        {processes.map((p) => (
          <li key={p.pid} className="border-b last:border-b-0">
            <label className="flex items-center gap-3 px-3 py-2">
              <input
                type="checkbox"
                className="accent-brand size-4"
                checked={p.matched_group !== null || picked.has(p.pid)}
                disabled={p.matched_group !== null}
                onChange={() => onToggle(p.pid)}
              />
              <span className="flex min-w-0 flex-1 flex-col">
                <span className="font-medium">{p.name}</span>
                <span className="text-muted-foreground truncate font-mono text-xs">{p.path}</span>
              </span>
              <span className="text-muted-foreground text-xs">
                {p.matched_group !== null
                  ? t('profile.add.inProfile')
                  : t('profile.add.pid', { pid: p.pid })}
              </span>
            </label>
          </li>
        ))}
      </ul>
      <fieldset className="flex flex-wrap gap-4 text-[13px]">
        <legend className="mb-1 font-medium">{t('profile.add.matchBy')}</legend>
        {(['name', 'path', 'dir'] as const).map((b) => (
          <label key={b} className="flex items-center gap-2">
            <input
              type="radio"
              name="match-by"
              className="accent-brand"
              checked={by === b}
              onChange={() => onBy(b)}
            />
            {t(`profile.add.by${b.charAt(0).toUpperCase()}${b.slice(1)}`)}
          </label>
        ))}
      </fieldset>
    </div>
  )
}
