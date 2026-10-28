// SPDX-License-Identifier: GPL-3.0-or-later
import { Plus } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import type { ProfileSummary } from '@/api/generated'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

type Props = {
  profiles: ProfileSummary[]
  selectedId: string | null
  onSelect: (id: string) => void
  onCreate: () => void
}

/** 方案列表：选中项进入右侧编辑器。方案名等按纯文本渲染（C-SEC-10）。 */
export default function ProfileList({ profiles, selectedId, onSelect, onCreate }: Props) {
  const { t } = useTranslation()
  return (
    <section aria-labelledby="profiles-title" className="flex w-64 shrink-0 flex-col gap-2">
      <div className="flex items-center justify-between">
        <h2 id="profiles-title" className="text-[15px] font-semibold">
          {t('profile.listTitle')}
        </h2>
        <Button
          size="icon-sm"
          variant="outline"
          aria-label={t('profile.create')}
          onClick={onCreate}
        >
          <Plus aria-hidden="true" />
        </Button>
      </div>
      {profiles.length === 0 ? (
        <p className="text-muted-foreground text-sm">{t('profile.empty')}</p>
      ) : null}
      {profiles.map((p) => (
        <button
          key={p.id}
          type="button"
          aria-current={p.id === selectedId ? 'true' : undefined}
          onClick={() => onSelect(p.id)}
          className={cn(
            'flex flex-col items-start gap-0.5 rounded-lg border px-3 py-2.5 text-left',
            p.id === selectedId ? 'bg-card border-ring' : 'hover:bg-card border-transparent',
          )}
        >
          <span className="flex items-center gap-2 font-medium">
            {p.name}
            {p.active ? (
              <Badge className="bg-brand-muted text-brand">{t('profile.active')}</Badge>
            ) : null}
          </span>
          <span className="text-muted-foreground text-xs">
            {t('profile.meta', { mode: t(`profile.modes.${p.mode}`), count: p.group_count })}
          </span>
        </button>
      ))}
    </section>
  )
}
