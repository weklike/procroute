// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import type { ComponentState, ComponentStatus } from '@/api/generated'
import { cn } from '@/lib/utils'

const DOT: Record<ComponentState, string> = {
  active: 'bg-brand',
  inactive: 'bg-muted-foreground',
  restarting: 'bg-warning',
  failed: 'bg-destructive',
}

/** 服务、驱动、内核三者的状态，如实显示（C-UI-02）。 */
export default function ComponentChips({ status }: { status: ComponentStatus }) {
  const { t } = useTranslation()
  const items = (['service', 'driver', 'kernel'] as const).map((c) => ({ c, state: status[c] }))
  return (
    <ul aria-label={t('session.componentsLabel')} className="flex flex-wrap gap-2">
      {items.map(({ c, state }) => (
        <li
          key={c}
          className="flex h-8 items-center gap-1.5 rounded-full border px-2.5 text-[13px]"
        >
          <span aria-hidden="true" className={cn('size-2 rounded-full', DOT[state])} />
          <span className="text-muted-foreground">{t(`session.components.${c}`)}</span>
          <span
            className={cn('font-semibold', state === 'failed' ? 'text-destructive' : undefined)}
          >
            {t(`session.states.${c}.${state}`)}
          </span>
        </li>
      ))}
    </ul>
  )
}
