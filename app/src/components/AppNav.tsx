// SPDX-License-Identifier: GPL-3.0-or-later
import { Link } from '@tanstack/react-router'
import { Activity, FileText, Layers, Route, Server, SlidersHorizontal } from 'lucide-react'
import { useTranslation } from 'react-i18next'

const ITEMS = [
  { to: '/profiles', key: 'nav.profiles', Icon: Layers },
  { to: '/nodes', key: 'nav.nodes', Icon: Server },
  { to: '/connections', key: 'nav.connections', Icon: Activity },
  { to: '/logs', key: 'nav.logs', Icon: FileText },
  { to: '/settings', key: 'nav.settings', Icon: SlidersHorizontal },
] as const

/** 左侧主导航。 */
export default function AppNav() {
  const { t } = useTranslation()
  return (
    <nav
      aria-label={t('nav.label')}
      className="bg-sidebar flex w-56 shrink-0 flex-col gap-1 border-r px-3 py-4"
    >
      <div className="flex items-center gap-2.5 px-2 pb-4">
        <span className="bg-brand text-brand-foreground flex size-7 items-center justify-center rounded-lg">
          <Route aria-hidden="true" className="size-4" />
        </span>
        <span className="text-[15px] font-bold tracking-tight">{t('app.title')}</span>
      </div>
      {ITEMS.map(({ to, key, Icon }) => (
        <Link
          key={to}
          to={to}
          className="text-muted-foreground hover:bg-background/60 flex h-10 items-center gap-2.5 rounded-lg border border-transparent px-3 font-medium"
          activeProps={{
            className: 'bg-card text-foreground border-border font-semibold',
            'aria-current': 'page',
          }}
        >
          <Icon aria-hidden="true" className="size-[18px]" />
          {t(key)}
        </Link>
      ))}
      <div className="bg-card text-muted-foreground mt-auto rounded-lg border p-3 text-xs">
        {t('nav.version', { version: __APP_VERSION__ })}
      </div>
    </nav>
  )
}
