// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import type { SubscriptionInfo } from '@/api/generated'

type Props = { subscriptions: SubscriptionInfo[] }

/** 订阅列表。地址只显示 `scheme://host`，完整地址可能含令牌，服务从不返回（C-SEC-04）。 */
export default function SubscriptionList({ subscriptions }: Props) {
  const { t, i18n } = useTranslation()
  if (subscriptions.length === 0) {
    return <p className="text-muted-foreground text-sm">{t('node.noSubscriptions')}</p>
  }
  const time = (ms: number) =>
    new Intl.DateTimeFormat(i18n.language, { dateStyle: 'short', timeStyle: 'short' }).format(ms)
  return (
    <ul className="flex flex-col gap-3">
      {subscriptions.map((s) => (
        <li
          key={s.id}
          className="bg-card flex flex-wrap items-center gap-4 rounded-xl border p-4 text-[13px]"
        >
          <div className="flex min-w-0 flex-[1_1_16rem] flex-col">
            <span className="text-sm font-semibold">{s.name}</span>
            <span className="text-muted-foreground truncate font-mono text-[12.5px]">
              {s.url_display}
            </span>
          </div>
          <span>{t('node.nodeCount', { count: s.node_count })}</span>
          <span className="text-muted-foreground">
            {s.updated_at_ms === null
              ? t('node.neverUpdated')
              : t('node.updatedAt', { time: time(s.updated_at_ms) })}
          </span>
        </li>
      ))}
    </ul>
  )
}
