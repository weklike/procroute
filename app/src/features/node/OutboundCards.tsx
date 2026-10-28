// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import type { NodeInfo, OutboundInfo } from '@/api/generated'
import { Badge } from '@/components/ui/badge'

type Props = { outbounds: OutboundInfo[]; nodes: NodeInfo[] }

/** 出站卡片：方案里的进程组按这些标签选择出站。 */
export default function OutboundCards({ outbounds, nodes }: Props) {
  const { t } = useTranslation()
  const nameOf = (id: string | null) => nodes.find((n) => n.id === id)?.name ?? id ?? ''
  return (
    <ul className="grid grid-cols-[repeat(auto-fit,minmax(13rem,1fr))] gap-3">
      {outbounds.map((o) => (
        <li key={o.tag} className="bg-card flex flex-col gap-1.5 rounded-xl border p-4">
          <div className="flex items-center justify-between gap-2">
            <span className="font-mono font-medium">{o.tag}</span>
            <Badge variant="secondary">{t(`node.kinds.${o.kind}`)}</Badge>
          </div>
          <span className="text-[13px]">{t('node.members', { count: o.members.length })}</span>
          {o.current ? (
            <span className="text-muted-foreground text-[13px]">
              {t('node.current', { name: nameOf(o.current) })}
            </span>
          ) : null}
        </li>
      ))}
    </ul>
  )
}
