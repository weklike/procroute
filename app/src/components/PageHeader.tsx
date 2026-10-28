// SPDX-License-Identifier: GPL-3.0-or-later
import type { ReactNode } from 'react'

type Props = {
  title: string
  hint?: string
  /** 标题右侧的操作按钮。 */
  actions?: ReactNode
}

/** 页面标题行：标题 + 一句说明 + 右侧操作。 */
export default function PageHeader({ title, hint, actions }: Props) {
  return (
    <div className="flex flex-wrap items-end gap-3">
      <div className="mr-auto flex flex-col">
        <h1 className="text-xl font-bold tracking-tight">{title}</h1>
        {hint ? <p className="text-muted-foreground text-[13px]">{hint}</p> : null}
      </div>
      {actions}
    </div>
  )
}
