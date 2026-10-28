// SPDX-License-Identifier: GPL-3.0-or-later
// 源自 shadcn/ui new-york-v4 的 separator（MIT，Copyright (c) 2023 shadcn），见 NOTICE。
// 改动：只调整了导入路径。
'use client'

import * as React from 'react'
import { cn } from '@/lib/utils'
import { Separator as SeparatorPrimitive } from 'radix-ui'

function Separator({
  className,
  orientation = 'horizontal',
  decorative = true,
  ...props
}: React.ComponentProps<typeof SeparatorPrimitive.Root>) {
  return (
    <SeparatorPrimitive.Root
      data-slot="separator"
      decorative={decorative}
      orientation={orientation}
      className={cn(
        'shrink-0 bg-border data-[orientation=horizontal]:h-px data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-px',
        className,
      )}
      {...props}
    />
  )
}

export { Separator }
