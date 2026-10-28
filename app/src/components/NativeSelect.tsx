// SPDX-License-Identifier: GPL-3.0-or-later
import type { ComponentProps } from 'react'

import { cn } from '@/lib/utils'

/** 与 shadcn Input 同样外观的原生下拉框：表单里可直接 register，可访问性由浏览器保证。 */
export default function NativeSelect({ className, ...props }: ComponentProps<'select'>) {
  return (
    <select
      className={cn(
        'border-input bg-background focus-visible:border-ring focus-visible:ring-ring/50 aria-invalid:border-destructive h-9 rounded-md border px-2 text-sm shadow-xs outline-none focus-visible:ring-[3px] disabled:opacity-50',
        className,
      )}
      {...props}
    />
  )
}
