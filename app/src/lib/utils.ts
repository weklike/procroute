// SPDX-License-Identifier: GPL-3.0-or-later
import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/** 合并 Tailwind 类名，后者覆盖前者（shadcn/ui 约定）。 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
