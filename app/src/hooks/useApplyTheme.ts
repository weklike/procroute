// SPDX-License-Identifier: GPL-3.0-or-later
import { useEffect } from 'react'

import { useUiStore } from '@/stores/ui'

const DARK_QUERY = '(prefers-color-scheme: dark)'

/** 把外观设置同步到 `<html class="dark">`；「跟随系统」时监听系统切换。 */
export function useApplyTheme(): void {
  const theme = useUiStore((s) => s.theme)

  useEffect(() => {
    const media = typeof window.matchMedia === 'function' ? window.matchMedia(DARK_QUERY) : null
    const apply = () => {
      const dark = theme === 'dark' || (theme === 'system' && (media?.matches ?? false))
      document.documentElement.classList.toggle('dark', dark)
    }
    apply()
    if (theme !== 'system' || !media) return
    media.addEventListener('change', apply)
    return () => {
      media.removeEventListener('change', apply)
    }
  }, [theme])
}
