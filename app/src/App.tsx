// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

/** 占位外壳；路由与各页面见 T-060。 */
export default function App() {
  const { t } = useTranslation()
  return (
    <main className="flex min-h-screen flex-col items-center justify-center gap-2 p-6">
      <h1 className="text-2xl font-bold tracking-tight">{t('app.title')}</h1>
      <p className="text-muted-foreground">{t('app.tagline')}</p>
    </main>
  )
}
