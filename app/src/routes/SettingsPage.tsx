// SPDX-License-Identifier: GPL-3.0-or-later
import { useTranslation } from 'react-i18next'

import PageHeader from '@/components/PageHeader'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import LatencyUrlForm from '@/features/node/LatencyUrlForm'
import DriverPanel from '@/features/session/DriverPanel'
import { useAutostart } from '@/features/shell/api'
import { SUPPORTED_LANGUAGES, type Language } from '@/i18n'
import { useUiStore, type Theme } from '@/stores/ui'

const LANGUAGE_NAMES: Record<Language, string> = { 'zh-CN': '简体中文', 'en-US': 'English' }
const THEMES: Theme[] = ['system', 'light', 'dark']

export default function SettingsPage() {
  const { t, i18n } = useTranslation()
  const theme = useUiStore((s) => s.theme)
  const setTheme = useUiStore((s) => s.setTheme)
  const autostart = useAutostart()
  const language = (SUPPORTED_LANGUAGES as readonly string[]).includes(i18n.language)
    ? i18n.language
    : 'zh-CN'

  return (
    <>
      <PageHeader title={t('pages.settings.title')} hint={t('pages.settings.hint')} />
      <section
        aria-labelledby="settings-general"
        className="bg-card flex max-w-2xl flex-col gap-4 rounded-xl border p-5"
      >
        <h2 id="settings-general" className="text-[15px] font-semibold">
          {t('settings.general')}
        </h2>
        <div className="flex items-center justify-between gap-4">
          <Label htmlFor="settings-language">{t('settings.language')}</Label>
          <Select value={language} onValueChange={(v) => void i18n.changeLanguage(v)}>
            <SelectTrigger id="settings-language" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {SUPPORTED_LANGUAGES.map((l) => (
                <SelectItem key={l} value={l}>
                  {LANGUAGE_NAMES[l]}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="flex items-center justify-between gap-4">
          <Label htmlFor="settings-theme">{t('settings.theme')}</Label>
          <Select value={theme} onValueChange={(v) => setTheme(v as Theme)}>
            <SelectTrigger id="settings-theme" className="w-44">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {THEMES.map((th) => (
                <SelectItem key={th} value={th}>
                  {t(`settings.themes.${th}`)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        {autostart.available ? (
          <div className="flex items-center justify-between gap-4">
            <div className="flex flex-col gap-1">
              <Label htmlFor="settings-autostart">{t('settings.autostart')}</Label>
              <p className="text-muted-foreground text-[13px]">{t('settings.autostartHint')}</p>
            </div>
            <Switch
              id="settings-autostart"
              checked={autostart.query.data ?? false}
              disabled={autostart.query.isPending || autostart.mutation.isPending}
              onCheckedChange={(enabled) => autostart.mutation.mutate(enabled)}
            />
          </div>
        ) : null}
      </section>
      <section
        aria-labelledby="settings-latency"
        className="bg-card flex max-w-2xl flex-col gap-4 rounded-xl border p-5"
      >
        <h2 id="settings-latency" className="text-[15px] font-semibold">
          {t('settings.latencyTitle')}
        </h2>
        <LatencyUrlForm />
      </section>
      <DriverPanel />
    </>
  )
}
