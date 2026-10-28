// SPDX-License-Identifier: GPL-3.0-or-later
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

import enUS from './locales/en-US'
import zhCN from './locales/zh-CN'

export const SUPPORTED_LANGUAGES = ['zh-CN', 'en-US'] as const
export type Language = (typeof SUPPORTED_LANGUAGES)[number]

function detect(): Language {
  const nav = typeof navigator === 'undefined' ? '' : navigator.language
  return nav.toLowerCase().startsWith('en') ? 'en-US' : 'zh-CN'
}

void i18n.use(initReactI18next).init({
  resources: {
    'zh-CN': { translation: zhCN },
    'en-US': { translation: enUS },
  },
  lng: detect(),
  fallbackLng: 'zh-CN',
  // React 本身会转义，避免二次转义；外部数据仍按纯文本渲染（C-SEC-10）
  interpolation: { escapeValue: false },
})

export default i18n
