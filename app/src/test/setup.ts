// SPDX-License-Identifier: GPL-3.0-or-later
import '@testing-library/jest-dom/vitest'

import { cleanup } from '@testing-library/react'
import { afterEach, beforeAll } from 'vitest'

import i18n from '@/i18n'

beforeAll(async () => {
  // 测试按默认语言（zh-CN）断言，不受 jsdom 的 navigator.language 影响
  await i18n.changeLanguage('zh-CN')
})

afterEach(() => {
  cleanup()
})
