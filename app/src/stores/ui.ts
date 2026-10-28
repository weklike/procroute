// SPDX-License-Identifier: GPL-3.0-or-later
// 纯前端状态（设计文档 13.5）。服务端数据只放在 TanStack Query 缓存里，不复制到这里（C-CODE-09）。
// 订阅时必须用 selector，例如 `useUiStore((s) => s.theme)`。
import { create } from 'zustand'
import { createJSONStorage, persist } from 'zustand/middleware'

export type Theme = 'system' | 'light' | 'dark'

type UiState = {
  theme: Theme
  /** 方案页里当前选中、正在编辑的方案。 */
  selectedProfileId: string | null
  setTheme: (theme: Theme) => void
  selectProfile: (id: string | null) => void
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      theme: 'system',
      selectedProfileId: null,
      setTheme: (theme) => set({ theme }),
      selectProfile: (selectedProfileId) => set({ selectedProfileId }),
    }),
    {
      name: 'procroute-ui',
      // 只记住外观；选中项每次启动重新确定
      partialize: (s) => ({ theme: s.theme }),
      storage: createJSONStorage(() => localStorage),
    },
  ),
)
