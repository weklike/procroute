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
  /** 节点测速地址，由用户填写；软件不内置任何地址（C-SEC-08、C-SEC-09）。空串表示未设置。 */
  latencyTestUrl: string
  setTheme: (theme: Theme) => void
  selectProfile: (id: string | null) => void
  setLatencyTestUrl: (url: string) => void
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      theme: 'system',
      selectedProfileId: null,
      latencyTestUrl: '',
      setTheme: (theme) => set({ theme }),
      selectProfile: (selectedProfileId) => set({ selectedProfileId }),
      setLatencyTestUrl: (latencyTestUrl) => set({ latencyTestUrl }),
    }),
    {
      name: 'procroute-ui',
      // 只记住偏好；选中项每次启动重新确定
      partialize: (s) => ({ theme: s.theme, latencyTestUrl: s.latencyTestUrl }),
      storage: createJSONStorage(() => localStorage),
    },
  ),
)
