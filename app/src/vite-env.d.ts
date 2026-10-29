// SPDX-License-Identifier: GPL-3.0-or-later
/// <reference types="vite/client" />

/** 构建时由 vite.config.ts 注入的应用版本号。 */
declare const __APP_VERSION__: string

interface ImportMetaEnv {
  /** 开发构建中设为 `1`：在 Tauri 外壳里也使用内存模拟服务（见 src/api/client.ts）。 */
  readonly VITE_IPC_MOCK?: string
}
