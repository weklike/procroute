// SPDX-License-Identifier: GPL-3.0-or-later
// 手写的桌面外壳命令薄封装：托盘、开机自启、与服务的连接状态。
//
// 这些不是服务的 IPC 方法（那些只走 ./client.ts），由 src-tauri/src/shell.rs 实现，类型也只在这里定义。
// 只有 features/<领域>/api.ts 可以导入本文件；组件禁止直接调用（C-CODE-09，lint 强制）。
// 不在 Tauri 里运行时（浏览器开发、单元测试）一律为空操作。
import { invoke, isTauri } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

/** 与服务的连接建立或断开，负载为布尔值。 */
export const CONNECTION_EVENT = 'shell:connection'
/** 托盘菜单项被点击，负载为菜单项 id。 */
export const TRAY_EVENT = 'shell:tray'

/** 外壳自己处理的托盘菜单项：显示主窗口、退出。 */
export const TRAY_SHOW = 'shell.show'
export const TRAY_QUIT = 'shell.quit'

/** 托盘菜单条目；外壳会检查条目数、标签长度与子菜单层数（只允许一层）。 */
export type TrayEntry =
  | { kind: 'action'; id: string; label: string; enabled: boolean }
  | { kind: 'check'; id: string; label: string; checked: boolean; enabled: boolean }
  | { kind: 'separator' }
  | { kind: 'submenu'; label: string; enabled: boolean; items: TrayEntry[] }

export type TrayModel = { tooltip: string; items: TrayEntry[] }

const noop: UnlistenFn = () => {}

/** 是否运行在桌面外壳里。 */
export function inShell(): boolean {
  return isTauri()
}

/** 替换托盘菜单与提示文字。 */
export async function updateTray(model: TrayModel): Promise<void> {
  if (!inShell()) return
  await invoke('tray_update', { model })
}

/** 订阅托盘菜单点击（外壳自己处理的两项除外）。 */
export async function onTrayAction(onAction: (id: string) => void): Promise<UnlistenFn> {
  if (!inShell()) return noop
  return listen<string>(TRAY_EVENT, (e) => {
    onAction(e.payload)
  })
}

/** 订阅与服务的连接变化。 */
export async function onServiceConnection(
  onChange: (connected: boolean) => void,
): Promise<UnlistenFn> {
  if (!inShell()) return noop
  return listen<boolean>(CONNECTION_EVENT, (e) => {
    onChange(e.payload)
  })
}

export async function getAutostart(): Promise<boolean> {
  return invoke<boolean>('autostart_get')
}

/** 返回设置之后的实际状态。 */
export async function setAutostart(enabled: boolean): Promise<boolean> {
  return invoke<boolean>('autostart_set', { enabled })
}
