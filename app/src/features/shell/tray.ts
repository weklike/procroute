// SPDX-License-Identifier: GPL-3.0-or-later
// 托盘菜单（T-113）：由会话状态、方案列表与 i18n 文案生成菜单模型，外壳只负责显示（C-UI-04）。
// 纯函数，便于测试；点击后的动作也在这里决定，实际调用走会话领域已有的 mutation。
import type { TFunction } from 'i18next'

import type { ProfileSummary, SessionStatus } from '@/api/generated'
import { TRAY_QUIT, TRAY_SHOW, type TrayEntry, type TrayModel } from '@/api/shell'

export const TRAY_START = 'session.start'
export const TRAY_STOP = 'session.stop'
export const TRAY_PROFILE_PREFIX = 'profile:'

/** 子菜单里最多列出的方案数（外壳限制整个菜单不超过 64 项）。 */
export const MAX_TRAY_PROFILES = 32
/** 菜单里方案名的最大字符数，超出截断。 */
const MAX_NAME_CHARS = 40

function clip(name: string): string {
  const chars = [...name]
  return chars.length > MAX_NAME_CHARS ? `${chars.slice(0, MAX_NAME_CHARS).join('')}…` : name
}

function isRunning(status: SessionStatus | undefined): status is SessionStatus {
  return status !== undefined && status.state !== 'stopped'
}

/**
 * 生成托盘菜单。`status` 为空表示连不上服务：会话相关的项全部禁用。
 * `target` 是会话条上「启动」会使用的方案。
 */
export function trayModel(
  t: TFunction,
  status: SessionStatus | undefined,
  profiles: readonly ProfileSummary[],
  target: ProfileSummary | undefined,
): TrayModel {
  const running = isRunning(status)
  const tooltip =
    status === undefined
      ? t('tray.tooltipOffline')
      : running
        ? t('tray.tooltipRunning', { name: clip(status.profile_name ?? '') })
        : t('tray.tooltipIdle')
  const session: TrayEntry = running
    ? { kind: 'action', id: TRAY_STOP, label: t('tray.stop'), enabled: true }
    : {
        kind: 'action',
        id: TRAY_START,
        label: target ? t('tray.start', { name: clip(target.name) }) : t('tray.startNoProfile'),
        enabled: status !== undefined && target !== undefined,
      }
  const choices: TrayEntry[] = profiles.slice(0, MAX_TRAY_PROFILES).map((p) => ({
    kind: 'check',
    id: `${TRAY_PROFILE_PREFIX}${p.id}`,
    label: clip(p.name),
    checked: running && status.profile_id === p.id,
    enabled: true,
  }))
  return {
    tooltip,
    items: [
      { kind: 'action', id: TRAY_SHOW, label: t('tray.show'), enabled: true },
      { kind: 'separator' },
      session,
      {
        kind: 'submenu',
        label: t('tray.profiles'),
        enabled: status !== undefined && choices.length > 0,
        items: choices,
      },
      { kind: 'separator' },
      { kind: 'action', id: TRAY_QUIT, label: t('tray.quit'), enabled: true },
    ],
  }
}

/** 托盘点击之后要做的事。 */
export type TrayPlan =
  | { kind: 'start'; profileId: string }
  | { kind: 'stop' }
  /** 先停止当前会话，再用另一个方案启动。 */
  | { kind: 'switch'; profileId: string }

export function planTrayAction(
  id: string,
  status: SessionStatus | undefined,
  target: ProfileSummary | undefined,
): TrayPlan | null {
  if (status === undefined) return null
  if (id === TRAY_STOP) return isRunning(status) ? { kind: 'stop' } : null
  if (id === TRAY_START) {
    return !isRunning(status) && target ? { kind: 'start', profileId: target.id } : null
  }
  if (id.startsWith(TRAY_PROFILE_PREFIX)) {
    const profileId = id.slice(TRAY_PROFILE_PREFIX.length)
    if (!profileId) return null
    if (!isRunning(status)) return { kind: 'start', profileId }
    return status.profile_id === profileId ? null : { kind: 'switch', profileId }
  }
  return null
}
