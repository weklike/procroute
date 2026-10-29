// SPDX-License-Identifier: GPL-3.0-or-later
import { describe, expect, it } from 'vitest'

import type { ProfileSummary, SessionStatus } from '@/api/generated'
import { TRAY_QUIT, TRAY_SHOW, type TrayEntry } from '@/api/shell'
import i18n from '@/i18n'

import { MAX_TRAY_PROFILES, planTrayAction, TRAY_START, TRAY_STOP, trayModel } from './tray'

const t = i18n.getFixedT('zh-CN')

const profile = (id: string, name: string): ProfileSummary => ({
  id,
  name,
  mode: 'tun',
  group_count: 1,
  active: false,
})
const P1 = profile('p1', '游戏加速')
const P2 = profile('p2', '浏览器')

const STOPPED: SessionStatus = {
  state: 'stopped',
  profile_id: null,
  profile_name: null,
  mode: null,
  components: { service: 'active', driver: 'inactive', kernel: 'inactive' },
  blocked_reason: null,
}
const RUNNING: SessionStatus = {
  ...STOPPED,
  state: 'running',
  profile_id: 'p1',
  profile_name: '游戏加速',
  mode: 'tun',
  components: { service: 'active', driver: 'inactive', kernel: 'active' },
}

function find(items: TrayEntry[], id: string): TrayEntry | undefined {
  for (const item of items) {
    if ('id' in item && item.id === id) return item
    if (item.kind === 'submenu') {
      const nested = find(item.items, id)
      if (nested) return nested
    }
  }
  return undefined
}

describe('trayModel', () => {
  it('offers to start the target profile when stopped', () => {
    const m = trayModel(t, STOPPED, [P1, P2], P2)
    expect(m.tooltip).toBe('ProcRoute：未启动会话')
    expect(find(m.items, TRAY_START)).toMatchObject({ label: '启动会话（浏览器）', enabled: true })
    expect(find(m.items, TRAY_STOP)).toBeUndefined()
    expect(find(m.items, 'profile:p1')).toMatchObject({ kind: 'check', checked: false })
    expect(m.items[0]).toMatchObject({ id: TRAY_SHOW })
    expect(m.items.at(-1)).toMatchObject({ id: TRAY_QUIT, label: '退出 ProcRoute' })
  })

  it('offers to stop and checks the running profile', () => {
    const m = trayModel(t, RUNNING, [P1, P2], P2)
    expect(m.tooltip).toBe('ProcRoute：游戏加速')
    expect(find(m.items, TRAY_STOP)).toMatchObject({ label: '停止会话', enabled: true })
    expect(find(m.items, 'profile:p1')).toMatchObject({ checked: true })
    expect(find(m.items, 'profile:p2')).toMatchObject({ checked: false })
  })

  it('disables session entries when the service is unreachable', () => {
    const m = trayModel(t, undefined, [P1], P1)
    expect(m.tooltip).toBe('ProcRoute：无法连接到服务')
    expect(find(m.items, TRAY_START)).toMatchObject({ enabled: false })
    expect(m.items.find((i) => i.kind === 'submenu')).toMatchObject({ enabled: false })
  })

  it('caps the profile list and clips long names', () => {
    const many = Array.from({ length: MAX_TRAY_PROFILES + 5 }, (_, i) =>
      profile(`p${i}`, '名'.repeat(80)),
    )
    const m = trayModel(t, STOPPED, many, many[0])
    const sub = m.items.find((i) => i.kind === 'submenu')
    expect(sub?.kind === 'submenu' && sub.items).toHaveLength(MAX_TRAY_PROFILES)
    const first = find(m.items, 'profile:p0')
    expect(first && 'label' in first && [...first.label].length).toBe(41)
  })

  it('needs a profile to start', () => {
    const m = trayModel(t, STOPPED, [], undefined)
    expect(find(m.items, TRAY_START)).toMatchObject({ label: '启动会话', enabled: false })
  })
})

describe('planTrayAction', () => {
  it('maps menu ids to session operations', () => {
    expect(planTrayAction(TRAY_START, STOPPED, P1)).toEqual({ kind: 'start', profileId: 'p1' })
    expect(planTrayAction(TRAY_STOP, RUNNING, P1)).toEqual({ kind: 'stop' })
    expect(planTrayAction('profile:p2', STOPPED, P1)).toEqual({ kind: 'start', profileId: 'p2' })
    expect(planTrayAction('profile:p2', RUNNING, P1)).toEqual({ kind: 'switch', profileId: 'p2' })
  })

  it('ignores stale or meaningless clicks', () => {
    expect(planTrayAction(TRAY_START, RUNNING, P1)).toBeNull()
    expect(planTrayAction(TRAY_STOP, STOPPED, P1)).toBeNull()
    expect(planTrayAction('profile:p1', RUNNING, P1)).toBeNull()
    expect(planTrayAction('profile:', STOPPED, P1)).toBeNull()
    expect(planTrayAction(TRAY_START, STOPPED, undefined)).toBeNull()
    expect(planTrayAction(TRAY_START, undefined, P1)).toBeNull()
    expect(planTrayAction('something.else', STOPPED, P1)).toBeNull()
  })
})
