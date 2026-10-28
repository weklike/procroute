// SPDX-License-Identifier: GPL-3.0-or-later
// 实时事件订阅 hook（T-042，C-CODE-10）。
//
// 连接与日志事件每秒可能上千条：事件先进本地缓冲，每个动画帧最多触发一次渲染，
// 列表只保留最近 cap 条。组件卸载（包括严格模式下的模拟卸载）时取消订阅。
import type { UnlistenFn } from '@tauri-apps/api/event'
import { useEffect, useState } from 'react'

import { subscribe } from '@/api/client'
import type { IpcChannel, IpcEvent } from '@/api/generated'

export const DEFAULT_CAP = 2000

export function useIpcSubscription<E extends IpcChannel>(
  channel: E,
  cap: number = DEFAULT_CAP,
): IpcEvent[E][] {
  const [items, setItems] = useState<IpcEvent[E][]>([])

  useEffect(() => {
    let disposed = false
    let frame: number | null = null
    let pending: IpcEvent[E][] = []
    let unlisten: UnlistenFn | null = null

    const flush = () => {
      frame = null
      if (disposed || pending.length === 0) return
      // 先把缓冲取出来再交给 setState：更新函数必须是纯函数，
      // 严格模式下 React 会调用它两次。
      const batch = pending
      pending = []
      setItems((prev) => appendCapped(prev, batch, cap))
    }

    subscribe(channel, (payload) => {
      if (disposed) return
      pending.push(payload)
      frame ??= requestAnimationFrame(flush)
    }).then(
      (fn) => {
        // 订阅建立前组件就卸载了：立刻取消
        if (disposed) fn()
        else unlisten = fn
      },
      () => {
        // 订阅失败时保持空列表；服务状态由 session.status 单独展示
      },
    )

    return () => {
      disposed = true
      if (frame !== null) cancelAnimationFrame(frame)
      unlisten?.()
    }
  }, [channel, cap])

  return items
}

/** 追加后只保留最后 cap 条。 */
export function appendCapped<T>(prev: readonly T[], batch: readonly T[], cap: number): T[] {
  const merged = prev.concat(batch)
  return merged.length > cap ? merged.slice(merged.length - cap) : merged
}
