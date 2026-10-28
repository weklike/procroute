// SPDX-License-Identifier: GPL-3.0-or-later
import { useEffect, useState } from 'react'

/** 每隔 `intervalMs` 更新一次的当前时间，供「时长」等显示使用（渲染函数里不能直接读时钟）。 */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs])
  return now
}
