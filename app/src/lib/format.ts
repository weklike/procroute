// SPDX-License-Identifier: GPL-3.0-or-later
// 数字与时间的显示格式。纯函数，便于测试。

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

/** 字节数 → `1.2 MB`。小于 10 的值保留一位小数。 */
export function formatBytes(n: number): string {
  let value = Math.max(0, n)
  let unit = 0
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024
    unit += 1
  }
  const text = unit === 0 || value >= 10 ? Math.round(value).toString() : value.toFixed(1)
  return `${text} ${UNITS[unit]}`
}

/** 毫秒时长 → `mm:ss`，超过一小时为 `h:mm:ss`。 */
export function formatDuration(ms: number): string {
  const total = Math.max(0, Math.floor(ms / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const pad = (v: number) => v.toString().padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`
}

/** 时间戳 → 本地时间 `HH:mm:ss.SSS`。 */
export function formatClock(ms: number): string {
  const d = new Date(ms)
  const pad = (v: number, w = 2) => v.toString().padStart(w, '0')
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`
}
