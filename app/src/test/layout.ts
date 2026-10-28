// SPDX-License-Identifier: GPL-3.0-or-later
// jsdom 不做布局，元素尺寸恒为 0，虚拟列表因此一行都不渲染。
// 测试虚拟化列表时用它给滚动容器一个可视尺寸。
import { afterEach, beforeEach } from 'vitest'

export function useFakeViewport(height = 600, width = 1000): void {
  const originals = {
    height: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientHeight'),
    width: Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'clientWidth'),
  }
  beforeEach(() => {
    Object.defineProperty(HTMLElement.prototype, 'clientHeight', {
      configurable: true,
      get: () => height,
    })
    Object.defineProperty(HTMLElement.prototype, 'clientWidth', {
      configurable: true,
      get: () => width,
    })
  })
  afterEach(() => {
    if (originals.height)
      Object.defineProperty(HTMLElement.prototype, 'clientHeight', originals.height)
    if (originals.width)
      Object.defineProperty(HTMLElement.prototype, 'clientWidth', originals.width)
  })
}
