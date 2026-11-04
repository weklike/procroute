// SPDX-License-Identifier: GPL-3.0-or-later
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { Dialog, DialogContent, DialogTitle } from './dialog'

describe('DialogContent', () => {
  // jsdom 没有布局，量不出溢出，这里只能确认这两处改动还在（重新生成 shadcn 组件时最容易丢）。
  // 没有 grid-cols-1 时，长路径会把网格列撑得比对话框还宽，取消和添加按钮被推到框外。
  it('keeps its content inside the dialog', () => {
    render(
      <Dialog open>
        <DialogContent aria-describedby={undefined}>
          <DialogTitle>title</DialogTitle>
        </DialogContent>
      </Dialog>,
    )
    const dialog = screen.getByRole('dialog', { name: 'title' })
    expect(dialog).toHaveClass('grid-cols-1')
    expect(dialog).toHaveClass('max-h-[calc(100dvh-2rem)]', 'overflow-y-auto')
  })
})
