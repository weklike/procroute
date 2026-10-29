// SPDX-License-Identifier: GPL-3.0-or-later
// 诊断包导出：显示保存路径；存盘失败与服务失败分别说明；不在桌面外壳里时不显示入口。
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { renderWithQuery } from '@/test/render'

const shell = vi.hoisted(() => ({ available: true }))

vi.mock('@/api/shell', async (orig) => ({
  ...(await orig<typeof import('@/api/shell')>()),
  inShell: () => shell.available,
  exportDiagnostics: vi.fn(),
}))

const { exportDiagnostics, DiagSaveError } = await import('@/api/shell')
const { IpcError } = await import('@/api/client')
const { default: DiagnosticsCard } = await import('./DiagnosticsCard')

const PATH = String.raw`C:\Users\me\Downloads\procroute-diag-20261029-120000.json`

beforeEach(() => {
  shell.available = true
  vi.mocked(exportDiagnostics).mockReset()
})

describe('DiagnosticsCard', () => {
  it('exports and shows where the file was saved', async () => {
    let finish: (path: string) => void = () => {}
    vi.mocked(exportDiagnostics).mockReturnValue(
      new Promise((resolve) => {
        finish = resolve
      }),
    )
    renderWithQuery(<DiagnosticsCard />)
    expect(screen.getByRole('heading', { name: '诊断包' })).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: '导出诊断包' }))
    expect(screen.getByRole('button', { name: '正在导出…' })).toBeDisabled()
    finish(PATH)

    const status = await screen.findByRole('status')
    expect(status).toHaveTextContent('已保存到「下载」文件夹：')
    expect(status).toHaveTextContent(PATH)
    expect(screen.getByRole('button', { name: '导出诊断包' })).toBeEnabled()
    expect(exportDiagnostics).toHaveBeenCalledTimes(1)
  })

  it('says when the report could not be saved', async () => {
    vi.mocked(exportDiagnostics).mockRejectedValue(new DiagSaveError('disk full'))
    renderWithQuery(<DiagnosticsCard />)
    await userEvent.click(screen.getByRole('button', { name: '导出诊断包' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      '诊断包已生成，但无法保存到「下载」文件夹',
    )
    expect(screen.queryByText(/disk full/)).not.toBeInTheDocument()
    expect(screen.queryByRole('status')).not.toBeInTheDocument()
  })

  it('translates service failures by error code', async () => {
    vi.mocked(exportDiagnostics).mockRejectedValue(new IpcError('ipc.transport', 'pipe closed'))
    renderWithQuery(<DiagnosticsCard />)
    await userEvent.click(screen.getByRole('button', { name: '导出诊断包' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('无法连接到 ProcRoute 服务')
  })

  it('is hidden outside the desktop shell', () => {
    shell.available = false
    const { container } = renderWithQuery(<DiagnosticsCard />)
    expect(container).toBeEmptyDOMElement()
  })
})
