// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from 'vitest'

const invoke = vi.fn()
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...a: unknown[]) => invoke(...a),
  isTauri: () => true,
}))

const { exportDiagnostics, DiagSaveError } = await import('./shell')

beforeEach(() => {
  invoke.mockReset()
})

describe('exportDiagnostics', () => {
  it('returns the saved path', async () => {
    invoke.mockResolvedValue(String.raw`C:\Downloads\procroute-diag.json`)
    await expect(exportDiagnostics()).resolves.toBe(String.raw`C:\Downloads\procroute-diag.json`)
    expect(invoke).toHaveBeenCalledWith('diag_export')
  })

  it('turns save failures into DiagSaveError', async () => {
    invoke.mockRejectedValue({ kind: 'save', message: 'cannot save the report: disk full' })
    const e: unknown = await exportDiagnostics().catch((x: unknown) => x)
    expect(e).toBeInstanceOf(DiagSaveError)
    expect(e).toMatchObject({ message: 'cannot save the report: disk full' })
  })

  it('unwraps service failures into IpcError', async () => {
    invoke.mockRejectedValue({
      kind: 'service',
      error: { code: 'internal.error', message: 'boom' },
    })
    await expect(exportDiagnostics()).rejects.toMatchObject({
      name: 'IpcError',
      code: 'internal.error',
    })
    invoke.mockRejectedValue({ kind: 'service', error: 'pipe closed' })
    await expect(exportDiagnostics()).rejects.toMatchObject({
      name: 'IpcError',
      code: 'ipc.transport',
    })
  })

  it('treats anything else as a transport failure', async () => {
    invoke.mockRejectedValue('command diag_export not allowed')
    await expect(exportDiagnostics()).rejects.toMatchObject({ code: 'ipc.transport' })
  })
})
