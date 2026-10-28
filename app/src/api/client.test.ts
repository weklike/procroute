// SPDX-License-Identifier: GPL-3.0-or-later
import { beforeEach, describe, expect, it, vi } from 'vitest'

const invoke = vi.fn()
const listen = vi.fn()
const tauri = { on: true }
vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...a: unknown[]) => invoke(...a),
  isTauri: () => tauri.on,
}))
vi.mock('@tauri-apps/api/event', () => ({ listen: (...a: unknown[]) => listen(...a) }))

const { call, subscribe, tauriEventName, IpcError, IPC_COMMAND } = await import('./client')

beforeEach(() => {
  tauri.on = true
  invoke.mockReset()
  listen.mockReset()
})

describe('call', () => {
  it('forwards method and params to the Tauri command', async () => {
    invoke.mockResolvedValue({ profiles: [] })
    const res = await call('profile.list', {})
    expect(invoke).toHaveBeenCalledWith(IPC_COMMAND, { method: 'profile.list', params: {} })
    expect(res).toEqual({ profiles: [] })
  })

  it('wraps structured service errors with their code', async () => {
    invoke.mockRejectedValue({ code: 'profile.not_found', message: 'no such id' })
    await expect(call('profile.get', { id: 'x' })).rejects.toMatchObject({
      name: 'IpcError',
      code: 'profile.not_found',
      message: 'no such id',
      fields: [],
    })
  })

  it('keeps per-field validation issues', async () => {
    invoke.mockRejectedValue({
      code: 'profile.invalid_schema',
      message: '1 issue',
      fields: [{ path: 'name', code: 'empty', message: 'x' }, { bogus: true }],
    })
    const err = await call('profile.save', {} as never).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(IpcError)
    expect((err as InstanceType<typeof IpcError>).fields).toEqual([
      { path: 'name', code: 'empty', message: 'x' },
    ])
  })

  it('wraps anything else as a transport error', async () => {
    invoke.mockRejectedValue('pipe closed')
    const err = await call('session.status', {}).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(IpcError)
    expect(err).toMatchObject({ code: 'ipc.transport', message: 'pipe closed' })
  })

  it('falls back to the in-memory mock service outside Tauri', async () => {
    tauri.on = false
    const res = await call('profile.list', {})
    expect(invoke).not.toHaveBeenCalled()
    expect(res.profiles.length).toBeGreaterThan(0)
  })
})

describe('subscribe', () => {
  it('maps the channel to a valid Tauri event name and forwards payloads', async () => {
    const unlisten = vi.fn()
    let handler: ((e: { payload: unknown }) => void) | undefined
    listen.mockImplementation((_name: string, h: (e: { payload: unknown }) => void) => {
      handler = h
      return Promise.resolve(unlisten)
    })
    const seen: unknown[] = []
    const stop = await subscribe('conn.subscribe', (p) => seen.push(p))

    expect(listen).toHaveBeenCalledWith('ipc:conn:subscribe', expect.any(Function))
    handler?.({ payload: { conn_id: 1 } })
    expect(seen).toEqual([{ conn_id: 1 }])
    stop()
    expect(unlisten).toHaveBeenCalledOnce()
  })

  it('uses the mock service outside Tauri', async () => {
    tauri.on = false
    const stop = await subscribe('session.status', () => {})
    expect(listen).not.toHaveBeenCalled()
    stop()
  })

  it('only produces characters Tauri allows in event names', () => {
    expect(tauriEventName('session.status')).toMatch(/^[A-Za-z0-9\-/:_]+$/)
  })
})
