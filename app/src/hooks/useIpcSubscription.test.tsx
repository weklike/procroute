// SPDX-License-Identifier: GPL-3.0-or-later
import { act, render, screen } from '@testing-library/react'
import { StrictMode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

type Handler = (payload: unknown) => void
const handlers: Handler[] = []
const unlistens: ReturnType<typeof vi.fn>[] = []

vi.mock('@/api/client', () => ({
  subscribe: (_channel: string, h: Handler) => {
    handlers.push(h)
    const un = vi.fn()
    unlistens.push(un)
    return Promise.resolve(un)
  },
}))

const { useIpcSubscription, appendCapped } = await import('./useIpcSubscription')

let renders = 0
function Probe({ cap }: { cap?: number }) {
  const items = useIpcSubscription('log.subscribe', cap)
  renders += 1
  return <output aria-label="count">{items.length}</output>
}

/** 等订阅的 Promise 落定。 */
async function settle() {
  await act(async () => {
    await Promise.resolve()
  })
}

function emit(n: number, h: Handler | undefined = handlers.at(-1)) {
  for (let i = 0; i < n; i++) h?.({ seq: i })
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['requestAnimationFrame', 'cancelAnimationFrame'] })
  handlers.length = 0
  unlistens.length = 0
  renders = 0
})

afterEach(() => {
  vi.useRealTimers()
})

describe('useIpcSubscription', () => {
  it('batches a burst of events into a single render per frame', async () => {
    render(<Probe />)
    await settle()
    const before = renders

    emit(500)
    expect(screen.getByLabelText('count')).toHaveTextContent('0')
    act(() => {
      vi.advanceTimersToNextFrame()
    })

    expect(screen.getByLabelText('count')).toHaveTextContent('500')
    expect(renders - before).toBe(1)
  })

  it('keeps only the most recent cap items', async () => {
    render(<Probe cap={10} />)
    await settle()
    emit(30)
    act(() => {
      vi.advanceTimersToNextFrame()
    })
    expect(screen.getByLabelText('count')).toHaveTextContent('10')
  })

  it('unsubscribes on unmount and ignores late events', async () => {
    const { unmount } = render(<Probe />)
    await settle()
    unmount()
    expect(unlistens.at(-1)).toHaveBeenCalledOnce()
    emit(5)
    expect(() => {
      vi.advanceTimersToNextFrame()
    }).not.toThrow()
  })

  it('does not duplicate events under StrictMode double effects', async () => {
    render(
      <StrictMode>
        <Probe />
      </StrictMode>,
    )
    await settle()
    // 严格模式下 effect 跑两次：第一次的订阅必须已被取消
    expect(handlers).toHaveLength(2)
    expect(unlistens[0]).toHaveBeenCalledOnce()
    emit(3, handlers[0])
    emit(3, handlers[1])
    act(() => {
      vi.advanceTimersToNextFrame()
    })
    expect(screen.getByLabelText('count')).toHaveTextContent('3')
  })
})

describe('appendCapped', () => {
  it('appends and trims from the front', () => {
    expect(appendCapped([1, 2], [3], 5)).toEqual([1, 2, 3])
    expect(appendCapped([1, 2, 3], [4, 5], 3)).toEqual([3, 4, 5])
  })
})
