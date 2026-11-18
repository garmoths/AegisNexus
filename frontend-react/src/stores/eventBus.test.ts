import { beforeEach, describe, expect, it } from 'vitest'
import useEventBus, { emitEvent } from './eventBus'

describe('event bus', () => {
  beforeEach(() => useEventBus.getState().clear())

  it('prepends events with defaults and counts high severity', () => {
    emitEvent({ module: 'phishing', type: 'scan', severity: 'high', title: 'Phishing' })
    emitEvent({ module: 'ioc', type: 'lookup' })
    const { events, counts, byModule, latestOfType } = useEventBus.getState()
    expect(events[0].module).toBe('ioc')
    expect(events[0].severity).toBe('info')
    expect(counts()).toEqual({ total: 2, high: 1 })
    expect(byModule('phishing')).toHaveLength(1)
    expect(latestOfType('scan')?.title).toBe('Phishing')
  })

  it('keeps at most 100 events', () => {
    for (let i = 0; i < 120; i += 1) emitEvent({ title: String(i) })
    expect(useEventBus.getState().events).toHaveLength(100)
    expect(useEventBus.getState().events[0].title).toBe('119')
  })
})
