import { create } from 'zustand'

/**
 * Modüller arası canlı olay veriyolu (in-memory, oturum boyunca).
 *
 * Bir modül bir bulgu ürettiğinde `emit()` çağırır; diğer modüller ve canlı
 * olaylar paneli store'u dinleyerek anında tepki verir. Veriler sunucuya
 * gönderilmez, tarayıcı depolamasına yazılmaz — yalnızca açık sekmede yaşar.
 *
 * Olay şekli:
 *   { id, ts, module, type, severity, title, detail, payload }
 *   severity: 'info' | 'low' | 'medium' | 'high' | 'critical'
 */

const MAX_EVENTS = 100

let counter = 0
function nextId() {
  counter += 1
  return `${Date.now().toString(36)}-${counter}`
}

const useEventBus = create((set, get) => ({
  events: [],

  emit(event) {
    const entry = {
      id: nextId(),
      ts: Date.now(),
      severity: 'info',
      module: 'system',
      type: 'event',
      title: '',
      detail: '',
      payload: null,
      ...event,
    }
    set(state => ({ events: [entry, ...state.events].slice(0, MAX_EVENTS) }))
    return entry.id
  },

  clear() {
    set({ events: [] })
  },

  /** Belirli modül(ler)in olaylarını döndürür. */
  byModule(module) {
    return get().events.filter(e => e.module === module)
  },

  /** Belirli tipteki en son olayı döndürür (yoksa null). */
  latestOfType(type) {
    return get().events.find(e => e.type === type) || null
  },

  counts() {
    const c = { total: 0, high: 0 }
    for (const e of get().events) {
      c.total += 1
      if (e.severity === 'high' || e.severity === 'critical') c.high += 1
    }
    return c
  },
}))

/** Modül dışından (store seçicisi olmadan) olay yayınlamak için kısayol. */
export function emitEvent(event) {
  return useEventBus.getState().emit(event)
}

// Yalnızca geliştirme: tarayıcı konsolundan olay veriyolunu incelemek/denemek için.
if (import.meta.env?.DEV && typeof window !== 'undefined') {
  window.__aegisEvents = useEventBus
}

export default useEventBus
