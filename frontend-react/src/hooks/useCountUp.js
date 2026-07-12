import { useEffect, useRef, useState } from 'react'

const prefersReducedMotion = () =>
  typeof window !== 'undefined' &&
  window.matchMedia &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches

// Verilen `to` değerine, `start` true olunca, `duration` ms içinde animatif sayar.
// `decimals` >= 1 ise ondalık değer döner. Reduced motion durumunda doğrudan hedefe atlar.
export function useCountUp(to, { duration = 1600, start = true, decimals = 0 } = {}) {
  const [value, setValue] = useState(0)
  const startedRef = useRef(false)
  const rafRef = useRef(0)

  useEffect(() => {
    if (!start || startedRef.current) return undefined
    startedRef.current = true

    if (prefersReducedMotion()) {
      // setState'i sıradaki frame'e alarak effect body'sinin sync setState yapmamasını sağlıyoruz.
      rafRef.current = requestAnimationFrame(() => setValue(to))
      return () => cancelAnimationFrame(rafRef.current)
    }

    const startTs = performance.now()
    const from = 0
    const factor = 10 ** decimals

    const tick = (now) => {
      const elapsed = now - startTs
      const t = Math.min(1, elapsed / duration)
      const eased = 1 - Math.pow(1 - t, 3)
      const next = from + (to - from) * eased
      setValue(Math.round(next * factor) / factor)
      if (t < 1) {
        rafRef.current = requestAnimationFrame(tick)
      }
    }

    rafRef.current = requestAnimationFrame(tick)

    return () => cancelAnimationFrame(rafRef.current)
  }, [start, to, duration, decimals])

  return value
}
