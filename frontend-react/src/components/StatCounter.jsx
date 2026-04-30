import { useEffect, useRef, useState } from 'react'
import { theme } from '../theme'

export default function StatCounter({ value, label, suffix = '', duration = 2000 }) {
  const [display, setDisplay] = useState(0)
  const ref = useRef(null)
  const started = useRef(false)

  useEffect(() => {
    if (started.current) return
    started.current = true

    const end = typeof value === 'number' ? value : parseInt(value, 10) || 0
    const start = 0
    const startTime = performance.now()

    function tick(now) {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      // ease-out
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(start + (end - start) * eased))
      if (progress < 1) requestAnimationFrame(tick)
    }

    requestAnimationFrame(tick)
  }, [value, duration])

  return (
    <div ref={ref} style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4,
    }}>
      <span style={{
        fontSize: 36, fontWeight: 800, color: theme.primary,
        fontFamily: 'monospace',
        textShadow: `0 0 30px ${theme.primary}40`,
      }}>
        {display.toLocaleString('tr-TR')}{suffix}
      </span>
      <span style={{
        fontSize: 12, color: theme.textMuted, fontWeight: 500,
        textTransform: 'uppercase', letterSpacing: '1px',
      }}>
        {label}
      </span>
    </div>
  )
}
