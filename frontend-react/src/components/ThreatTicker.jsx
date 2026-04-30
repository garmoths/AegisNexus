import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { theme } from '../theme'

export default function ThreatTicker({ cases = [], interval = 4000 }) {
  const [idx, setIdx] = useState(0)

  useEffect(() => {
    if (cases.length === 0) return
    const timer = setInterval(() => {
      setIdx(i => (i + 1) % cases.length)
    }, interval)
    return () => clearInterval(timer)
  }, [cases.length, interval])

  const current = cases[idx]
  if (!current) return null

  return (
    <div style={{
      background: `${theme.danger}10`,
      border: `1px solid ${theme.danger}30`,
      borderRadius: theme.radius.sm,
      padding: '10px 16px',
      display: 'flex', alignItems: 'center', gap: 10,
      overflow: 'hidden',
    }}>
      <span style={{ fontSize: 16 }}>⚠️</span>
      <AnimatePresence mode="wait">
        <motion.span
          key={current.case_title}
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -20 }}
          transition={{ duration: 0.3 }}
          style={{ fontSize: 13, color: theme.text, whiteSpace: 'nowrap' }}
        >
          {current.case_title}
        </motion.span>
      </AnimatePresence>
      <span style={{
        marginLeft: 'auto', fontSize: 11, color: theme.danger, fontWeight: 600,
      }}>
        Şiddet: {current.severity_score}
      </span>
    </div>
  )
}
