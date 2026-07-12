import { motion } from 'framer-motion'
import { theme } from '../theme'

export default function GeminiLoader({ text = 'AI analiz ediyor...' }) {
  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16,
      padding: '40px 20px',
    }}>
      <motion.div
        animate={{ rotate: 360 }}
        transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
        style={{
          width: 48, height: 48, borderRadius: '50%',
          border: `3px solid ${theme.border}`,
          borderTopColor: theme.primary,
        }}
      />
      <motion.p
        animate={{ opacity: [0.5, 1, 0.5] }}
        transition={{ duration: 1.5, repeat: Infinity }}
        style={{ color: theme.primary, fontSize: 14, fontWeight: 500, margin: 0 }}
      >
        {text}
      </motion.p>
    </div>
  )
}
