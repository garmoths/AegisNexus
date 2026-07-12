import { motion } from 'framer-motion'
import { theme } from '../../theme'
import { MODULES_URL } from '../../lib/links'

const reveal = (delay = 0) => ({
  initial: { opacity: 0, y: 24 },
  animate: { opacity: 1, y: 0 },
  transition: { duration: 0.65, ease: [0.22, 1, 0.36, 1], delay },
})

export default function HeroText({ reducedMotion }) {
  const r = (delay) => (reducedMotion ? { initial: false } : reveal(delay))

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'flex-start',
        gap: 0,
      }}
    >
      {/* Badge */}
      <motion.span
        {...r(0)}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 8,
          padding: '7px 16px',
          background: theme.primaryDim,
          border: `1px solid ${theme.primary}33`,
          borderRadius: 999,
          fontSize: 11,
          fontWeight: 700,
          color: theme.primary,
          textTransform: 'uppercase',
          letterSpacing: '2px',
          marginBottom: 22,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        <span
          style={{
            width: 7,
            height: 7,
            borderRadius: '50%',
            background: theme.success,
            boxShadow: `0 0 10px ${theme.success}`,
          }}
        />
        Canlı Tehdit İstihbaratı · 7/24 Aktif
      </motion.span>

      {/* H1 */}
      <motion.h1
        {...r(0.1)}
        style={{
          fontSize: 'clamp(36px, 5.2vw, 72px)',
          fontWeight: 900,
          color: '#fff',
          lineHeight: 1.04,
          marginBottom: 20,
          letterSpacing: '-2px',
        }}
      >
        Tehditler Sizi Bulmadan
        <br />
        <span
          style={{
            background: theme.gradientPrimary,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}
        >
          Siz Keşfedin
        </span>
      </motion.h1>

      {/* Description */}
      <motion.p
        {...r(0.22)}
        style={{
          color: theme.textMuted,
          fontSize: 'clamp(14px, 1.5vw, 17px)',
          maxWidth: 480,
          lineHeight: 1.72,
          marginBottom: 36,
        }}
      >
        1,7 milyondan fazla phishing URL, 30.000+ aktif IOC ve SMS tabanlı kurban atlasıyla —
        tehditleri siz fark etmeden biz engelliyoruz.
      </motion.p>

      {/* CTA Buttons */}
      <motion.div
        {...r(0.34)}
        style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: 0 }}
      >
        <a
          href={MODULES_URL}
          style={{
            padding: '13px 30px',
            borderRadius: 8,
            border: 'none',
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: 700,
            letterSpacing: '0.4px',
            background: theme.gradientPrimary,
            color: '#000',
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            boxShadow: '0 4px 20px rgba(0,212,255,0.32)',
            transition: 'transform 200ms ease, box-shadow 200ms ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-2px)'
            e.currentTarget.style.boxShadow = '0 8px 32px rgba(0,212,255,0.45)'
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'none'
            e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,212,255,0.32)'
          }}
        >
          Paneli Aç →
        </a>
        <button
          type="button"
          onClick={() => document.getElementById('modules')?.scrollIntoView({ behavior: 'smooth' })}
          style={{
            padding: '13px 30px',
            borderRadius: 8,
            border: `1px solid ${theme.primary}55`,
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: 700,
            letterSpacing: '0.4px',
            background: 'transparent',
            color: theme.primary,
            textDecoration: 'none',
            display: 'inline-flex',
            alignItems: 'center',
            gap: 8,
            transition: 'transform 200ms ease, box-shadow 200ms ease, background 200ms ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.transform = 'translateY(-2px)'
            e.currentTarget.style.background = theme.primaryDim
            e.currentTarget.style.boxShadow = `0 8px 30px ${theme.primary}33`
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.transform = 'none'
            e.currentTarget.style.background = 'transparent'
            e.currentTarget.style.boxShadow = 'none'
          }}
        >
          Modülleri Keşfet
        </button>
      </motion.div>
    </div>
  )
}
