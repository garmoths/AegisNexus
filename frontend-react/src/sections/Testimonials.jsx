import { useEffect, useState } from 'react'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { theme } from '../theme'
import { testimonials } from '../data/landing'

const ROTATE_MS = 6500

export default function Testimonials() {
  const reducedMotion = useReducedMotion()
  const [index, setIndex] = useState(0)
  const [paused, setPaused] = useState(false)

  useEffect(() => {
    if (reducedMotion || paused) return
    const id = setInterval(() => setIndex((i) => (i + 1) % testimonials.length), ROTATE_MS)
    return () => clearInterval(id)
  }, [reducedMotion, paused])

  const current = testimonials[index]

  return (
    <section
      id="testimonials"
      style={{ padding: '90px 24px' }}
      onMouseEnter={() => setPaused(true)}
      onMouseLeave={() => setPaused(false)}
    >
      <div style={{ maxWidth: 980, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <span
            style={{
              display: 'inline-block',
              padding: '6px 14px',
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 700,
              color: theme.primary,
              background: theme.primaryDim,
              border: `1px solid ${theme.primary}33`,
              letterSpacing: '1.6px',
              textTransform: 'uppercase',
              marginBottom: 16,
            }}
          >
            Ekip & Kullanıcılar
          </span>
          <h2 style={{ fontSize: 'clamp(30px, 3.8vw, 42px)', fontWeight: 820, color: '#fff', letterSpacing: '-1px' }}>
            Platformu inşa edenler ve <span style={{ color: theme.primary }}>ilk kullananlar</span> anlatıyor
          </h2>
        </div>

        <div
          style={{
            position: 'relative',
            background: theme.gradientSurface,
            border: `1px solid ${theme.border}`,
            borderRadius: theme.radius.xl,
            padding: 'clamp(28px, 4vw, 44px)',
            minHeight: 240,
            overflow: 'hidden',
          }}
        >
          <div
            aria-hidden
            style={{
              position: 'absolute',
              top: -30,
              left: -10,
              fontSize: 180,
              lineHeight: 1,
              color: `${current.color}1f`,
              fontFamily: 'serif',
              fontWeight: 700,
              userSelect: 'none',
            }}
          >
            “
          </div>
          <AnimatePresence mode="wait">
            <motion.blockquote
              key={index}
              initial={reducedMotion ? false : { opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={reducedMotion ? undefined : { opacity: 0, y: -8 }}
              transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
              style={{
                position: 'relative',
                color: '#fff',
                fontSize: 'clamp(18px, 2vw, 22px)',
                lineHeight: 1.55,
                fontWeight: 500,
                letterSpacing: '-0.2px',
                margin: 0,
              }}
            >
              {current.quote}
              <footer
                style={{
                  marginTop: 28,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 14,
                }}
              >
                <span
                  aria-hidden
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: '50%',
                    display: 'grid',
                    placeItems: 'center',
                    fontWeight: 800,
                    color: current.color,
                    background: `${current.color}1c`,
                    border: `1px solid ${current.color}66`,
                  }}
                >
                  {current.author.split(' ').slice(0, 2).map((s) => s[0]).join('')}
                </span>
                <div>
                  <div style={{ color: '#fff', fontSize: 14, fontWeight: 700 }}>{current.author}</div>
                  <div style={{ color: theme.textMuted, fontSize: 12 }}>{current.role}</div>
                </div>
              </footer>
            </motion.blockquote>
          </AnimatePresence>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 28 }}>
            <div style={{ display: 'flex', gap: 8 }} role="tablist" aria-label="Müşteri yorumları">
              {testimonials.map((t, i) => {
                const active = i === index
                return (
                  <button
                    key={i}
                    type="button"
                    role="tab"
                    aria-selected={active}
                    aria-label={`${t.author} yorumunu göster`}
                    onClick={() => setIndex(i)}
                    style={{
                      width: active ? 28 : 10,
                      height: 6,
                      borderRadius: 999,
                      border: 'none',
                      background: active ? t.color : theme.border,
                      cursor: 'pointer',
                      transition: 'width 220ms ease, background 220ms ease',
                    }}
                  />
                )
              })}
            </div>
            <button
              type="button"
              onClick={() => setIndex((i) => (i + 1) % testimonials.length)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                padding: '8px 18px',
                borderRadius: 999,
                border: `1px solid ${theme.primary}40`,
                background: `${theme.primary}12`,
                color: theme.primary,
                fontSize: 13,
                fontWeight: 700,
                letterSpacing: '0.5px',
                cursor: 'pointer',
                transition: 'background 180ms ease, border-color 180ms ease',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.background = `${theme.primary}25`
                e.currentTarget.style.borderColor = `${theme.primary}80`
              }}
              onMouseLeave={e => {
                e.currentTarget.style.background = `${theme.primary}12`
                e.currentTarget.style.borderColor = `${theme.primary}40`
              }}
            >
              Sonraki
              <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                <path d="M3 7h8M7 3l4 4-4 4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"/>
              </svg>
            </button>
          </div>
        </div>
      </div>
    </section>
  )
}
