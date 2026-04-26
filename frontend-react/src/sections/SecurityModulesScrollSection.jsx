import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import { theme } from '../theme'

const moduleCards = [
  {
    icon: '🤖',
    title: 'AI Guvenlik Asistani',
    badge: 'AKTIF',
    color: '#00d4ff',
    subtitle: 'Scroll-Linked Threat Context',
    desc: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer posuere orci sed mauris elementum, ac luctus orci convallis.',
  },
  {
    icon: '🎣',
    title: 'Phishing Dedektoru',
    badge: 'ANALIZ',
    color: '#ff6b35',
    subtitle: 'Behavior Pattern Detection',
    desc: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Phasellus feugiat justo nec sapien interdum, ut porta mi porttitor.',
  },
  {
    icon: '🕸️',
    title: 'IOC / Tuzak Sistemi',
    badge: 'CANLI',
    color: '#f59e0b',
    subtitle: 'Signal Correlation Layer',
    desc: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla facilisi. In cursus mauris et turpis lacinia, non ullamcorper velit aliquet.',
  },
  {
    icon: '🔓',
    title: 'Veri Sizinti Radari',
    badge: 'SCAN',
    color: '#ef4444',
    subtitle: 'Leak Surface Mapping',
    desc: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vestibulum dictum sem sed neque fermentum efficitur.',
  },
  {
    icon: '🔐',
    title: 'Kriptografik Kalkan',
    badge: 'HARDEN',
    color: '#22c55e',
    subtitle: 'Encryption Posture Checks',
    desc: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec faucibus velit vel dolor auctor, vitae pharetra eros efficitur.',
  },
]

function ModuleStackCard({ item, index, progress, total, reducedMotion }) {
  const step = 1 / total
  const center = step * index + step * 0.5
  const spread = step * 0.65
  const start = Math.max(0, center - spread)
  const end = Math.min(1, center + spread)

  const y = useTransform(progress, [start, center, end], [110, 0, -90])
  const scale = useTransform(progress, [start, center, end], [0.88, 1, 0.9])
  const opacity = useTransform(progress, [start, center, end], [0.3, 1, 0.35])
  const rotateX = useTransform(progress, [start, center, end], [12, 0, -10])

  return (
    <motion.article
      style={{
        position: 'absolute',
        inset: 0,
        maxWidth: 760,
        margin: '0 auto',
        borderRadius: 20,
        border: `1px solid ${item.color}55`,
        background: `linear-gradient(155deg, ${theme.surface}, ${theme.surface2})`,
        boxShadow: `0 20px 55px ${item.color}22`,
        padding: '32px clamp(20px, 4vw, 36px)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        zIndex: total - index,
        y: reducedMotion ? 0 : y,
        scale: reducedMotion ? 1 : scale,
        opacity: reducedMotion ? 1 : opacity,
        rotateX: reducedMotion ? 0 : rotateX,
        transformPerspective: 1200,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 18, alignItems: 'flex-start' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 42 }} aria-hidden="true">{item.icon}</span>
          <div>
            <h3 style={{ color: '#fff', fontWeight: 750, fontSize: 'clamp(20px, 2.5vw, 28px)', letterSpacing: '-0.7px', marginBottom: 4 }}>{item.title}</h3>
            <p style={{ color: item.color, fontSize: 12, textTransform: 'uppercase', letterSpacing: '1.3px', fontWeight: 700 }}>{item.subtitle}</p>
          </div>
        </div>
        <span style={{ padding: '6px 12px', borderRadius: 20, fontSize: 11, fontWeight: 700, background: `${item.color}22`, color: item.color, border: `1px solid ${item.color}66` }}>
          {item.badge}
        </span>
      </div>
      <p style={{ marginTop: 24, color: theme.textMuted, lineHeight: 1.75, fontSize: 'clamp(14px, 1.9vw, 16px)' }}>{item.desc}</p>
      <div style={{ marginTop: 26, height: 1, background: `linear-gradient(90deg, transparent, ${item.color}80, transparent)` }} />
    </motion.article>
  )
}

export default function SecurityModulesScrollSection() {
  const sectionRef = useRef(null)
  const reducedMotion = useReducedMotion()
  const [isCompact, setIsCompact] = useState(false)
  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start start', 'end end'],
  })

  useEffect(() => {
    const media = window.matchMedia('(max-width: 900px)')
    const sync = () => setIsCompact(media.matches)
    sync()
    media.addEventListener('change', sync)
    return () => media.removeEventListener('change', sync)
  }, [])

  return (
    <section
      id="modules"
      ref={sectionRef}
      style={{
        minHeight: reducedMotion || isCompact ? 'auto' : `${moduleCards.length * 75}vh`,
        padding: '40px 24px',
      }}
    >
      <div style={{ maxWidth: 980, margin: '0 auto' }}>
        <h2 style={{ fontSize: 'clamp(34px, 4vw, 44px)', fontWeight: 820, color: '#fff', textAlign: 'center', letterSpacing: '-1px' }}>
          Guvenlik <span style={{ color: theme.primary }}>Modulleri</span>
        </h2>
        <p style={{ color: theme.textMuted, textAlign: 'center', maxWidth: 680, margin: '14px auto 34px', lineHeight: 1.7 }}>
          Scroll scrubbing ile ileri-geri kontrol edilebilen kartvizit akisi: her modulu adim adim, sticky stacking deneyimiyle inceleyin.
        </p>
      </div>

      {reducedMotion || isCompact ? (
        <div style={{ maxWidth: 760, margin: '0 auto', display: 'grid', gap: 18 }}>
          {moduleCards.map((item, index) => (
            <ModuleStackCard key={item.title} item={item} index={index} total={moduleCards.length} progress={scrollYProgress} reducedMotion />
          ))}
        </div>
      ) : (
        <div style={{ position: 'sticky', top: 92, height: 'calc(100vh - 112px)', display: 'grid', placeItems: 'center' }}>
          <div style={{ width: '100%', maxWidth: 760, height: 'min(65vh, 540px)', position: 'relative' }}>
            {moduleCards.map((item, index) => (
              <ModuleStackCard key={item.title} item={item} index={index} total={moduleCards.length} progress={scrollYProgress} reducedMotion={false} />
            ))}
          </div>
        </div>
      )}
    </section>
  )
}
