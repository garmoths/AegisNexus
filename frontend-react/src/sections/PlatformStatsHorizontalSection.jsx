import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import { theme } from '../theme'

const statsCards = [
  {
    metric: 'Threat Surface',
    value: 'Lorem 120K',
    detail: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin suscipit arcu ac metus posuere.',
    tag: 'Realtime',
    color: '#00d4ff',
  },
  {
    metric: 'IOC Correlation',
    value: 'Lorem 9.4K',
    detail: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec volutpat enim in feugiat aliquet.',
    tag: 'Signal',
    color: '#ff6b35',
  },
  {
    metric: 'AI Triage',
    value: 'Lorem Groq',
    detail: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nam commodo augue vitae tincidunt tempor.',
    tag: 'LLM',
    color: '#f59e0b',
  },
  {
    metric: 'Response Posture',
    value: 'Lorem 5-Layer',
    detail: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam a nibh ut ligula scelerisque posuere.',
    tag: 'Defense',
    color: '#22c55e',
  },
  {
    metric: 'Risk Drift',
    value: 'Lorem Low',
    detail: 'Lorem ipsum dolor sit amet, consectetur adipiscing elit. Integer lobortis urna at nibh sagittis.',
    tag: 'Control',
    color: '#9f7aea',
  },
]

function HorizontalStatCard({ card, reducedMotion }) {
  return (
    <motion.article
      whileHover={{
        y: -5,
        borderColor: `${card.color}cc`,
        boxShadow: `0 0 0 1px ${card.color}66, 0 18px 45px ${card.color}33, inset 0 0 24px ${card.color}1f`,
      }}
      transition={{ duration: 0.22, ease: 'easeOut' }}
      style={{
        width: 'clamp(240px, 32vw, 320px)',
        minHeight: 290,
        borderRadius: 18,
        padding: 24,
        background: `linear-gradient(145deg, ${theme.surface}, ${theme.surface2})`,
        border: `1px solid ${theme.border}`,
        display: 'flex',
        flexDirection: 'column',
        gap: 14,
        flexShrink: 0,
        scrollSnapAlign: 'start',
        boxShadow: `0 10px 30px ${card.color}12, inset 0 0 0 ${card.color}00`,
        transition: reducedMotion ? 'none' : 'box-shadow 200ms ease, border-color 200ms ease',
      }}
      tabIndex={0}
      whileFocus={{
        borderColor: `${card.color}cc`,
        boxShadow: `0 0 0 1px ${card.color}66, 0 18px 45px ${card.color}33, inset 0 0 24px ${card.color}1f`,
      }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <p style={{ color: theme.textMuted, fontSize: 12, textTransform: 'uppercase', letterSpacing: '1.4px', fontWeight: 700 }}>{card.metric}</p>
        <span style={{ padding: '5px 10px', borderRadius: 999, fontSize: 11, color: card.color, background: `${card.color}1f`, border: `1px solid ${card.color}55` }}>{card.tag}</span>
      </div>
      <h3 style={{ color: '#fff', fontSize: 'clamp(24px, 3vw, 34px)', letterSpacing: '-0.6px' }}>{card.value}</h3>
      <p style={{ color: theme.textMuted, lineHeight: 1.68, fontSize: 14 }}>{card.detail}</p>
      <div style={{ marginTop: 'auto', height: 1, background: `linear-gradient(90deg, transparent, ${card.color}aa, transparent)` }} />
    </motion.article>
  )
}

export default function PlatformStatsHorizontalSection() {
  const sectionRef = useRef(null)
  const viewportRef = useRef(null)
  const trackRef = useRef(null)
  const reducedMotion = useReducedMotion()
  const [isCompact, setIsCompact] = useState(false)
  const [maxTranslate, setMaxTranslate] = useState(0)

  const { scrollYProgress } = useScroll({
    target: sectionRef,
    offset: ['start start', 'end end'],
  })

  const x = useTransform(scrollYProgress, [0, 1], [0, -maxTranslate])

  useEffect(() => {
    const media = window.matchMedia('(max-width: 900px)')
    const sync = () => setIsCompact(media.matches)
    sync()
    media.addEventListener('change', sync)
    return () => media.removeEventListener('change', sync)
  }, [])

  useEffect(() => {
    if (reducedMotion) {
      setMaxTranslate(0)
      return undefined
    }

    const recalc = () => {
      const viewportWidth = viewportRef.current?.clientWidth ?? 0
      const trackWidth = trackRef.current?.scrollWidth ?? 0
      setMaxTranslate(Math.max(trackWidth - viewportWidth, 0))
    }

    recalc()
    const observer = new ResizeObserver(recalc)
    if (viewportRef.current) observer.observe(viewportRef.current)
    if (trackRef.current) observer.observe(trackRef.current)
    window.addEventListener('resize', recalc)

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', recalc)
    }
  }, [reducedMotion, isCompact])

  return (
    <section
      id="features"
      ref={sectionRef}
      style={{
        minHeight: reducedMotion || isCompact ? 'auto' : '290vh',
        padding: '36px 0 68px',
      }}
    >
      <div style={{ maxWidth: 1220, margin: '0 auto', padding: '0 24px 26px' }}>
        <h2 style={{ fontSize: 'clamp(34px, 4vw, 44px)', fontWeight: 820, color: '#fff', textAlign: 'center', letterSpacing: '-1px' }}>
          Platform <span style={{ color: theme.primary }}>Istatistikleri</span>
        </h2>
        <p style={{ color: theme.textMuted, textAlign: 'center', margin: '12px auto 0', maxWidth: 760, lineHeight: 1.7 }}>
          Sticky horizontal scroll ile sayfa inerken kartlar soldan saga akiyor; her kart hover aninda parlayan border ve hafif neon inset ile canli bir his veriyor.
        </p>
      </div>

      <div
        ref={viewportRef}
        style={{
          position: reducedMotion || isCompact ? 'relative' : 'sticky',
          top: reducedMotion || isCompact ? 'auto' : 90,
          minHeight: reducedMotion || isCompact ? 'auto' : 'calc(100vh - 112px)',
          display: 'flex',
          alignItems: 'center',
          overflow: reducedMotion || isCompact ? 'auto' : 'hidden',
          padding: '0 24px',
        }}
      >
        <motion.div
          ref={trackRef}
          style={{
            display: 'flex',
            gap: 18,
            width: 'max-content',
            x: reducedMotion || isCompact ? 0 : x,
            scrollSnapType: isCompact ? 'x mandatory' : 'none',
            paddingBottom: isCompact ? 8 : 0,
          }}
        >
          {statsCards.map((card) => (
            <HorizontalStatCard key={card.metric} card={card} reducedMotion={reducedMotion} />
          ))}
        </motion.div>
      </div>
    </section>
  )
}
