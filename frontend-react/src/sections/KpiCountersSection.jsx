import { motion, useReducedMotion } from 'framer-motion'
import { theme } from '../theme'
import { kpis } from '../data/landing'
import { useCountUp } from '../hooks/useCountUp'
import { useInViewOnce } from '../hooks/useInViewOnce'

function formatValue(raw, decimals) {
  if (decimals > 0) return raw.toFixed(decimals)
  return Math.round(raw).toLocaleString('tr-TR')
}

function KpiCard({ kpi, index, reducedMotion }) {
  const [ref, inView] = useInViewOnce({ threshold: 0.35 })
  const decimals = Number.isInteger(kpi.value) ? 0 : 2
  const animated = useCountUp(kpi.value, { start: inView, duration: 1500, decimals })

  return (
    <motion.div
      ref={ref}
      initial={reducedMotion ? false : { opacity: 0, y: 18 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.5, delay: index * 0.06, ease: [0.16, 1, 0.3, 1] }}
      style={{
        position: 'relative',
        padding: '32px 26px',
        borderRadius: theme.radius.lg,
        background: theme.gradientSurface,
        border: `1px solid ${theme.border}`,
        overflow: 'hidden',
      }}
    >
      <div
        aria-hidden
        style={{
          position: 'absolute',
          top: -40,
          right: -40,
          width: 160,
          height: 160,
          background: `radial-gradient(circle, ${kpi.color}33 0%, transparent 65%)`,
          pointerEvents: 'none',
        }}
      />
      <div style={{ position: 'relative', display: 'flex', alignItems: 'baseline', gap: 6 }}>
        <span
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 'clamp(36px, 4.4vw, 52px)',
            fontWeight: 800,
            color: '#fff',
            letterSpacing: '-1.5px',
            lineHeight: 1,
          }}
        >
          {formatValue(animated, decimals)}
        </span>
        <span style={{ fontSize: 22, fontWeight: 700, color: kpi.color }}>{kpi.suffix}</span>
      </div>
      <p
        style={{
          position: 'relative',
          marginTop: 14,
          fontSize: 13,
          fontWeight: 700,
          color: '#fff',
          letterSpacing: '0.4px',
          textTransform: 'uppercase',
        }}
      >
        {kpi.label}
      </p>
      <p style={{ position: 'relative', marginTop: 6, fontSize: 13, color: theme.textMuted, lineHeight: 1.6 }}>{kpi.desc}</p>
      <div
        aria-hidden
        style={{
          position: 'relative',
          marginTop: 18,
          height: 1,
          background: `linear-gradient(90deg, ${kpi.color}99, transparent)`,
        }}
      />
    </motion.div>
  )
}

export default function KpiCountersSection() {
  const reducedMotion = useReducedMotion()
  return (
    <section id="kpi" style={{ padding: '60px 24px 80px' }}>
      <div style={{ maxWidth: 1220, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 40 }}>
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
              marginBottom: 18,
            }}
          >
            Sayılarla AegisNexus
          </span>
          <h2 style={{ fontSize: 'clamp(30px, 3.8vw, 42px)', fontWeight: 820, color: '#fff', letterSpacing: '-1px' }}>
            Reklam değil, ölçülen <span style={{ color: theme.primary }}>sonuçlar</span>
          </h2>
          <p style={{ color: theme.textMuted, maxWidth: 680, margin: '12px auto 0', lineHeight: 1.7 }}>
            Aşağıdaki rakamlar üretim ortamından gelen 90 günlük telemetri özetidir.
          </p>
        </div>
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: 18,
          }}
        >
          {kpis.map((kpi, index) => (
            <KpiCard key={kpi.label} kpi={kpi} index={index} reducedMotion={reducedMotion} />
          ))}
        </div>
      </div>
    </section>
  )
}
