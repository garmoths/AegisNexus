import { motion, useReducedMotion } from 'framer-motion'
import { theme } from '../theme'
import { cases } from '../data/landing'

function CaseCard({ item, index, span, reducedMotion }) {
  return (
    <motion.article
      initial={reducedMotion ? false : { opacity: 0, y: 24 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-80px' }}
      transition={{ duration: 0.55, delay: index * 0.08, ease: [0.16, 1, 0.3, 1] }}
      whileHover={reducedMotion ? undefined : { y: -6, borderColor: `${item.color}aa` }}
      style={{
        gridColumn: span,
        position: 'relative',
        padding: 28,
        borderRadius: theme.radius.xl,
        background: theme.gradientSurface,
        border: `1px solid ${theme.border}`,
        overflow: 'hidden',
        minHeight: 260,
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        gap: 18,
        transition: 'border-color 220ms ease',
      }}
    >
      <div
        aria-hidden
        style={{
          position: 'absolute',
          inset: 0,
          background: `radial-gradient(circle at 100% 0%, ${item.color}22 0%, transparent 55%)`,
          pointerEvents: 'none',
        }}
      />
      <div
        aria-hidden
        style={{
          position: 'absolute',
          inset: 0,
          backgroundImage: `linear-gradient(135deg, ${item.color}11 0%, transparent 50%)`,
          mixBlendMode: 'overlay',
          pointerEvents: 'none',
        }}
      />
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <span
          style={{
            padding: '5px 12px',
            borderRadius: 999,
            fontSize: 11,
            fontWeight: 700,
            color: item.color,
            background: `${item.color}1c`,
            border: `1px solid ${item.color}55`,
            letterSpacing: '0.6px',
          }}
        >
          {item.sector}
        </span>
        <span style={{ fontSize: 12, color: theme.textMuted, letterSpacing: '0.5px' }}>Case Study</span>
      </div>
      <div style={{ position: 'relative' }}>
        <h3 style={{ color: '#fff', fontSize: 'clamp(20px, 2.4vw, 26px)', fontWeight: 760, letterSpacing: '-0.5px', lineHeight: 1.25 }}>
          {item.title}
        </h3>
        <p style={{ color: theme.textMuted, marginTop: 12, lineHeight: 1.7, fontSize: 14 }}>{item.summary}</p>
      </div>
      <div
        style={{
          position: 'relative',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          paddingTop: 18,
          borderTop: `1px solid ${theme.border}`,
        }}
      >
        <div>
          <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 32, fontWeight: 800, color: item.color, letterSpacing: '-1px' }}>
            {item.metric}
          </div>
          <div style={{ fontSize: 12, color: theme.textMuted, marginTop: 2 }}>{item.metricLabel}</div>
        </div>
        <span
          aria-hidden
          style={{
            width: 38,
            height: 38,
            borderRadius: '50%',
            display: 'grid',
            placeItems: 'center',
            background: `${item.color}1c`,
            border: `1px solid ${item.color}55`,
            color: item.color,
          }}
        >
          →
        </span>
      </div>
    </motion.article>
  )
}

const SPANS = ['span 7', 'span 5', 'span 5', 'span 7']

export default function CaseStudiesShowcase() {
  const reducedMotion = useReducedMotion()
  return (
    <section id="cases" style={{ padding: '90px 24px', position: 'relative' }}>
      <div style={{ maxWidth: 1220, margin: '0 auto' }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', justifyContent: 'space-between', gap: 18, marginBottom: 36 }}>
          <div>
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
              Vaka Çalışmaları
            </span>
            <h2 style={{ fontSize: 'clamp(30px, 3.8vw, 44px)', fontWeight: 820, color: '#fff', letterSpacing: '-1.2px' }}>
              Saldırıyı sayfanın <span style={{ color: theme.primary }}>arkasında</span> durduruyoruz
            </h2>
          </div>
          <p style={{ color: theme.textMuted, maxWidth: 420, lineHeight: 1.75 }}>
            Müşteri gizliliğine saygıyla anonimleştirilmiş gerçek olaylar. Sayılar üretim ortamından alınmıştır.
          </p>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(12, 1fr)',
            gap: 18,
          }}
        >
          {cases.map((item, index) => (
            <CaseCard
              key={item.title}
              item={item}
              index={index}
              span={SPANS[index % SPANS.length]}
              reducedMotion={reducedMotion}
            />
          ))}
        </div>

        <style>{`
          @media (max-width: 900px) {
            #cases > div > div:last-of-type > article {
              grid-column: span 12 !important;
            }
          }
        `}</style>
      </div>
    </section>
  )
}
