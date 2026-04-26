import { useRef } from 'react'
import { motion, useReducedMotion, useScroll, useTransform } from 'framer-motion'
import { theme } from '../theme'
import { incidentSteps } from '../data/landing'

function StepCard({ step, index, total, reducedMotion }) {
  const ref = useRef(null)
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ['start 80%', 'start 30%'],
  })
  const opacity = useTransform(scrollYProgress, [0, 1], [0.35, 1])
  const x = useTransform(scrollYProgress, [0, 1], [reducedMotion ? 0 : -24, 0])

  return (
    <motion.li
      ref={ref}
      style={{
        position: 'relative',
        paddingLeft: 60,
        paddingBottom: index === total - 1 ? 0 : 38,
        opacity: reducedMotion ? 1 : opacity,
        x: reducedMotion ? 0 : x,
      }}
    >
      <div
        aria-hidden
        style={{
          position: 'absolute',
          left: 18,
          top: 6,
          width: 24,
          height: 24,
          borderRadius: '50%',
          background: theme.bgDeep,
          border: `2px solid ${theme.primary}`,
          boxShadow: `0 0 0 4px ${theme.bg}, 0 0 18px ${theme.primary}66`,
          display: 'grid',
          placeItems: 'center',
        }}
      >
        <span style={{ width: 8, height: 8, borderRadius: '50%', background: theme.primary }} />
      </div>
      <div
        style={{
          padding: 22,
          borderRadius: theme.radius.lg,
          background: theme.gradientSurface,
          border: `1px solid ${theme.border}`,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span
              style={{
                width: 44,
                height: 44,
                borderRadius: 12,
                display: 'grid',
                placeItems: 'center',
                fontSize: 22,
                background: `${theme.primary}1a`,
                border: `1px solid ${theme.primary}55`,
              }}
              aria-hidden
            >
              {step.icon}
            </span>
            <div>
              <div style={{ fontSize: 11, color: theme.primary, letterSpacing: '1.4px', fontWeight: 700, textTransform: 'uppercase' }}>
                Aşama {String(index + 1).padStart(2, '0')} · {step.phase}
              </div>
              <h3 style={{ color: '#fff', fontSize: 20, fontWeight: 750, marginTop: 2 }}>{step.title}</h3>
            </div>
          </div>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 12, color: theme.textMuted }}>
            T+{(index + 1) * 6}dk
          </span>
        </div>
        <p style={{ color: theme.text, marginTop: 12, lineHeight: 1.7, fontSize: 14 }}>{step.desc}</p>
      </div>
    </motion.li>
  )
}

export default function IncidentTimeline() {
  const reducedMotion = useReducedMotion()
  const containerRef = useRef(null)
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start 70%', 'end 60%'],
  })
  const lineHeight = useTransform(scrollYProgress, [0, 1], ['0%', '100%'])

  return (
    <section id="timeline" style={{ padding: '90px 24px' }}>
      <div style={{ maxWidth: 920, margin: '0 auto' }}>
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <span
            style={{
              display: 'inline-block',
              padding: '6px 14px',
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 700,
              color: theme.danger,
              background: `${theme.danger}1c`,
              border: `1px solid ${theme.danger}55`,
              letterSpacing: '1.6px',
              textTransform: 'uppercase',
              marginBottom: 16,
            }}
          >
            Olay Müdahale Akışı
          </span>
          <h2 style={{ fontSize: 'clamp(30px, 3.8vw, 42px)', fontWeight: 820, color: '#fff', letterSpacing: '-1px' }}>
            Saldırının ilk dakikası, savunmanın <span style={{ color: theme.primary }}>en kritik</span> dakikasıdır
          </h2>
          <p style={{ color: theme.textMuted, maxWidth: 660, margin: '12px auto 0', lineHeight: 1.7 }}>
            NIST 800-61 referans alınmış 5 aşamalı playbook. Ortalama containment süresi 18 dakika.
          </p>
        </div>

        <div ref={containerRef} style={{ position: 'relative' }}>
          <div
            aria-hidden
            style={{
              position: 'absolute',
              left: 29,
              top: 12,
              bottom: 12,
              width: 2,
              background: theme.borderSoft,
              borderRadius: 999,
            }}
          />
          <motion.div
            aria-hidden
            style={{
              position: 'absolute',
              left: 29,
              top: 12,
              width: 2,
              height: lineHeight,
              background: `linear-gradient(180deg, ${theme.primary}, ${theme.violet})`,
              borderRadius: 999,
              boxShadow: `0 0 12px ${theme.primary}66`,
            }}
          />
          <ol style={{ listStyle: 'none', padding: 0, margin: 0 }}>
            {incidentSteps.map((step, index) => (
              <StepCard
                key={step.phase}
                step={step}
                index={index}
                total={incidentSteps.length}
                reducedMotion={reducedMotion}
              />
            ))}
          </ol>
        </div>
      </div>
    </section>
  )
}
