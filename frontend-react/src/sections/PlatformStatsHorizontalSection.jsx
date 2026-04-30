import { motion, useReducedMotion } from 'framer-motion'
import { theme } from '../theme'
import { platformPath } from '../data/landing'

// voxr.ai "Your Path from Leads to Live Conversations" pattern'inden esinlenmiş
// numaralı dikey adım listesi. Yatay sticky scroll yok; her adım kendi satırında,
// solda büyük mono numara, sağda başlık + açıklama, en altta ince ayraç çizgisi.
function PathStep({ step, index, total, prefersReducedMotion }) {
  const isLast = index === total - 1

  return (
    <motion.article
      initial={prefersReducedMotion ? false : { opacity: 0, y: 24 }}
      whileInView={prefersReducedMotion ? undefined : { opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-10% 0px' }}
      transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1], delay: index * 0.06 }}
      whileHover={prefersReducedMotion ? undefined : { y: -2 }}
      style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(120px, 200px) 1fr',
        gap: 'clamp(24px, 4vw, 56px)',
        padding: 'clamp(28px, 4vw, 48px) 0',
        borderBottom: isLast ? 'none' : `1px solid ${theme.borderSoft || '#1a2236'}`,
        cursor: 'default',
      }}
    >
      <div
        style={{
          fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
          fontSize: 'clamp(48px, 7vw, 88px)',
          fontWeight: 600,
          color: theme.textSubtle || theme.textMuted,
          letterSpacing: '-0.04em',
          lineHeight: 1,
          transition: 'color .25s ease',
        }}
        className="path-step-num"
      >
        {step.num}
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 14, paddingTop: 8 }}>
        <h3
          style={{
            color: '#fff',
            fontSize: 'clamp(24px, 3vw, 34px)',
            fontWeight: 750,
            letterSpacing: '-0.6px',
            lineHeight: 1.15,
          }}
        >
          {step.title}
        </h3>
        <p
          style={{
            color: theme.textMuted,
            fontSize: 'clamp(14px, 1.5vw, 17px)',
            lineHeight: 1.75,
            maxWidth: 720,
          }}
        >
          {step.desc}
        </p>
      </div>
    </motion.article>
  )
}

export default function PlatformStatsHorizontalSection() {
  const prefersReducedMotion = useReducedMotion() ?? false

  return (
    <section
      id="path"
      style={{
        padding: 'clamp(60px, 10vw, 120px) 0',
        position: 'relative',
      }}
    >
      <style>{`
        .path-step-num-wrapper:hover .path-step-num,
        .path-step-num-wrapper:focus-within .path-step-num {
          color: ${theme.primary};
        }
      `}</style>

      <div style={{ maxWidth: 1180, margin: '0 auto', padding: '0 24px' }}>
        <header style={{ maxWidth: 760, marginBottom: 'clamp(40px, 6vw, 72px)' }}>
          <span
            style={{
              display: 'inline-block',
              padding: '6px 14px',
              borderRadius: 999,
              background: `${theme.primary}1a`,
              border: `1px solid ${theme.primary}40`,
              color: theme.primary,
              fontSize: 12,
              fontWeight: 700,
              letterSpacing: 1.4,
              textTransform: 'uppercase',
              marginBottom: 22,
            }}
          >
            Akış
          </span>
          <h2
            style={{
              fontSize: 'clamp(36px, 5vw, 56px)',
              fontWeight: 820,
              color: '#fff',
              letterSpacing: '-1.4px',
              lineHeight: 1.05,
            }}
          >
            Tehdit sinyalinden kapatılan olaya{' '}
            <span style={{ color: theme.primary }}>5 adımlık yol</span>
          </h2>
          <p
            style={{
              color: theme.textMuted,
              fontSize: 'clamp(15px, 1.6vw, 18px)',
              lineHeight: 1.7,
              marginTop: 22,
              maxWidth: 640,
            }}
          >
            AegisNexus’ın günlük operasyonu nasıl şekillendirdiğini kısaca anlatıyoruz: bağlantı kurmaktan iyileştirme döngüsüne kadar her adım, ekibinizin manuel iş yükünü azaltacak şekilde tasarlandı.
          </p>
        </header>

        <div>
          {platformPath.map((step, i) => (
            <div key={step.num} className="path-step-num-wrapper">
              <PathStep
                step={step}
                index={i}
                total={platformPath.length}
                prefersReducedMotion={prefersReducedMotion}
              />
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
