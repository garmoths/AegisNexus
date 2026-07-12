import { theme } from '../../theme'
import HeroCanvas from './HeroCanvas'
import HeroText from './HeroText'
import LiveScanPanel from './LiveScanPanel'

export default function HeroSection({ reducedMotion }) {
  return (
    <header
      id="hero"
      style={{
        position: 'relative',
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        overflow: 'hidden',
        background: theme.bgDeep,
      }}
    >
      {/* Radial glow layer */}
      <div
        aria-hidden
        style={{
          position: 'absolute',
          inset: 0,
          background: theme.gradientHero,
          pointerEvents: 'none',
        }}
      />

      {/* Canvas animation — bottom layer */}
      <HeroCanvas reducedMotion={reducedMotion} />

      {/* Content grid */}
      <div
        style={{
          position: 'relative',
          zIndex: 1,
          width: '100%',
          maxWidth: 1200,
          margin: '0 auto',
          padding: 'clamp(100px, 14vh, 160px) clamp(20px, 5vw, 80px) clamp(60px, 10vh, 100px)',
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: 'clamp(32px, 5vw, 72px)',
          alignItems: 'center',
        }}
        className="hero-grid"
      >
        {/* Left — text */}
        <HeroText reducedMotion={reducedMotion} />

        {/* Right — live scan panel */}
        <div
          className="hero-scan-panel"
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 16,
          }}
        >
          {/* Decorative label above panel */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 10,
              fontSize: 11,
              fontWeight: 700,
              color: theme.textMuted,
              letterSpacing: '1.5px',
              textTransform: 'uppercase',
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            <span
              style={{
                display: 'inline-block',
                width: 28,
                height: 1,
                background: `linear-gradient(to right, transparent, ${theme.primary}88)`,
              }}
            />
            Gerçek Zamanlı Tehdit Taraması
          </div>
          <LiveScanPanel />
        </div>
      </div>

      {/* Responsive styles */}
      <style>{`
        @media (max-width: 900px) {
          .hero-grid {
            grid-template-columns: 1fr !important;
          }
          .hero-scan-panel {
            display: none !important;
          }
        }
        @media (max-width: 480px) {
          .hero-grid {
            padding-left: 18px !important;
            padding-right: 18px !important;
          }
        }
      `}</style>
    </header>
  )
}
