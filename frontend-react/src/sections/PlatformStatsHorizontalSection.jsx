import { useRef, useState, useEffect } from 'react'
import { useGSAP } from '@gsap/react'
import gsap from 'gsap'
import { ScrollTrigger } from 'gsap/ScrollTrigger'
import { theme } from '../theme'
import { platformPath } from '../data/landing'

gsap.registerPlugin(ScrollTrigger)

const STEP_COLORS = ['#00E5CC', '#9B5CF6', '#4A5568', '#F59E0B', '#10B981']

function StepCard({ step, index }) {
  const color = STEP_COLORS[index % STEP_COLORS.length]

  return (
    <div className="step-wrapper" style={{ flexShrink: 0, width: '500px', position: 'relative' }}>
      <div className="step-card" style={{
        background: 'linear-gradient(180deg, rgba(15,22,41,0.95) 0%, rgba(10,14,22,0.9) 100%)',
        border: `1px solid ${color}33`,
        borderRadius: 24,
        padding: 'clamp(24px, 3vw, 36px)',
        boxShadow: `0 20px 60px rgba(0,0,0,0.4), 0 0 0 1px ${color}11 inset`,
        minHeight: 'min(60vh, 480px)',
        display: 'flex',
        flexDirection: 'column',
        gap: 20,
      }}>
        <div
          className="step-number"
          style={{
            fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
            fontSize: 'clamp(48px, 6vw, 72px)',
            fontWeight: 600,
            color: color,
            letterSpacing: '-0.04em',
            lineHeight: 1,
          }}
        >
          {step.num}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 12 }}>
          <h3
            style={{
              color: '#fff',
              fontSize: 'clamp(24px, 3vw, 32px)',
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
              fontSize: 'clamp(14px, 1.5vw, 16px)',
              lineHeight: 1.75,
            }}
          >
            {step.desc}
          </p>
        </div>

        <div style={{ marginTop: 'auto', height: 1, background: `linear-gradient(90deg, transparent, ${color}80, transparent)` }} />
      </div>
    </div>
  )
}

export default function PlatformStatsHorizontalSection() {
  const sectionRef = useRef(null)
  const trackRef = useRef(null)
  const [isMobile, setIsMobile] = useState(false)

  useEffect(() => {
    const checkMobile = () => setIsMobile(window.innerWidth < 768)
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  // Mobile fallback - dikey liste
  if (isMobile) {
    return (
      <section
        id="path"
        style={{
          padding: 'clamp(60px, 10vw, 120px) 0',
          position: 'relative',
        }}
      >
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
              Sinyal almaktan olayı kapatmaya — AegisNexus'un 5 adımlık operasyon döngüsü mevcut araçlarınıza entegre olur, ekibinizin manuel yükünü otomasyona devreder ve her aksiyonu denetlenebilir kanıt zinciriyle kayıt altına alır.
            </p>
          </header>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
            {platformPath.map((step, i) => (
              <div key={step.num} style={{ padding: '24px', background: 'rgba(15,22,41,0.5)', borderRadius: 16, border: `1px solid ${STEP_COLORS[i % STEP_COLORS.length]}33` }}>
                <div style={{ fontFamily: 'ui-monospace, monospace', fontSize: 32, color: STEP_COLORS[i % STEP_COLORS.length], marginBottom: 12 }}>{step.num}</div>
                <h3 style={{ color: '#fff', fontSize: 20, fontWeight: 700, marginBottom: 8 }}>{step.title}</h3>
                <p style={{ color: theme.textMuted, lineHeight: 1.6 }}>{step.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    )
  }

  // Desktop - GSAP horizontal scroll
  useGSAP(() => {
    const track = trackRef.current
    const totalWidth = track.scrollWidth - window.innerWidth

    // Ana yatay hareket
    const mainTween = gsap.to(track, {
      x: -totalWidth,
      ease: 'none',
      scrollTrigger: {
        trigger: sectionRef.current,
        pin: true,
        scrub: 1.5,
        start: 'top top',
        end: () => `+=${totalWidth}`,
        endTrigger: sectionRef.current,
        invalidateOnRefresh: true,
        anticipatePin: 1,
        onEnter: () => window.dispatchEvent(new CustomEvent('gsap-section-enter', { detail: 'path' })),
        onLeave: () => window.dispatchEvent(new CustomEvent('gsap-section-leave', { detail: 'path' })),
        onEnterBack: () => window.dispatchEvent(new CustomEvent('gsap-section-enter', { detail: 'path' })),
        onLeaveBack: () => window.dispatchEvent(new CustomEvent('gsap-section-leave', { detail: 'path' })),
      },
    })

    // Kart animasyonları
    gsap.utils.toArray('.step-wrapper').forEach((step) => {
      gsap.from(step.querySelector('.step-number'), {
        opacity: 0,
        scale: 1.6,
        filter: 'blur(16px)',
        duration: 0.8,
        ease: 'power3.out',
        scrollTrigger: {
          trigger: step,
          containerAnimation: mainTween,
          start: 'left 85%',
          toggleActions: 'play none none reverse',
        },
      })

      gsap.from(step.querySelector('.step-card'), {
        opacity: 0,
        y: 50,
        duration: 0.9,
        ease: 'back.out(1.2)',
        scrollTrigger: {
          trigger: step,
          containerAnimation: mainTween,
          start: 'left 70%',
          toggleActions: 'play none none reverse',
        },
      })
    })

    return () => {
      ScrollTrigger.getAll().forEach(t => t.kill())
    }
  }, { scope: sectionRef })

  return (
    <section
      ref={sectionRef}
      id="path"
      className="flow-section"
      style={{
        height: '100vh',
        overflow: 'hidden',
        position: 'relative',
        background: '#060C18',
        backgroundImage: `
          linear-gradient(rgba(0,229,204,0.04) 1px, transparent 1px),
          linear-gradient(90deg, rgba(0,229,204,0.04) 1px, transparent 1px)
        `,
        backgroundSize: '60px 60px',
      }}
    >
      {/* Radar sonar arka plan animasyonu */}
      <div aria-hidden style={{ position: 'absolute', top: 60, left: '50%', transform: 'translateX(-50%)', width: 280, height: 280, opacity: 0.08, pointerEvents: 'none', zIndex: 0 }}>
        {[0, 1, 2].map((i) => (
          <div key={i} style={{ position: 'absolute', inset: 0, borderRadius: '50%', border: '1px solid #00D4FF', animation: 'radarPulse 3s ease-out infinite', animationDelay: `${i}s` }} />
        ))}
        <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)', width: 6, height: 6, borderRadius: '50%', background: '#FF3366', animation: 'threatDot 1.5s ease-in-out infinite' }} />
      </div>
      <style>{`
        @keyframes radarPulse {
          0%   { transform: scale(0.25); opacity: 0.6; }
          100% { transform: scale(1.9);  opacity: 0; }
        }
        @keyframes threatDot {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.3; }
        }
      `}</style>
      <div
        ref={trackRef}
        className="horizontal-track"
        style={{
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          height: '100%',
          width: 'max-content',
          padding: '60px 30vw 0 6vw',
          gap: '8vw',
          willChange: 'transform',
        }}
      >
        <div style={{ flexShrink: 0, width: '760px', paddingRight: '4vw' }}>
          <header>
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
              Sinyal almaktan olayı kapatmaya — AegisNexus'un 5 adımlık operasyon döngüsü mevcut araçlarınıza entegre olur, ekibinizin manuel yükünü otomasyona devreder ve her aksiyonu denetlenebilir kanıt zinciriyle kayıt altına alır.
            </p>
          </header>
        </div>
        {platformPath.map((step, i) => (
          <StepCard key={step.num} step={step} index={i} />
        ))}
      </div>
    </section>
  )
}
