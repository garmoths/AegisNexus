import { Suspense, lazy, useEffect, useMemo, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { BrainCircuit, RadioTower, ShieldCheck, FileBadge2, LockKeyhole, ChartBarBig } from 'lucide-react'
import logoImg from './assets/logo.png'
import HeroSection from './components/home/HeroSection'
import SectionDivider from './components/SectionDivider'
import SecurityModulesScrollSection from './sections/SecurityModulesScrollSection'
import PlatformStatsHorizontalSection from './sections/PlatformStatsHorizontalSection'
import KpiCountersSection from './sections/KpiCountersSection'
import { theme } from './theme'
import { MODULES_URL, HOME_URL } from './lib/links'
import { why } from './data/landing'
import useActiveSection from './hooks/useActiveSection'

const ThreatLandscapeLive = lazy(() => import('./sections/ThreatLandscapeLive'))
const CaseStudiesShowcase = lazy(() => import('./sections/CaseStudiesShowcase'))
const IncidentTimeline = lazy(() => import('./sections/IncidentTimeline'))
const Testimonials = lazy(() => import('./sections/Testimonials'))
const ContactCTA = lazy(() => import('./sections/ContactCTA'))

const API = '/api/v2'

const NAV_LINKS = [
  { id: 'modules', label: 'Modüller', glyph: '⬡' },
  { id: 'path', label: 'Akış', glyph: '◈' },
  { id: 'cases', label: 'Vakalar', glyph: '△' },
  { id: 'timeline', label: 'Süreç', glyph: '◇' },
  { id: 'contact', label: 'İletişim', glyph: '⎔' },
]

const NAV_FONT_FAMILY = 'ui-monospace, SFMono-Regular, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace'

function SectionFallback({ minHeight = 320 }) {
  return (
    <div style={{ minHeight, display: 'grid', placeItems: 'center', color: theme.textMuted, fontSize: 13 }}>
      Yükleniyor…
    </div>
  )
}

function GlowButton({ children, onClick, variant = 'primary', as = 'button', href, style }) {
  const Tag = as
  const baseStyle = {
    padding: '14px 32px',
    borderRadius: theme.radius.sm,
    border: variant === 'primary' ? 'none' : `1px solid ${theme.primary}55`,
    cursor: 'pointer',
    fontSize: 14,
    fontWeight: 700,
    letterSpacing: '0.5px',
    background: variant === 'primary' ? theme.gradientPrimary : 'transparent',
    color: variant === 'primary' ? '#000' : theme.primary,
    transition: 'transform 220ms ease, box-shadow 220ms ease',
    boxShadow: variant === 'primary' ? '0 4px 20px rgba(0,212,255,0.3)' : 'none',
    textDecoration: 'none',
    display: 'inline-flex',
    alignItems: 'center',
    gap: 8,
    ...style,
  }
  return (
    <Tag
      onClick={onClick}
      href={href}
      style={baseStyle}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform = 'translateY(-2px)'
        e.currentTarget.style.boxShadow =
          variant === 'primary' ? '0 8px 30px rgba(0,212,255,0.4)' : `0 8px 30px ${theme.primary}33`
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform = 'none'
        e.currentTarget.style.boxShadow = variant === 'primary' ? '0 4px 20px rgba(0,212,255,0.3)' : 'none'
      }}
    >
      {children}
    </Tag>
  )
}


function NavLink({ item, active, onClick, reducedMotion }) {
  const isActive = active === item.id

  return (
    <motion.button
      type="button"
      onClick={() => onClick(item.id)}
      initial={false}
      whileHover={reducedMotion ? undefined : 'hover'}
      whileFocus={reducedMotion ? undefined : 'hover'}
      animate={isActive ? 'hover' : 'rest'}
      style={{
        position: 'relative',
        display: 'inline-flex',
        alignItems: 'center',
        gap: 8,
        padding: '8px 12px',
        background: 'transparent',
        border: '1px solid transparent',
        borderRadius: 10,
        cursor: 'pointer',
        color: isActive ? theme.primary : theme.textMuted,
        fontSize: 13,
        fontWeight: 600,
        letterSpacing: '0.04em',
        fontFamily: NAV_FONT_FAMILY,
        fontFeatureSettings: '"tnum" 1',
        transition: 'color 200ms ease, background 200ms ease, border-color 200ms ease',
      }}
      onMouseEnter={(e) => {
        if (isActive) return
        e.currentTarget.style.color = theme.primary
        e.currentTarget.style.background = theme.primaryDim
        e.currentTarget.style.borderColor = `${theme.primary}33`
      }}
      onMouseLeave={(e) => {
        if (isActive) return
        e.currentTarget.style.color = theme.textMuted
        e.currentTarget.style.background = 'transparent'
        e.currentTarget.style.borderColor = 'transparent'
      }}
      aria-current={isActive ? 'true' : undefined}
    >
      <motion.span
        aria-hidden
        variants={{
          rest: { rotate: 0, scale: 1 },
          hover: { rotate: 30, scale: 1.08 },
        }}
        transition={{ type: 'spring', stiffness: 320, damping: 20 }}
        style={{
          display: 'inline-block',
          color: isActive ? theme.primary : 'inherit',
          fontSize: 14,
          lineHeight: 1,
        }}
      >
        {item.glyph}
      </motion.span>
      <span style={{ position: 'relative', display: 'inline-block' }}>
        {item.label}
        <motion.span
          aria-hidden
          variants={{
            rest: { scaleX: 0 },
            hover: { scaleX: 1 },
          }}
          transition={{ duration: 0.32, ease: [0.22, 1, 0.36, 1] }}
          style={{
            position: 'absolute',
            left: 0,
            right: 0,
            bottom: -4,
            height: 2,
            background: theme.primary,
            transformOrigin: 'left center',
            borderRadius: 2,
            boxShadow: `0 0 8px ${theme.primary}80`,
          }}
        />
      </span>
      {isActive && (
        <motion.span
          aria-hidden
          layoutId="nav-active-pulse"
          style={{
            position: 'absolute',
            inset: 0,
            borderRadius: 10,
            border: `1px solid ${theme.primary}33`,
            background: theme.primaryDim,
            pointerEvents: 'none',
          }}
        />
      )}
    </motion.button>
  )
}

function Navbar({ scrolled, scrollTo, mobileOpen, setMobileOpen, activeId, reducedMotion }) {
  return (
    <nav
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        zIndex: 1000,
        background: scrolled ? 'rgba(8,12,20,0.92)' : 'rgba(8,12,20,0.55)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: `1px solid ${scrolled ? theme.border : 'transparent'}`,
        transition: 'background 220ms ease, border-color 220ms ease',
        padding: '0 24px',
      }}
    >
      <div
        style={{
          maxWidth: 1280,
          margin: '0 auto',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: 70,
        }}
      >
        <a
          href={HOME_URL}
          aria-label="AegisNexus ana sayfa"
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 12,
            textDecoration: 'none',
            cursor: 'pointer',
            color: '#fff',
          }}
        >
          <img src={logoImg} alt="AegisNexus" width={40} height={40} style={{ objectFit: 'contain', display: 'block' }} />
          <span style={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.5px' }}>
            Aegis<span style={{ color: theme.primary }}>Nexus</span>
          </span>
          <span style={{ fontSize: 10, fontWeight: 700, color: theme.primary, background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)', borderRadius: 6, padding: '3px 8px', letterSpacing: '2px', textTransform: 'uppercase', marginLeft: 2 }}>Ana Sayfa</span>
        </a>
        <div className="nav-desktop" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {NAV_LINKS.map((item) => (
            <NavLink
              key={item.id}
              item={item}
              active={activeId}
              onClick={scrollTo}
              reducedMotion={reducedMotion}
            />
          ))}
          <a
            href={MODULES_URL}
            style={{
              marginLeft: 14,
              padding: '10px 22px',
              borderRadius: theme.radius.sm,
              fontSize: 13,
              fontWeight: 700,
              fontFamily: NAV_FONT_FAMILY,
              letterSpacing: '0.04em',
              background: theme.gradientPrimary,
              color: '#000',
              textDecoration: 'none',
              boxShadow: '0 4px 20px rgba(0,212,255,0.3)',
              transition: 'transform 220ms ease, box-shadow 220ms ease',
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = 'translateY(-2px)'
              e.currentTarget.style.boxShadow = '0 8px 30px rgba(0,212,255,0.4)'
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = 'none'
              e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,212,255,0.3)'
            }}
          >
            Panele Git →
          </a>
        </div>
        <button
          type="button"
          onClick={() => setMobileOpen((v) => !v)}
          aria-label="Menüyü aç/kapat"
          aria-expanded={mobileOpen}
          className="nav-mobile-toggle"
          style={{
            display: 'none',
            background: 'none',
            border: `1px solid ${theme.border}`,
            color: '#fff',
            width: 40,
            height: 40,
            borderRadius: 10,
            cursor: 'pointer',
            fontFamily: NAV_FONT_FAMILY,
          }}
        >
          {mobileOpen ? '✕' : '☰'}
        </button>
      </div>
      {mobileOpen && (
        <div
          className="nav-mobile-panel"
          style={{
            display: 'none',
            padding: '12px 0 18px',
            borderTop: `1px solid ${theme.border}`,
            flexDirection: 'column',
            gap: 6,
          }}
        >
          {NAV_LINKS.map((item) => {
            const isActive = activeId === item.id
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  scrollTo(item.id)
                  setMobileOpen(false)
                }}
                style={{
                  background: isActive ? theme.primaryDim : 'none',
                  border: isActive ? `1px solid ${theme.primary}33` : '1px solid transparent',
                  color: isActive ? theme.primary : theme.text,
                  textAlign: 'left',
                  padding: '12px 14px',
                  fontSize: 15,
                  fontWeight: 600,
                  letterSpacing: '0.04em',
                  fontFamily: NAV_FONT_FAMILY,
                  borderRadius: 10,
                  cursor: 'pointer',
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 10,
                }}
                aria-current={isActive ? 'true' : undefined}
              >
                <span aria-hidden style={{ fontSize: 16 }}>{item.glyph}</span>
                {item.label}
              </button>
            )
          })}
          <a
            href={MODULES_URL}
            style={{
              marginTop: 8,
              padding: '12px 16px',
              borderRadius: theme.radius.sm,
              background: theme.gradientPrimary,
              color: '#000',
              textDecoration: 'none',
              fontWeight: 700,
              fontFamily: NAV_FONT_FAMILY,
              letterSpacing: '0.04em',
              textAlign: 'center',
            }}
          >
            Panele Git →
          </a>
        </div>
      )}
      <style>{`
        @media (max-width: 880px) {
          .nav-desktop { display: none !important; }
          .nav-mobile-toggle { display: inline-flex !important; align-items: center; justify-content: center; }
          .nav-mobile-panel { display: flex !important; }
        }
      `}</style>
    </nav>
  )
}

const WHY_ICONS = [
  { Icon: BrainCircuit, color: '#06b6d4' },
  { Icon: RadioTower,   color: '#3b82f6' },
  { Icon: ShieldCheck,  color: '#6366f1' },
  { Icon: FileBadge2,   color: '#06b6d4' },
  { Icon: LockKeyhole,  color: '#3b82f6' },
  { Icon: ChartBarBig,  color: '#8b5cf6' },
]

function WhySection() {
  return (
    <section style={{ padding: '80px 24px', maxWidth: 1220, margin: '0 auto' }}>
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
            marginBottom: 16,
          }}
        >
          Neden AegisNexus
        </span>
        <h2 style={{ fontSize: 'clamp(30px, 3.8vw, 42px)', fontWeight: 820, color: '#fff', letterSpacing: '-1px' }}>
          Kurumsal güvenlik kalkanı, <span style={{ color: theme.primary }}>KOBİ'ye uygun fiyatta</span>
        </h2>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 18 }}>
        {why.map((item, i) => {
          const { Icon, color } = WHY_ICONS[i] ?? { Icon: ShieldCheck, color: theme.primary }
          return (
            <div
              key={item.title}
              className="why-card"
              style={{
                padding: 24,
                borderRadius: theme.radius.lg,
                background: theme.gradientSurface,
                border: `1px solid ${theme.border}`,
                transition: 'transform 220ms ease, border-color 220ms ease',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.transform = 'translateY(-4px)'
                e.currentTarget.style.borderColor = `${color}66`
                const wrapper = e.currentTarget.querySelector('.why-icon-wrap')
                if (wrapper) {
                  wrapper.style.transform = 'scale(1.08)'
                  wrapper.style.boxShadow = `0 0 24px ${color}4d`
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.transform = 'none'
                e.currentTarget.style.borderColor = theme.border
                const wrapper = e.currentTarget.querySelector('.why-icon-wrap')
                if (wrapper) {
                  wrapper.style.transform = 'none'
                  wrapper.style.boxShadow = `0 0 12px ${color}1f`
                }
              }}
            >
              <div
                className="why-icon-wrap"
                aria-hidden
                style={{
                  width: 56,
                  height: 56,
                  borderRadius: 14,
                  background: `linear-gradient(135deg, ${color}26 0%, ${color}14 100%)`,
                  border: `1px solid ${color}40`,
                  boxShadow: `0 0 12px ${color}1f, inset 0 1px 0 rgba(255,255,255,0.06)`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  marginBottom: 16,
                  transition: 'transform 220ms ease, box-shadow 220ms ease',
                }}
              >
                <Icon size={26} strokeWidth={1.5} color={color} />
              </div>
              <h3 style={{ fontSize: 18, fontWeight: 750, color: '#fff', marginBottom: 8 }}>{item.title}</h3>
              <p style={{ fontSize: 14, color: theme.textMuted, lineHeight: 1.7 }}>{item.desc}</p>
            </div>
          )
        })}
      </div>
    </section>
  )
}

function Footer() {
  return (
    <footer style={{ borderTop: `1px solid ${theme.border}`, padding: '32px 24px', color: theme.textMuted, fontSize: 13 }}>
      <div style={{ maxWidth: 1220, margin: '0 auto', display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: 18, alignItems: 'center' }}>
        <p>AegisNexus — Enterprise Cybersecurity Platform &copy; {new Date().getFullYear()}</p>
        <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap' }}>
          <a href={`${API}/docs`} style={{ color: theme.textMuted, textDecoration: 'none' }} target="_blank" rel="noreferrer">
            API Docs
          </a>
          <a
            href={MODULES_URL}
            style={{ color: theme.primary, textDecoration: 'none' }}
            target="_blank"
            rel="noreferrer"
          >
            Modül Paneli →
          </a>
        </div>
      </div>
    </footer>
  )
}

export default function LandingPage() {
  const reducedMotion = useReducedMotion() ?? false
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const navIds = useMemo(() => NAV_LINKS.map((item) => item.id), [])
  const activeId = useActiveSection(navIds)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const scrollTo = (id) =>
    document.getElementById(id)?.scrollIntoView({
      behavior: reducedMotion ? 'auto' : 'smooth',
      block: 'start',
    })

  return (
    <div style={{ minHeight: '100vh', background: theme.bg, color: theme.text, position: 'relative' }}>
      <Navbar
        scrolled={scrolled}
        scrollTo={scrollTo}
        mobileOpen={mobileOpen}
        setMobileOpen={setMobileOpen}
        activeId={activeId}
        reducedMotion={reducedMotion}
      />

      <main>
        <HeroSection reducedMotion={reducedMotion} />
        <SectionDivider height={120} toColor={theme.bg} />

        <KpiCountersSection />
        <SectionDivider height={80} toColor={theme.bg} />

        <SecurityModulesScrollSection />
        <SectionDivider height={80} toColor={theme.bg} />

        <PlatformStatsHorizontalSection />
        <SectionDivider height={100} toColor={theme.bg} />

        <Suspense fallback={<SectionFallback />}>
          <ThreatLandscapeLive />
        </Suspense>
        <SectionDivider height={80} toColor={theme.bg} />

        <Suspense fallback={<SectionFallback />}>
          <CaseStudiesShowcase />
        </Suspense>
        <SectionDivider height={80} toColor={theme.bg} />

        <Suspense fallback={<SectionFallback />}>
          <IncidentTimeline />
        </Suspense>

        <Suspense fallback={<SectionFallback />}>
          <Testimonials />
        </Suspense>
        <SectionDivider height={80} toColor={theme.bg} />

        <WhySection />

        <Suspense fallback={<SectionFallback />}>
          <ContactCTA />
        </Suspense>
      </main>

      <Footer />
    </div>
  )
}
