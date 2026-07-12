import { useCallback, useRef } from 'react'
import { motion, useScroll, useTransform, useReducedMotion } from 'framer-motion'
import { Bot, ScanLine, Network, Database, Lock } from 'lucide-react'
import { theme } from '../theme'
import { modules as moduleCards } from '../data/landing'

const MODULE_ICONS = [Bot, ScanLine, Network, Database, Lock]

// nmore.com esintili "deck of cards" sticky stack:
//  - Her kart kendi sticky offset'inde durur (başlık + önceki kart peek'leri görünür kalır)
//  - Bir sonraki kart geldiğinde altta kalan kart hafifçe scale + opacity düşer
//  - Tüm wrapper sadece N * cardScroll kadar yüksekliğe sahiptir → kısa scroll
//  - Kartlara tıklayınca / Enter/Space basınca bir sonraki kartın sticky pozisyonuna kaydırılır.
function StackingModuleCard({
  item,
  index,
  total,
  peek,
  headerOffset,
  cardHeightVh,
  prefersReducedMotion,
  onAdvance,
  registerRef,
}) {
  const localRef = useRef(null)

  const setRef = (node) => {
    localRef.current = node
    registerRef(index, node)
  }

  const { scrollYProgress } = useScroll({
    target: localRef,
    offset: ['start start', 'end start'],
  })

  // İlk yarıda kart aktif (1.0), ikinci yarıda yığına geri kayar (0.96).
  const scale = useTransform(scrollYProgress, [0, 0.5, 1], [1, 1, 0.96])
  const opacity = useTransform(scrollYProgress, [0, 0.55, 1], [1, 1, 0.78])

  const stickyTop = `calc(${headerOffset}px + ${index} * ${peek}px)`
  const isLast = index === total - 1
  const hint = isLast ? 'Sonraki bölüm →' : 'İleri →'
  const ariaLabel = isLast
    ? `${item.title} — sonraki bölüme geç`
    : `${item.title} — sonraki modüle geç`

  const articleStyle = prefersReducedMotion
    ? {
        position: 'relative',
        marginBottom: 24,
        height: 'auto',
      }
    : {
        position: 'sticky',
        top: stickyTop,
        height: `${cardHeightVh}vh`,
        zIndex: 10 + index,
      }

  const handleKeyDown = (event) => {
    if (event.key === 'Enter' || event.key === ' ' || event.key === 'Spacebar') {
      event.preventDefault()
      onAdvance(index + 1)
    }
  }

  return (
    <article
      ref={setRef}
      style={{
        ...articleStyle,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'flex-start',
        padding: '0 24px',
      }}
    >
      <motion.div
        role="button"
        tabIndex={0}
        aria-label={ariaLabel}
        onClick={() => onAdvance(index + 1)}
        onKeyDown={handleKeyDown}
        whileHover={prefersReducedMotion ? undefined : { y: -4 }}
        transition={{ type: 'spring', stiffness: 260, damping: 22 }}
        style={prefersReducedMotion
          ? { cursor: 'pointer', outline: 'none' }
          : { scale, opacity, cursor: 'pointer', outline: 'none' }}
      >
        <div
          className="module-card-shell"
          style={{
            width: 'min(960px, 92vw)',
            background: 'linear-gradient(180deg, #0e1320 0%, #0a0f1a 100%)',
            border: `1px solid ${item.color}33`,
            borderRadius: 24,
            boxShadow: `0 24px 60px rgba(0,0,0,0.55), 0 0 0 1px ${item.color}11 inset`,
            padding: 'clamp(28px, 3vw, 44px)',
            display: 'flex',
            flexDirection: 'column',
            gap: 18,
            minHeight: 'min(58vh, 460px)',
            transition: 'border-color 220ms ease, box-shadow 220ms ease',
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.borderColor = `${item.color}88`
            e.currentTarget.style.boxShadow = `0 28px 70px rgba(0,0,0,0.6), 0 0 0 1px ${item.color}33 inset, 0 0 30px ${item.color}22`
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.borderColor = `${item.color}33`
            e.currentTarget.style.boxShadow = `0 24px 60px rgba(0,0,0,0.55), 0 0 0 1px ${item.color}11 inset`
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 18, alignItems: 'flex-start', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div
                style={{
                  width: 64,
                  height: 64,
                  borderRadius: 18,
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: `linear-gradient(135deg, ${item.color}26 0%, ${item.color}14 100%)`,
                  border: `1px solid ${item.color}40`,
                  boxShadow: `0 0 14px ${item.color}22, inset 0 1px 0 rgba(255,255,255,0.06)`,
                  flexShrink: 0,
                }}
                aria-hidden="true"
              >
                {(() => { const Icon = MODULE_ICONS[index] ?? Lock; return <Icon size={30} strokeWidth={1.5} color={item.color} /> })()}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: theme.textMuted, letterSpacing: 1.2 }}>
                    0{index + 1}/{String(total).padStart(2, '0')}
                  </span>
                  <span style={{ width: 4, height: 4, borderRadius: 4, background: theme.borderSoft || '#26314a' }} />
                  <span style={{ color: item.color, fontSize: 11, textTransform: 'uppercase', letterSpacing: '1.4px', fontWeight: 700 }}>
                    {item.subtitle}
                  </span>
                </div>
                <h3
                  style={{
                    color: '#fff',
                    fontWeight: 800,
                    fontSize: 'clamp(24px, 3vw, 34px)',
                    letterSpacing: '-0.8px',
                    marginTop: 6,
                  }}
                >
                  {item.title}
                </h3>
              </div>
            </div>
            <span
              style={{
                padding: '6px 12px',
                borderRadius: 20,
                fontSize: 11,
                fontWeight: 700,
                background: `${item.color}22`,
                color: item.color,
                border: `1px solid ${item.color}66`,
                whiteSpace: 'nowrap',
              }}
            >
              {item.badge}
            </span>
          </div>

          <p
            style={{
              color: theme.textMuted,
              lineHeight: 1.75,
              fontSize: 'clamp(14px, 1.6vw, 17px)',
              maxWidth: 760,
            }}
          >
            {item.desc}
          </p>

          <div style={{ marginTop: 'auto', height: 1, background: `linear-gradient(90deg, transparent, ${item.color}80, transparent)` }} />

          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', gap: 8 }}>
              {[...Array(total)].map((_, i) => (
                <span
                  key={i}
                  style={{
                    width: i === index ? 28 : 8,
                    height: 6,
                    borderRadius: 4,
                    background: i === index ? item.color : '#1c2336',
                    transition: 'all .25s ease',
                  }}
                />
              ))}
            </div>
            <span
              aria-hidden
              style={{
                marginLeft: 'auto',
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '6px 12px',
                borderRadius: 999,
                fontSize: 12,
                fontWeight: 700,
                color: item.color,
                background: `${item.color}14`,
                border: `1px solid ${item.color}40`,
                fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
                letterSpacing: '0.04em',
              }}
            >
              {hint}
            </span>
          </div>
        </div>
      </motion.div>
    </article>
  )
}

export default function SecurityModulesScrollSection() {
  const prefersReducedMotion = useReducedMotion() ?? false

  // Sticky stack ayarları
  const peek = 18           // Her kart için bırakılan görünür offset (px)
  const headerOffset = 110  // Üstteki sticky başlık + navbar payı (px)
  const cardHeightVh = 70   // Her kart için ayrılan scroll yüksekliği

  const articleRefs = useRef([])

  const registerRef = useCallback((index, node) => {
    articleRefs.current[index] = node
  }, [])

  const advance = useCallback(
    (nextIndex) => {
      const total = moduleCards.length
      const behavior = prefersReducedMotion ? 'auto' : 'smooth'

      if (nextIndex >= total) {
        const target = document.getElementById('path')
        if (target) {
          target.scrollIntoView({ behavior, block: 'start' })
        }
        return
      }

      const nextEl = articleRefs.current[nextIndex]
      if (!nextEl) return
      const stickyTop = headerOffset + nextIndex * peek
      const top =
        nextEl.getBoundingClientRect().top + window.scrollY - stickyTop + 8
      window.scrollTo({ top, behavior })
    },
    [prefersReducedMotion]
  )

  return (
    <section id="modules" style={{ padding: '0', position: 'relative' }}>
      {/* Konsantrik halka arka plan */}
      <div aria-hidden style={{ position: 'absolute', inset: 0, pointerEvents: 'none', overflow: 'hidden', zIndex: 0 }}>
        {[1000, 800, 600, 400, 200].map((size, i) => (
          <div
            key={size}
            style={{
              position: 'absolute',
              width: size,
              height: size,
              borderRadius: '50%',
              border: '1px solid rgba(0, 212, 255, 0.06)',
              top: '50%',
              right: '-5%',
              transform: 'translateY(-50%)',
              animation: `ringPulse ${4 + i * 0.6}s ease-in-out infinite`,
              animationDelay: `${i * 0.8}s`,
            }}
          />
        ))}
      </div>
      <style>{`
        @keyframes ringPulse {
          0%, 100% { opacity: 0.06; }
          50%       { opacity: 0.16; }
        }
      `}</style>
      <div
        style={{
          maxWidth: 980,
          margin: '0 auto',
          padding: '60px 24px 28px',
          textAlign: 'center',
          position: 'relative',
          zIndex: 1,
        }}
      >
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
            marginBottom: 18,
          }}
        >
          Modüller
        </span>
        <h2
          style={{
            fontSize: 'clamp(34px, 4vw, 48px)',
            fontWeight: 820,
            color: '#fff',
            letterSpacing: '-1.2px',
          }}
        >
          Güvenlik <span style={{ color: theme.primary }}>Modülleri</span>
        </h2>
        <p
          style={{
            color: theme.textMuted,
            maxWidth: 680,
            margin: '14px auto 0',
            lineHeight: 1.7,
            fontSize: 16,
          }}
        >
          5 katmanlı koruma mimarimizdeki her modül; ayrı ayrı çalışabildiği gibi, ortak telemetri katmanı üzerinden birbirini güçlendirir. Karta sol tıklayarak veya <kbd style={{ padding: '1px 6px', borderRadius: 4, background: theme.surface, border: `1px solid ${theme.border}`, fontFamily: 'ui-monospace, monospace', fontSize: 12 }}>Enter</kbd> ile bir sonraki modüle geçebilirsiniz.
        </p>
      </div>

      <div
        style={{
          maxWidth: 1200,
          margin: '0 auto',
          paddingBottom: prefersReducedMotion ? 60 : '12vh',
        }}
      >
        {moduleCards.map((item, index) => (
          <StackingModuleCard
            key={item.title}
            item={item}
            index={index}
            total={moduleCards.length}
            peek={peek}
            headerOffset={headerOffset}
            cardHeightVh={cardHeightVh}
            prefersReducedMotion={prefersReducedMotion}
            onAdvance={advance}
            registerRef={registerRef}
          />
        ))}
      </div>
    </section>
  )
}
