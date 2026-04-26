import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { theme } from '../theme'

// Eski "Topluluğa Katıl" gradient kart bloğunun yerine geçen bütünleşik
// iletişim bölümü. Sol sütunda iletişim özet kartı (e-posta, GitHub,
// yanıt süresi rozeti), sağ sütunda klasik iletişim formu yer alır.
// Honeypot + min-time check + e-posta regex doğrulaması korunur.

export default function ContactCTA() {
  const prefersReducedMotion = useReducedMotion() ?? false

  const [email, setEmail] = useState('')
  const [message, setMessage] = useState('')
  const [status, setStatus] = useState({ type: 'idle', text: '' })
  const honeypotRef = useRef(null)
  const mountedAtRef = useRef(0)

  useEffect(() => {
    mountedAtRef.current = performance.now()
  }, [])

  const submit = (e) => {
    e.preventDefault()
    if (status.type === 'loading') return
    if (honeypotRef.current?.value) {
      setStatus({ type: 'success', text: 'Teşekkürler! Yakında dönüş yapacağız.' })
      return
    }
    if (performance.now() - mountedAtRef.current < 1500) {
      setStatus({ type: 'error', text: 'Lütfen formu biraz daha okuyup gönderiniz.' })
      return
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
      setStatus({ type: 'error', text: 'Geçerli bir e-posta adresi giriniz.' })
      return
    }
    if (message.trim().length < 10) {
      setStatus({ type: 'error', text: 'Mesajınız en az 10 karakter olmalı.' })
      return
    }
    setStatus({ type: 'loading', text: '' })
    setTimeout(() => {
      setStatus({ type: 'success', text: 'Mesajınız bize ulaştı. En kısa sürede dönüş yapacağız.' })
      setEmail('')
      setMessage('')
    }, 600)
  }

  return (
    <section
      id="contact"
      style={{
        padding: 'clamp(60px, 9vw, 110px) 24px',
        position: 'relative',
      }}
    >
      <div style={{ maxWidth: 1180, margin: '0 auto' }}>
        <motion.div
          initial={prefersReducedMotion ? false : { opacity: 0, y: 24 }}
          whileInView={prefersReducedMotion ? undefined : { opacity: 1, y: 0 }}
          viewport={{ once: true, margin: '-10% 0px' }}
          transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
          style={{
            position: 'relative',
            borderRadius: 28,
            overflow: 'hidden',
            background: theme.gradientSurface,
            border: `1px solid ${theme.border}`,
            boxShadow: '0 30px 80px rgba(0,0,0,0.45), 0 0 0 1px rgba(0,212,255,0.08) inset',
          }}
        >
          {/* Hero gradient katman */}
          <div
            aria-hidden
            style={{
              position: 'absolute',
              inset: 0,
              background: theme.gradientHero,
              pointerEvents: 'none',
            }}
          />
          {/* Grid pattern dokusu */}
          <div
            aria-hidden
            style={{
              position: 'absolute',
              inset: 0,
              backgroundImage: theme.gridPattern,
              backgroundSize: theme.gridPatternSize,
              maskImage: 'radial-gradient(ellipse at 50% 50%, #000 30%, transparent 75%)',
              WebkitMaskImage: 'radial-gradient(ellipse at 50% 50%, #000 30%, transparent 75%)',
              opacity: 0.4,
              pointerEvents: 'none',
            }}
          />
          {/* Glow */}
          <div
            aria-hidden
            style={{
              position: 'absolute',
              top: -120,
              left: '50%',
              transform: 'translateX(-50%)',
              width: 520,
              height: 520,
              borderRadius: '50%',
              background: 'radial-gradient(circle, rgba(0,212,255,0.18) 0%, transparent 70%)',
              filter: 'blur(40px)',
              pointerEvents: 'none',
            }}
          />

          <div
            className="contact-cta-grid"
            style={{
              position: 'relative',
              display: 'grid',
              gridTemplateColumns: '1fr 1fr',
              gap: 'clamp(24px, 4vw, 56px)',
              padding: 'clamp(32px, 5vw, 64px)',
            }}
          >
            {/* Sol: özet kartı */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              <span
                style={{
                  display: 'inline-flex',
                  alignSelf: 'flex-start',
                  alignItems: 'center',
                  gap: 8,
                  padding: '6px 14px',
                  borderRadius: 999,
                  background: theme.primaryDim,
                  border: `1px solid ${theme.primary}33`,
                  color: theme.primary,
                  fontSize: 12,
                  fontWeight: 700,
                  letterSpacing: 1.4,
                  textTransform: 'uppercase',
                }}
              >
                <span
                  style={{
                    width: 8,
                    height: 8,
                    borderRadius: '50%',
                    background: theme.success,
                    boxShadow: `0 0 10px ${theme.success}`,
                  }}
                />
                İletişim
              </span>

              <h2
                style={{
                  fontSize: 'clamp(30px, 4.4vw, 48px)',
                  fontWeight: 820,
                  color: '#fff',
                  letterSpacing: '-1.2px',
                  lineHeight: 1.05,
                }}
              >
                Pilot mu, demo mu, tek bir sorun mu?{' '}
                <span style={{ color: theme.primary }}>Bize yazın.</span>
              </h2>

              <p
                style={{
                  color: theme.text,
                  fontSize: 'clamp(15px, 1.5vw, 17px)',
                  lineHeight: 1.7,
                  maxWidth: 460,
                }}
              >
                Form bize ulaşır ulaşmaz mesajınızı SOC ekibine yönlendiriyoruz. Hafta içi 1 iş günü, hafta sonu 2 iş günü içinde detaylı bir geri dönüş alırsınız.
              </p>

              <ul
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 14,
                  margin: 0,
                  padding: 0,
                  listStyle: 'none',
                }}
              >
                <ContactRow
                  icon="📧"
                  label="E-posta"
                  value="info@aegisnexus.dev"
                  href="mailto:info@aegisnexus.dev"
                />
                <ContactRow
                  icon="🐙"
                  label="GitHub"
                  value="github.com/garmoths/AegisNexus"
                  href="https://github.com/garmoths/AegisNexus"
                />
                <ContactRow
                  icon="⏱"
                  label="Yanıt süresi"
                  value="Ortalama 1 iş günü"
                />
              </ul>

              <div
                style={{
                  marginTop: 'auto',
                  padding: '14px 18px',
                  borderRadius: 14,
                  background: 'rgba(0,212,255,0.06)',
                  border: `1px solid ${theme.primary}26`,
                  color: theme.textMuted,
                  fontSize: 13,
                  lineHeight: 1.6,
                }}
              >
                Mesajlarınız sadece dönüş için kullanılır, üçüncü taraflarla paylaşılmaz. KVKK uyumlu işleme.
              </div>
            </div>

            {/* Sağ: form */}
            <form
              onSubmit={submit}
              noValidate
              style={{
                display: 'flex',
                flexDirection: 'column',
                gap: 14,
                padding: 'clamp(20px, 3vw, 32px)',
                borderRadius: 22,
                background: 'rgba(8,12,20,0.55)',
                border: `1px solid ${theme.border}`,
                backdropFilter: 'blur(18px)',
                WebkitBackdropFilter: 'blur(18px)',
              }}
            >
              <label
                htmlFor="contact-email"
                style={{
                  fontSize: 12,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: 1.2,
                  color: theme.textMuted,
                }}
              >
                E-posta
              </label>
              <input
                id="contact-email"
                type="email"
                inputMode="email"
                autoComplete="email"
                required
                placeholder="adiniz@ornek.com"
                value={email}
                onChange={(e) => {
                  setEmail(e.target.value)
                  if (status.type !== 'idle') setStatus({ type: 'idle', text: '' })
                }}
                aria-label="E-posta"
                style={{
                  padding: '14px 18px',
                  borderRadius: theme.radius.sm,
                  background: theme.bgDeep,
                  border: `1px solid ${status.type === 'error' ? theme.danger : theme.border}`,
                  color: '#fff',
                  fontSize: 14,
                  outline: 'none',
                }}
              />

              <label
                htmlFor="contact-message"
                style={{
                  fontSize: 12,
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  letterSpacing: 1.2,
                  color: theme.textMuted,
                  marginTop: 6,
                }}
              >
                Mesajınız
              </label>
              <textarea
                id="contact-message"
                required
                placeholder="Kısaca: hangi sektör, kaç kullanıcı, hangi ihtiyaç…"
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value)
                  if (status.type !== 'idle') setStatus({ type: 'idle', text: '' })
                }}
                aria-label="Mesajınız"
                rows={5}
                style={{
                  padding: '14px 18px',
                  borderRadius: theme.radius.sm,
                  background: theme.bgDeep,
                  border: `1px solid ${status.type === 'error' ? theme.danger : theme.border}`,
                  color: '#fff',
                  fontSize: 14,
                  outline: 'none',
                  resize: 'vertical',
                  fontFamily: 'inherit',
                  minHeight: 130,
                }}
              />

              {/* Honeypot */}
              <input
                ref={honeypotRef}
                type="text"
                tabIndex={-1}
                autoComplete="off"
                aria-hidden="true"
                name="website"
                style={{ position: 'absolute', left: '-10000px', width: 1, height: 1, overflow: 'hidden' }}
              />

              <button
                type="submit"
                disabled={status.type === 'loading'}
                style={{
                  marginTop: 6,
                  padding: '14px 28px',
                  borderRadius: theme.radius.sm,
                  border: 'none',
                  cursor: status.type === 'loading' ? 'wait' : 'pointer',
                  fontSize: 14,
                  fontWeight: 700,
                  background: theme.gradientPrimary,
                  color: '#000',
                  boxShadow: '0 4px 20px rgba(0,212,255,0.3)',
                  transition: 'transform 220ms ease, box-shadow 220ms ease',
                }}
                onMouseEnter={(e) => {
                  if (status.type === 'loading') return
                  e.currentTarget.style.transform = 'translateY(-2px)'
                  e.currentTarget.style.boxShadow = '0 8px 30px rgba(0,212,255,0.4)'
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.transform = 'none'
                  e.currentTarget.style.boxShadow = '0 4px 20px rgba(0,212,255,0.3)'
                }}
              >
                {status.type === 'loading' ? 'Gönderiliyor…' : 'Gönder →'}
              </button>

              <div
                role="status"
                aria-live="polite"
                style={{ minHeight: 22, fontSize: 13, marginTop: 4 }}
              >
                {status.type === 'success' && <span style={{ color: theme.success }}>{status.text}</span>}
                {status.type === 'error' && <span style={{ color: theme.danger }}>{status.text}</span>}
              </div>

              <p style={{ fontSize: 12, color: theme.textSubtle, lineHeight: 1.6, marginTop: 4 }}>
                Gönderdiğinizde KVKK uyumlu iletişim onayı vermiş olursunuz. Pazarlama listesine eklenmezsiniz.
              </p>
            </form>
          </div>
        </motion.div>
      </div>

      <style>{`
        @media (max-width: 880px) {
          .contact-cta-grid { grid-template-columns: 1fr !important; }
        }
      `}</style>
    </section>
  )
}

function ContactRow({ icon, label, value, href }) {
  const inner = (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 14,
        padding: '12px 14px',
        borderRadius: 14,
        background: 'rgba(8,12,20,0.55)',
        border: `1px solid ${theme.border}`,
        transition: 'border-color 220ms ease, transform 220ms ease',
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = `${theme.primary}55`
        e.currentTarget.style.transform = 'translateY(-1px)'
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = theme.border
        e.currentTarget.style.transform = 'none'
      }}
    >
      <span
        aria-hidden
        style={{
          width: 36,
          height: 36,
          borderRadius: 10,
          display: 'inline-flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: theme.primaryDim,
          border: `1px solid ${theme.primary}33`,
          fontSize: 18,
        }}
      >
        {icon}
      </span>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <span style={{ fontSize: 11, fontWeight: 700, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: 1.2 }}>
          {label}
        </span>
        <span style={{ color: '#fff', fontSize: 14, fontWeight: 600, marginTop: 2 }}>{value}</span>
      </div>
    </div>
  )

  return (
    <li>
      {href ? (
        <a
          href={href}
          target={href.startsWith('http') ? '_blank' : undefined}
          rel={href.startsWith('http') ? 'noreferrer' : undefined}
          style={{ display: 'block', textDecoration: 'none' }}
        >
          {inner}
        </a>
      ) : (
        inner
      )}
    </li>
  )
}
