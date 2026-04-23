import { useState, useEffect, useRef, useCallback } from 'react'

// ============================================================
// API BASE
// ============================================================
const API = '/api/v2'

// ============================================================
// HOOKS
// ============================================================
function useCountUp(end, duration = 1500) {
  const [val, setVal] = useState(0)
  const ref = useRef(null)
  useEffect(() => {
    const start = performance.now()
    const animate = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setVal(Math.floor(eased * end))
      if (progress < 1) ref.current = requestAnimationFrame(animate)
    }
    ref.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(ref.current)
  }, [end, duration])
  return val
}

// ============================================================
// STYLE HELPERS
// ============================================================
const s = (obj) => obj

const theme = {
  bg: '#080c14',
  surface: '#0f1629',
  surface2: '#1a2342',
  border: '#1e2a4a',
  borderLight: 'rgba(30,42,74,0.5)',
  primary: '#00d4ff',
  primaryDim: 'rgba(0,212,255,0.1)',
  accent: '#ff6b35',
  accentDim: 'rgba(255,107,53,0.1)',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  text: '#e2e8f0',
  textMuted: '#64748b',
  textDim: '#475569',
  font: "'Inter', sans-serif",
  mono: "'JetBrains Mono', monospace",
  radius: '12px',
  radiusSm: '8px',
  glow: '0 0 40px rgba(0,212,255,0.08)',
}

// ============================================================
// NAVBAR
// ============================================================
function Navbar({ page, setPage }) {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const tabs = [
    { id: 'ai-analyzer', label: 'AI Analiz', icon: '🤖' },
    { id: 'phishing-detector', label: 'Phishing', icon: '🎣' },
    { id: 'honeypot', label: 'IOC / Tuzak', icon: '🕸️' },
    { id: 'breach-intel', label: 'Sızıntı', icon: '🔓' },
  ]

  return (
    <nav style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 1000,
      background: scrolled ? 'rgba(8,12,20,0.95)' : 'rgba(8,12,20,0.8)',
      backdropFilter: 'blur(20px)',
      borderBottom: `1px solid ${scrolled ? theme.border : 'transparent'}`,
      transition: 'all 0.3s ease',
      padding: '0 24px',
    }}>
      <div style={{
        maxWidth: 1400, margin: '0 auto',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        height: 70,
      }}>
        {/* Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
            <path d="M18 4L6 11V18C6 23.5 10 28.5 18 30C26 28.5 30 23.5 30 18V11L18 4Z" stroke="#00d4ff" strokeWidth="2" fill="none"/>
            <path d="M14 18L17 21L23 15" stroke="#00d4ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span style={{ fontSize: 20, fontWeight: 700, color: '#fff', letterSpacing: '-0.5px' }}>
            Aegis<span style={{ color: theme.primary }}>Nexus</span>
          </span>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 4, background: theme.surface, borderRadius: theme.radiusSm, padding: 3 }}>
          {tabs.map(t => (
            <button key={t.id} onClick={() => setPage(t.id)}
              style={{
                padding: '8px 18px', borderRadius: '6px', border: 'none', cursor: 'pointer',
                fontSize: 13, fontWeight: 600,
                background: page === t.id ? theme.primary : 'transparent',
                color: page === t.id ? '#000' : theme.textMuted,
                transition: 'all 0.2s ease',
                display: 'flex', alignItems: 'center', gap: 6,
              }}>
              <span>{t.icon}</span>
              <span>{t.label}</span>
            </button>
          ))}
        </div>
      </div>
    </nav>
  )
}

// ============================================================
// FOOTER
// ============================================================
function Footer() {
  return (
    <footer style={{
      borderTop: `1px solid ${theme.border}`, padding: '24px',
      textAlign: 'center', color: theme.textMuted, fontSize: 13, marginTop: 80,
    }}>
      <div style={{ maxWidth: 1400, margin: '0 auto' }}>
        <p>AegisNexus — Enterprise Cybersecurity Platform &copy; 2026</p>
        <div style={{ display: 'flex', gap: 24, justifyContent: 'center', marginTop: 12 }}>
          <a href={API + '/docs'} style={{ color: theme.textMuted, textDecoration: 'none' }} target="_blank">API Docs</a>
          <a href="/api/health" style={{ color: theme.textMuted, textDecoration: 'none' }} target="_blank">Health</a>
          <a href="https://github.com" style={{ color: theme.textMuted, textDecoration: 'none' }} target="_blank">GitHub</a>
        </div>
      </div>
    </footer>
  )
}

// ============================================================
// SECTION HEADER
// ============================================================
function SectionHeader({ badge, title, subtitle }) {
  return (
    <div style={{ textAlign: 'center', marginBottom: 48 }}>
      <span style={{
        display: 'inline-block', padding: '6px 16px',
        background: theme.primaryDim, border: `1px solid ${theme.primary}33`,
        borderRadius: '20px', fontSize: 11, fontWeight: 700, color: theme.primary,
        textTransform: 'uppercase', letterSpacing: '1.5px', marginBottom: 16,
      }}>{badge}</span>
      <h1 style={{ fontSize: 36, fontWeight: 800, color: '#fff', marginBottom: 12, letterSpacing: '-1px' }}>
        {title}
      </h1>
      <p style={{ color: theme.textMuted, fontSize: 16, maxWidth: 600, margin: '0 auto', lineHeight: 1.6 }}>
        {subtitle}
      </p>
    </div>
  )
}

// ============================================================
// ANIMATED CARD
// ============================================================
function Card({ children, style, hover = true, ...props }) {
  const [hovered, setHovered] = useState(false)
  return (
    <div
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        background: `linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`,
        border: `1px solid ${hovered ? theme.primary + '66' : theme.border}`,
        borderRadius: theme.radius,
        padding: 24,
        transition: 'all 0.3s cubic-bezier(0.175,0.885,0.32,1.275)',
        boxShadow: hovered ? theme.glow : 'none',
        transform: hovered ? 'translateY(-2px)' : 'none',
        ...style,
      }}
      {...props}
    >
      {children}
    </div>
  )
}

// ============================================================
// GLOW BUTTON
// ============================================================
function GlowButton({ children, onClick, disabled, loading, variant = 'primary', style, ...props }) {
  const isPrimary = variant === 'primary'
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      style={{
        padding: '14px 32px', borderRadius: theme.radiusSm, border: 'none', cursor: disabled ? 'not-allowed' : 'pointer',
        fontSize: 14, fontWeight: 700, letterSpacing: '0.5px',
        background: isPrimary
          ? `linear-gradient(135deg, ${theme.primary}, #0099cc)`
          : 'transparent',
        color: isPrimary ? '#000' : theme.primary,
        border: isPrimary ? 'none' : `1px solid ${theme.primary}44`,
        transition: 'all 0.3s ease',
        opacity: disabled ? 0.5 : 1,
        display: 'inline-flex', alignItems: 'center', gap: 8,
        boxShadow: isPrimary ? '0 4px 20px rgba(0,212,255,0.3)' : 'none',
        ...style,
      }}
      onMouseEnter={e => {
        if (!disabled) {
          e.currentTarget.style.transform = 'translateY(-2px)'
          e.currentTarget.style.boxShadow = '0 8px 30px rgba(0,212,255,0.4)'
        }
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = 'none'
        e.currentTarget.style.boxShadow = isPrimary ? '0 4px 20px rgba(0,212,255,0.3)' : 'none'
      }}
      {...props}
    >
      {loading && <Spinner size={18} />}
      {children}
    </button>
  )
}

// ============================================================
// SPINNER
// ============================================================
function Spinner({ size = 20 }) {
  return (
    <span style={{
      display: 'inline-block', width: size, height: size,
      border: '2px solid rgba(255,255,255,0.2)',
      borderTop: '2px solid #fff',
      borderRadius: '50%',
      animation: 'spin 0.8s linear infinite',
    }} />
  )
}

// ============================================================
// BADGE
// ============================================================
function RiskBadge({ level, size = 'sm' }) {
  const colors = {
    critical: { bg: 'rgba(239,68,68,0.2)', text: '#ef4444' },
    high: { bg: 'rgba(255,107,53,0.2)', text: '#ff6b35' },
    medium: { bg: 'rgba(245,158,11,0.2)', text: '#f59e0b' },
    low: { bg: 'rgba(34,197,94,0.2)', text: '#22c55e' },
    safe: { bg: 'rgba(0,212,255,0.2)', text: '#00d4ff' },
  }
  const c = colors[level] || { bg: 'rgba(100,116,139,0.2)', text: '#64748b' }
  return (
    <span style={{
      display: 'inline-block', padding: size === 'sm' ? '3px 10px' : '6px 16px',
      background: c.bg, color: c.text, borderRadius: '20px',
      fontSize: size === 'sm' ? 11 : 13, fontWeight: 700, textTransform: 'uppercase',
      letterSpacing: '0.5px',
    }}>
      {level === 'critical' ? '🔴 Kritik' :
       level === 'high' ? '🟠 Yüksek' :
       level === 'medium' ? '🟡 Orta' :
       level === 'low' ? '🟢 Düşük' :
       level === 'safe' ? '🔵 Güvenli' : level}
    </span>
  )
}

// ============================================================
// TOAST
// ============================================================
function Toast({ message, type = 'success', visible }) {
  if (!visible) return null
  return (
    <div style={{
      position: 'fixed', bottom: 30, right: 30, zIndex: 9999,
      padding: '14px 24px', borderRadius: theme.radiusSm,
      background: type === 'success' ? '#22c55e' : '#ef4444',
      color: '#fff', fontWeight: 600, fontSize: 14,
      boxShadow: '0 10px 40px rgba(0,0,0,0.4)',
      animation: 'fadeInUp 0.3s ease',
    }}>
      {type === 'success' ? '✅ ' : '❌ '}{message}
    </div>
  )
}

// ============================================================
// STATUS DOT
// ============================================================
function StatusDot({ active }) {
  return (
    <span style={{
      display: 'inline-block', width: 8, height: 8,
      borderRadius: '50%',
      background: active ? theme.success : theme.danger,
      boxShadow: `0 0 8px ${active ? theme.success : theme.danger}66`,
      marginRight: 6,
    }} />
  )
}

// ============================================================
// MAIN APP
// ============================================================
export default function App() {
  const [page, setPage] = useState('ai-analyzer')

  return (
    <div style={{ minHeight: '100vh', background: theme.bg, color: theme.text }}>
      <style>{`
        @keyframes spin { to { transform: rotate(360deg) } }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px) } to { opacity: 1; transform: translateY(0) } }
        @keyframes pulse { 0%,100% { opacity: 1 } 50% { opacity: 0.5 } }
        @keyframes slideInLeft { from { opacity: 0; transform: translateX(-30px) } to { opacity: 1; transform: translateX(0) } }
        @keyframes slideInRight { from { opacity: 0; transform: translateX(30px) } to { opacity: 1; transform: translateX(0) } }
        @keyframes scaleIn { from { opacity: 0; transform: scale(0.9) } to { opacity: 1; transform: scale(1) } }
        * { scrollbar-width: thin; scrollbar-color: ${theme.border} transparent; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: ${theme.border}; border-radius: 3px; }
      `}</style>
      <Navbar page={page} setPage={setPage} />
      <main style={{ paddingTop: 86, maxWidth: 1400, margin: '0 auto', padding: '86px 24px 0' }}>
        {page === 'ai-analyzer' && <AIAnalyzer />}
        {page === 'phishing-detector' && <PhishingDetector />}
        {page === 'honeypot' && <HoneypotIOC />}
        {page === 'breach-intel' && <BreachIntel />}
      </main>
      <Footer />
    </div>
  )
}

// ============================================================
// AI ANALYZER PAGE
// ============================================================
function AIAnalyzer() {
  const [message, setMessage] = useState('')
  const [context, setContext] = useState('email')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [toast, setToast] = useState({ message: '', type: 'success', visible: false })

  useEffect(() => { loadHistory() }, [])

  async function loadHistory() {
    try {
      const r = await fetch(`${API}/ai-analyzer/history?limit=10`)
      const d = await r.json()
      setHistory(d.data || [])
    } catch {}
  }

  async function handleAnalyze() {
    if (!message || message.length < 10) {
      setToast({ message: 'Lütfen en az 10 karakter girin', type: 'error', visible: true })
      setTimeout(() => setToast(t => ({ ...t, visible: false })), 3000)
      return
    }
    setAnalyzing(true)
    setResult(null)
    try {
      const r = await fetch(`${API}/ai-analyzer/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, context }),
      })
      const d = await r.json()
      setResult(d)
      loadHistory()
    } catch (e) {
      setToast({ message: 'Analiz hatası: ' + e.message, type: 'error', visible: true })
      setTimeout(() => setToast(t => ({ ...t, visible: false })), 3000)
    }
    setAnalyzing(false)
  }

  const examples = [
    { text: 'Sayın müşterimiz, hesabınız askıya alınmıştır. Hemen tıklayın: http://bit.ly/3xK...', label: 'Phishing Email' },
    { text: 'Tebrikler! 100.000 TL kazandınız. Hemen arayın: 0555 123 45 67', label: 'SMS Dolandırıcılığı' },
    { text: 'Merhaba, fatura ekteki gibidir. acil ödeme yapınız. Saygılar, Mali İşler', label: 'Fatura Dolandırıcılığı' },
  ]

  return (
    <div style={{ animation: 'fadeInUp 0.5s ease' }}>
      <Toast {...toast} />

      {/* Header */}
      <SectionHeader
        badge="AI Analiz Modülü"
        title="Yapay Zeka ile Güvenlik Analizi"
        subtitle="Mesaj, e-posta veya metinlerinizi AI ile analiz edin. Phishing, sosyal mühendislik ve kötü amaçlı içerikleri tespit edin."
      />

      {/* Info Banner */}
      <Card style={{ marginBottom: 32, padding: '20px 28px', display: 'flex', gap: 16, alignItems: 'center' }}>
        <span style={{ fontSize: 32 }}>🤖</span>
        <div>
          <p style={{ fontWeight: 600, color: theme.primary, marginBottom: 4 }}>LLM Destekli Analiz Motoru</p>
          <p style={{ fontSize: 13, color: theme.textMuted, lineHeight: 1.5 }}>
            DeepSeek / Groq AI modelleri ile gerçek zamanlı phishing, sosyal mühendislik ve psikolojik manipülasyon tespiti.
            Şüpheli URL'ler otomatik olarak taranır ve risk skoru hesaplanır.
          </p>
        </div>
      </Card>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 48 }}>
        {/* LEFT: Input */}
        <Card style={{ animation: 'slideInLeft 0.5s ease' }}>
          <h3 style={{ fontSize: 18, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span>📝</span> Analiz Edilecek Metin
          </h3>

          {/* Context Selector */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexWrap: 'wrap' }}>
            {[{ id: 'email', label: '📧 E-posta' }, { id: 'sms', label: '💬 SMS' }, { id: 'whatsapp', label: '📱 WhatsApp' }, { id: 'social_media', label: '🌐 Sosyal Medya' }].map(c => (
              <button key={c.id} onClick={() => setContext(c.id)}
                style={{
                  padding: '6px 14px', borderRadius: '20px', border: '1px solid',
                  cursor: 'pointer', fontSize: 12, fontWeight: 600,
                  background: context === c.id ? theme.primary : 'transparent',
                  borderColor: context === c.id ? theme.primary : theme.border,
                  color: context === c.id ? '#000' : theme.textMuted,
                  transition: 'all 0.2s',
                }}>
                {c.label}
              </button>
            ))}
          </div>

          <textarea
            value={message}
            onChange={e => setMessage(e.target.value)}
            placeholder="Analiz edilecek metni buraya yapıştırın veya yazın..."
            rows={8}
            style={{
              width: '100%', padding: 16, borderRadius: theme.radiusSm,
              background: theme.bg, border: `1px solid ${theme.border}`,
              color: theme.text, fontSize: 14, resize: 'vertical',
              fontFamily: theme.mono,
              outline: 'none',
            }}
          />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}>
            <span style={{ fontSize: 12, color: theme.textMuted }}>{message.length} karakter</span>
            <GlowButton onClick={handleAnalyze} loading={analyzing} disabled={message.length < 10}>
              {analyzing ? 'Analiz Ediliyor...' : '🔍 Analiz Et'}
            </GlowButton>
          </div>

          {/* Examples */}
          <div style={{ marginTop: 24 }}>
            <p style={{ fontSize: 12, color: theme.textMuted, fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '1px' }}>
              Örnek Metinler
            </p>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {examples.map((ex, i) => (
                <button key={i} onClick={() => setMessage(ex.text)}
                  style={{
                    padding: '10px 14px', borderRadius: theme.radiusSm, border: `1px solid ${theme.border}`,
                    background: theme.surface, cursor: 'pointer', textAlign: 'left',
                    fontSize: 12, color: theme.textMuted, lineHeight: 1.4, transition: 'all 0.2s',
                  }}
                  onMouseEnter={e => { e.currentTarget.style.borderColor = theme.primary + '44'; e.currentTarget.style.background = theme.surface2 }}
                  onMouseLeave={e => { e.currentTarget.style.borderColor = theme.border; e.currentTarget.style.background = theme.surface }}>
                  <span style={{ color: theme.primary, fontWeight: 600, fontSize: 11 }}>{ex.label}</span>
                  <br />{ex.text.substring(0, 70)}...
                </button>
              ))}
            </div>
          </div>
        </Card>

        {/* RIGHT: Results */}
        <Card style={{ animation: 'slideInRight 0.5s ease' }}>
          <h3 style={{ fontSize: 18, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span>📊</span> Analiz Sonuçları
          </h3>

          {!result && !analyzing && (
            <div style={{ textAlign: 'center', padding: '60px 20px', color: theme.textMuted }}>
              <span style={{ fontSize: 48, display: 'block', marginBottom: 16 }}>🔍</span>
              <p style={{ fontSize: 14 }}>Henüz analiz yapılmadı</p>
              <p style={{ fontSize: 12, marginTop: 8 }}>Sol taraftaki metni girin ve "Analiz Et" butonuna tıklayın</p>
            </div>
          )}

          {analyzing && (
            <div style={{ textAlign: 'center', padding: '60px 20px' }}>
              <Spinner size={40} />
              <p style={{ marginTop: 16, color: theme.textMuted, fontSize: 14 }}>AI analiz ediyor...</p>
            </div>
          )}

          {result && (
            <div style={{ animation: 'scaleIn 0.3s ease' }}>
              {/* Risk Score Ring */}
              <div style={{ textAlign: 'center', marginBottom: 24 }}>
                <RiskGauge
                  score={result.security_assessment?.threat_level === 'critical' ? 95 :
                         result.security_assessment?.threat_level === 'high' ? 75 :
                         result.security_assessment?.threat_level === 'medium' ? 50 :
                         result.security_assessment?.threat_level === 'low' ? 25 : 0}
                  label="Risk Seviyesi"
                />
              </div>

              {/* Summary */}
              <Card style={{ padding: 16, marginBottom: 16 }}>
                <p style={{ fontSize: 13, lineHeight: 1.6, color: theme.textDim }}>{result.summary || 'Özet bulunamadı.'}</p>
              </Card>

              {/* Assessment Details */}
              {result.security_assessment && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
                  <Card style={{ padding: 14, textAlign: 'center' }}>
                    <p style={{ fontSize: 11, color: theme.textMuted, marginBottom: 4 }}>Tehdit Seviyesi</p>
                    <RiskBadge level={result.security_assessment.threat_level || 'unknown'} size="md" />
                  </Card>
                  <Card style={{ padding: 14, textAlign: 'center' }}>
                    <p style={{ fontSize: 11, color: theme.textMuted, marginBottom: 4 }}>Phishing Riski</p>
                    <p style={{ fontSize: 24, fontWeight: 800, color: result.security_assessment.is_phishing ? theme.danger : theme.success }}>
                      {result.security_assessment.is_phishing ? '⚠️ EVET' : '✅ HAYIR'}
                    </p>
                  </Card>
                  <Card style={{ padding: 14, textAlign: 'center' }}>
                    <p style={{ fontSize: 11, color: theme.textMuted, marginBottom: 4 }}>Güven Skoru</p>
                    <p style={{ fontSize: 24, fontWeight: 800, color: theme.primary }}>
                      %{Math.round((result.security_assessment.confidence || 0) * 100)}
                    </p>
                  </Card>
                  <Card style={{ padding: 14, textAlign: 'center' }}>
                    <p style={{ fontSize: 11, color: theme.textMuted, marginBottom: 4 }}>Manipülasyon</p>
                    <p style={{ fontSize: 24, fontWeight: 800, color: theme.warning }}>
                      {result.security_assessment.psychological_score || '-'}/10
                    </p>
                  </Card>
                </div>
              )}

              {/* Detailed Findings */}
              {result.detailed_analysis && (
                <div>
                  <p style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 12 }}>Detaylı Bulgular</p>
                  {Object.entries(result.detailed_analysis).map(([key, val]) => (
                    <div key={key} style={{
                      padding: '10px 0', borderBottom: `1px solid ${theme.border}`,
                      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    }}>
                      <span style={{ fontSize: 13, color: theme.textMuted, textTransform: 'capitalize' }}>
                        {key.replace(/_/g, ' ')}
                      </span>
                      <span style={{ fontSize: 13, color: '#fff', fontWeight: 600 }}>
                        {typeof val === 'boolean' ? (val ? '✅' : '❌') :
                         typeof val === 'object' ? JSON.stringify(val) : String(val)}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Recommendations */}
              {result.recommendations && result.recommendations.length > 0 && (
                <div style={{ marginTop: 16 }}>
                  <p style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 12 }}>Öneriler</p>
                  {result.recommendations.map((rec, i) => (
                    <div key={i} style={{
                      padding: '12px 14px', marginBottom: 8,
                      background: theme.primaryDim, borderRadius: theme.radiusSm,
                      borderLeft: `3px solid ${theme.primary}`,
                      fontSize: 13, lineHeight: 1.5,
                    }}>
                      💡 {rec.description || rec.message || rec}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* History */}
      <Card style={{ marginBottom: 48 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span>📜</span> Son Analizler
        </h3>
        {history.length === 0 ? (
          <p style={{ color: theme.textMuted, fontSize: 13, textAlign: 'center', padding: 20 }}>Henüz analiz yapılmadı</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {history.map(h => (
              <div key={h.id} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '12px 16px', background: theme.surface, borderRadius: theme.radiusSm,
                border: `1px solid ${theme.border}`,
              }}>
                <div style={{ flex: 1, overflow: 'hidden' }}>
                  <p style={{ fontSize: 13, color: '#fff', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {h.url || h.message || h.text}
                  </p>
                  <p style={{ fontSize: 11, color: theme.textMuted, marginTop: 2 }}>
                    {h.created_at ? new Date(h.created_at).toLocaleString('tr-TR') : ''}
                  </p>
                </div>
                <RiskBadge level={h.risk_level || h.threat_level || 'safe'} />
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}

// ============================================================
// RISK GAUGE
// ============================================================
function RiskGauge({ score, label }) {
  const circumference = 2 * Math.PI * 40
  const offset = circumference - (score / 100) * circumference
  const color = score > 75 ? theme.danger : score > 50 ? theme.warning : score > 25 ? theme.primary : theme.success

  return (
    <div style={{ display: 'inline-flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width="120" height="120" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="40" fill="none" stroke={theme.border} strokeWidth="8" />
        <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={offset}
          transform="rotate(-90 50 50)"
          style={{ transition: 'stroke-dashoffset 1s ease' }}
          strokeLinecap="round"
        />
        <text x="50" y="50" textAnchor="middle" dominantBaseline="central"
          fill="#fff" fontSize="22" fontWeight="800" fontFamily="'Inter', sans-serif">
          {score}
        </text>
      </svg>
      <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 8, fontWeight: 600 }}>{label}</p>
    </div>
  )
}

// ============================================================
// PHISHING DETECTOR PAGE
// ============================================================
function PhishingDetector() {
  const [url, setUrl] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [latest, setLatest] = useState([])
  const [stats, setStats] = useState({ total_urls: 0, phishing_count: 0 })
  const [toast, setToast] = useState({ message: '', type: 'success', visible: false })
  const [pageNum, setPageNum] = useState(1)

  useEffect(() => { loadLatest(); loadStats() }, [])

  async function loadLatest(p = pageNum) {
    try {
      const r = await fetch(`${API}/phishing-detector/latest?limit=20&page=${p}`)
      const d = await r.json()
      setLatest(d.data || d.latest || [])
    } catch {}
  }

  async function loadStats() {
    try {
      const r = await fetch(`${API}/phishing-detector/stats`)
      const d = await r.json()
      setStats(d.stats || {})
    } catch {}
  }

  async function handleCheck() {
    if (!url) return
    setChecking(true)
    setResult(null)
    try {
      const r = await fetch(`${API}/phishing-detector/check-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      })
      const d = await r.json()
      setResult(d)
    } catch (e) {
      setToast({ message: 'URL kontrol hatası: ' + e.message, type: 'error', visible: true })
      setTimeout(() => setToast(t => ({ ...t, visible: false })), 3000)
    }
    setChecking(false)
  }

  return (
    <div style={{ animation: 'fadeInUp 0.5s ease' }}>
      <Toast {...toast} />

      <SectionHeader
        badge="Phishing Dedektörü"
        title="URL Güvenlik Tarama Motoru"
        subtitle="1.2M+ phishing URL veritabanı ile anlık güvenlik kontrolü. DNS, SSL ve makine öğrenimi analizi."
      />

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16, marginBottom: 32 }}>
        <Card style={{ textAlign: 'center', padding: '20px' }}>
          <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Toplam URL</p>
          <p style={{ fontSize: 32, fontWeight: 800, color: theme.primary }}>
            <CountUp end={stats.total_urls || 0} />
          </p>
        </Card>
        <Card style={{ textAlign: 'center', padding: '20px' }}>
          <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Phishing Tespit</p>
          <p style={{ fontSize: 32, fontWeight: 800, color: theme.danger }}>
            <CountUp end={stats.phishing_count || 0} />
          </p>
        </Card>
        <Card style={{ textAlign: 'center', padding: '20px' }}>
          <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Güven Skoru</p>
          <p style={{ fontSize: 32, fontWeight: 800, color: theme.success }}>92%</p>
        </Card>
      </div>

      {/* URL Check */}
      <Card style={{ marginBottom: 32 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span>🔍</span> URL Güvenlik Kontrolü
        </h3>
        <div style={{ display: 'flex', gap: 12, marginBottom: 16 }}>
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            placeholder="https://ornek.com/supheli-link"
            style={{
              flex: 1, padding: '14px 18px', borderRadius: theme.radiusSm,
              background: theme.bg, border: `1px solid ${theme.border}`,
              color: '#fff', fontSize: 14, fontFamily: theme.mono, outline: 'none',
            }}
            onKeyDown={e => e.key === 'Enter' && handleCheck()}
          />
          <GlowButton onClick={handleCheck} loading={checking} disabled={!url}>
            {checking ? 'Taranıyor...' : '🔍 Tara'}
          </GlowButton>
        </div>

        {/* Result */}
        {result && (
          <div style={{ animation: 'scaleIn 0.3s ease', padding: 20, background: theme.bg, borderRadius: theme.radiusSm, border: `1px solid ${theme.border}` }}>
            <div style={{ display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
              <div style={{ textAlign: 'center' }}>
                <RiskGauge score={result.score || (result.status === 'phishing' ? 85 : 15)} label="Risk Skoru" />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
                  <RiskBadge level={result.threat_level || (result.score > 70 ? 'high' : 'safe')} size="md" />
                  <span style={{
                    padding: '4px 14px', borderRadius: '20px', fontSize: 12, fontWeight: 700,
                    background: result.status === 'phishing' ? theme.accentDim : theme.primaryDim,
                    color: result.status === 'phishing' ? theme.accent : theme.primary,
                  }}>
                    {result.status === 'phishing' ? '⚠️ PHISHING' : '✅ GÜVENLİ'}
                  </span>
                </div>
                <p style={{ fontSize: 13, color: theme.textDim, wordBreak: 'break-all' }}>{url}</p>
                {result.details && Object.entries(result.details).map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', gap: 8, fontSize: 12, marginTop: 4 }}>
                    <span style={{ color: theme.textMuted, textTransform: 'capitalize' }}>{k.replace(/_/g, ' ')}:</span>
                    <span style={{ color: '#fff' }}>{String(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </Card>

      {/* Latest Phishing URLs Table */}
      <Card>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span>📋</span> Son Phishing Verileri
          <span style={{ fontSize: 11, color: theme.textMuted, fontWeight: 400, marginLeft: 'auto' }}>
            Son 20 kayıt
          </span>
        </h3>

        {/* Table */}
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.border}`, color: theme.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: '1px' }}>
                <th style={{ textAlign: 'left', padding: '12px 8px' }}>URL</th>
                <th style={{ textAlign: 'left', padding: '12px 8px' }}>Domain</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Hedef</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Durum</th>
                <th style={{ textAlign: 'right', padding: '12px 8px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {latest.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: 32, color: theme.textMuted }}>
                    Veri yükleniyor...
                  </td>
                </tr>
              )}
              {latest.map((item, i) => (
                <tr key={item.id || i} style={{
                  borderBottom: `1px solid ${theme.border}`,
                  transition: 'background 0.2s',
                }}
                  onMouseEnter={e => e.currentTarget.style.background = theme.surface}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '10px 8px', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span style={{ color: theme.text }}>{item.url || item.url}</span>
                  </td>
                  <td style={{ padding: '10px 8px' }}>
                    <span style={{ color: theme.primary, fontSize: 12 }}>{item.domain_norm || item.domain || '-'}</span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                    <span style={{ padding: '2px 8px', borderRadius: '10px', fontSize: 11, background: theme.accentDim, color: theme.accent }}>
                      {item.target || '-'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                    <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4, fontSize: 12 }}>
                      <StatusDot active={item.status === 'ONLINE' || item.online} />
                      {item.status || (item.online ? 'ONLINE' : 'OFFLINE')}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'right', color: theme.textMuted, fontSize: 11 }}>
                    {item.created_at ? new Date(item.created_at).toLocaleDateString('tr-TR') :
                     item.submission_time ? new Date(item.submission_time).toLocaleDateString('tr-TR') : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 20 }}>
          <button onClick={() => { setPageNum(p => Math.max(1, p - 1)); loadLatest(pageNum - 1) }}
            disabled={pageNum <= 1}
            style={{
              padding: '8px 16px', borderRadius: theme.radiusSm, border: `1px solid ${theme.border}`,
              background: theme.surface, color: pageNum <= 1 ? theme.textMuted : '#fff', cursor: pageNum <= 1 ? 'not-allowed' : 'pointer',
              fontSize: 13, fontWeight: 600,
            }}>← Önceki</button>

          <span style={{ padding: '8px 16px', color: theme.textMuted, fontSize: 13 }}>
            Sayfa {pageNum}
          </span>

          <button onClick={() => { setPageNum(p => p + 1); loadLatest(pageNum + 1) }}
            style={{
              padding: '8px 16px', borderRadius: theme.radiusSm, border: `1px solid ${theme.border}`,
              background: theme.surface, color: '#fff', cursor: 'pointer',
              fontSize: 13, fontWeight: 600,
            }}>Sonraki →</button>
        </div>
      </Card>
    </div>
  )
}

// ============================================================
// COUNT UP
// ============================================================
function CountUp({ end, duration = 1500 }) {
  const [val, setVal] = useState(0)
  const ref = useRef(null)
  useEffect(() => {
    const start = performance.now()
    const animate = (now) => {
      const elapsed = now - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setVal(Math.floor(eased * end))
      if (progress < 1) ref.current = requestAnimationFrame(animate)
    }
    ref.current = requestAnimationFrame(animate)
    return () => cancelAnimationFrame(ref.current)
  }, [end, duration])
  return <>{val.toLocaleString('tr-TR')}</>
}

// ============================================================
// HONEYPOT / IOC PAGE
// ============================================================
function HoneypotIOC() {
  const [iocStats, setIocStats] = useState(null)
  const [iocList, setIocList] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [activeTab, setActiveTab] = useState('stats')
  const [toast, setToast] = useState({ message: '', type: 'success', visible: false })

  useEffect(() => { loadIoCStats(); loadIoCList() }, [])

  async function loadIoCStats() {
    try {
      const r = await fetch(`${API}/honeypot/ioc/stats`)
      const d = await r.json()
      setIocStats(d)
    } catch {}
  }

  async function loadIoCList() {
    try {
      const r = await fetch(`${API}/honeypot/ioc/list-collected?limit=20`)
      const d = await r.json()
      setIocList(d.data || d.iocs || d.results || [])
    } catch {}
  }

  async function handleSearch() {
    if (!searchQuery) return
    try {
      const r = await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`)
      const d = await r.json()
      setSearchResults(d.data || d.results || d.iocs || [])
      setActiveTab('search')
    } catch {}
  }

  return (
    <div style={{ animation: 'fadeInUp 0.5s ease' }}>
      <Toast {...toast} />

      <SectionHeader
        badge="IOC / Tuzak Modülü"
        title="Tehdit İstihbaratı & IOC Analizi"
        subtitle="Saldırganlardan toplanan göstergeler, zararlı IP'ler, domain'ler ve hash'ler. Gerçek zamanlı tehdit istihbaratı."
      />

      {/* Main two-column layout */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 32 }}>
        {/* LEFT: Description + Search */}
        <div>
          <Card style={{ marginBottom: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span>🕸️</span> IOC Nedir?
            </h3>
            <p style={{ fontSize: 13, color: theme.textDim, lineHeight: 1.7 }}>
              <strong style={{ color: '#fff' }}>Indicator of Compromise (IoC)</strong>, bir siber saldırıyı tespit etmek için kullanılan 
              adli kanıtlardır. IP adresleri, domain adları, URL'ler, dosya hash'leri ve e-posta adreslerini içerir.
            </p>
            <div style={{ marginTop: 16, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {[
                { label: 'IP Adresleri', value: iocStats?.total_records || 0, color: theme.danger },
                { label: 'Domain', value: (iocStats?.top_threats || []).filter(t => t.threat_type?.includes('domain')).length || '12+', color: theme.warning },
                { label: 'URL', value: '8.5K+', color: theme.primary },
                { label: 'Hash', value: '3.2K+', color: theme.success },
              ].map((item, i) => (
                <div key={i} style={{ padding: '12px', background: theme.surface, borderRadius: theme.radiusSm, textAlign: 'center' }}>
                  <p style={{ fontSize: 20, fontWeight: 800, color: item.color }}>{item.value}</p>
                  <p style={{ fontSize: 11, color: theme.textMuted }}>{item.label}</p>
                </div>
              ))}
            </div>
          </Card>

          {/* IOC Search */}
          <Card>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span>🔎</span> IOC Sorgula
            </h3>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="IP, domain, URL veya hash girin..."
                style={{
                  flex: 1, padding: '12px 16px', borderRadius: theme.radiusSm,
                  background: theme.bg, border: `1px solid ${theme.border}`,
                  color: '#fff', fontSize: 13, fontFamily: theme.mono, outline: 'none',
                }}
                onKeyDown={e => e.key === 'Enter' && handleSearch()}
              />
              <GlowButton onClick={handleSearch}>Ara</GlowButton>
            </div>

            {/* Search Results */}
            {activeTab === 'search' && searchResults.length > 0 && (
              <div style={{ marginTop: 16 }}>
                <p style={{ fontSize: 12, color: theme.textMuted, marginBottom: 8 }}>{searchResults.length} sonuç bulundu:</p>
                {searchResults.slice(0, 10).map((item, i) => (
                  <div key={i} style={{
                    padding: '10px', marginBottom: 6,
                    background: theme.surface, borderRadius: theme.radiusSm,
                    border: `1px solid ${theme.border}`, fontSize: 12,
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ color: theme.primary, fontFamily: theme.mono }}>{item.value || item.ioc || item.indicator}</span>
                      <span style={{ background: theme.accentDim, color: theme.accent, padding: '2px 8px', borderRadius: '10px', fontSize: 10 }}>
                        {item.type || item.ioc_type || 'unknown'}
                      </span>
                    </div>
                    <p style={{ color: theme.textMuted, marginTop: 4, fontSize: 11 }}>
                      Risk: {item.risk_score || 'N/A'} | Kaynak: {item.source || 'N/A'}
                    </p>
                  </div>
                ))}
              </div>
            )}
            {activeTab === 'search' && searchResults.length === 0 && (
              <p style={{ color: theme.textMuted, fontSize: 13, marginTop: 16, textAlign: 'center' }}>Sonuç bulunamadı</p>
            )}
          </Card>
        </div>

        {/* RIGHT: Stats + Charts */}
        <div>
          {iocStats ? (
            <>
              {/* Risk Distribution */}
              <Card style={{ marginBottom: 24 }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 16 }}>📊 IOC Risk Dağılımı</h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                  {(iocStats.risk_distribution || []).map((item, i) => {
                    const colors = ['#22c55e', '#84cc16', '#f59e0b', '#ff6b35', '#ef4444']
                    return (
                      <div key={i}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                          <span style={{ color: theme.textMuted }}>{item.range}</span>
                          <span style={{ color: '#fff', fontWeight: 600 }}>{item.count}</span>
                        </div>
                        <div style={{ height: 8, background: theme.surface, borderRadius: 4, overflow: 'hidden' }}>
                          <div style={{
                            height: '100%', width: `${item.percentage}%`,
                            background: colors[i] || theme.primary,
                            borderRadius: 4, transition: 'width 1s ease',
                          }} />
                        </div>
                      </div>
                    )
                  })}
                </div>
              </Card>

              {/* Weekly Growth */}
              <Card style={{ marginBottom: 24 }}>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 16 }}>📈 Haftalık IOC Artışı</h3>
                <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end', height: 120, position: 'relative' }}>
                  {(iocStats.weekly_growth || []).map((item, i) => {
                    const maxVal = Math.max(...(iocStats.weekly_growth || []).map(w => w.count), 1)
                    const height = (item.count / maxVal) * 100
                    return (
                      <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
                        <span style={{ fontSize: 10, color: theme.textMuted }}>{item.count}</span>
                        <div style={{
                          width: '100%', height: `${height}%`, minHeight: 4,
                          background: `linear-gradient(to top, ${theme.primary}, ${theme.primary}88)`,
                          borderRadius: '4px 4px 0 0', transition: 'height 1s ease',
                        }} />
                        <span style={{ fontSize: 9, color: theme.textMuted, transform: 'rotate(-45deg)', whiteSpace: 'nowrap' }}>
                          {item.date?.slice(5)}
                        </span>
                      </div>
                    )
                  })}
                </div>
              </Card>

              {/* Top Threats */}
              <Card>
                <h3 style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 12 }}>🔥 En Çok Görülen Tehditler</h3>
                {(iocStats.top_threats || []).slice(0, 8).map((t, i) => (
                  <div key={i} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '8px 0', borderBottom: `1px solid ${theme.border}`,
                  }}>
                    <span style={{ fontSize: 13, color: '#fff' }}>
                      {i + 1}. {t.threat_type || t.type || t.name}
                    </span>
                    <span style={{ fontSize: 13, fontWeight: 700, color: theme.danger }}>{t.count}</span>
                  </div>
                ))}
              </Card>
            </>
          ) : (
            <Card style={{ textAlign: 'center', padding: 60 }}>
              <Spinner size={32} />
              <p style={{ marginTop: 16, color: theme.textMuted, fontSize: 14 }}>IOC istatistikleri yükleniyor...</p>
            </Card>
          )}
        </div>
      </div>

      {/* IOC List Table */}
      <Card>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span>📋</span> Son Eklenen IOC'ler
        </h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.border}`, color: theme.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: '1px' }}>
                <th style={{ textAlign: 'left', padding: '12px 8px' }}>Gösterge</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Tür</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Risk</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Kaynak</th>
                <th style={{ textAlign: 'right', padding: '12px 8px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {iocList.length === 0 && (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: 32, color: theme.textMuted }}>Veri yükleniyor...</td>
                </tr>
              )}
              {iocList.map((item, i) => (
                <tr key={item.id || i} style={{ borderBottom: `1px solid ${theme.border}` }}
                  onMouseEnter={e => e.currentTarget.style.background = theme.surface}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '10px 8px' }}>
                    <span style={{ color: theme.primary, fontFamily: theme.mono, fontSize: 12 }}>{item.value || item.ioc || item.indicator}</span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                    <span style={{ padding: '2px 8px', borderRadius: '10px', fontSize: 11, background: theme.primaryDim, color: theme.primary }}>
                      {item.type || item.ioc_type || 'N/A'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                    <span style={{
                      padding: '2px 8px', borderRadius: '10px', fontSize: 11, fontWeight: 600,
                      background: (item.risk_score || 0) > 75 ? theme.accentDim : theme.primaryDim,
                      color: (item.risk_score || 0) > 75 ? theme.accent : theme.primary,
                    }}>
                      {item.risk_score || 'N/A'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'center', color: theme.textMuted, fontSize: 12 }}>
                    {item.source || 'N/A'}
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'right', color: theme.textMuted, fontSize: 11 }}>
                    {item.created_at ? new Date(item.created_at).toLocaleDateString('tr-TR') : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}

// ============================================================
// BREACH INTELLIGENCE PAGE
// ============================================================
function BreachIntel() {
  const [email, setEmail] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [stats, setStats] = useState(null)
  const [toast, setToast] = useState({ message: '', type: 'success', visible: false })
  const [activeSection, setActiveSection] = useState('check')

  useEffect(() => { loadStats() }, [])

  async function loadStats() {
    try {
      const r = await fetch(`${API}/breach-intel/stats`)
      const d = await r.json()
      setStats(d)
    } catch {}
  }

  async function handleCheck() {
    if (!email || !email.includes('@')) {
      setToast({ message: 'Geçerli bir e-posta adresi girin', type: 'error', visible: true })
      setTimeout(() => setToast(t => ({ ...t, visible: false })), 3000)
      return
    }
    setChecking(true)
    setResult(null)
    try {
      const r = await fetch(`${API}/breach-intel/check-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      const d = await r.json()
      setResult(d)
    } catch (e) {
      setToast({ message: 'Sorgu hatası: ' + e.message, type: 'error', visible: true })
      setTimeout(() => setToast(t => ({ ...t, visible: false })), 3000)
    }
    setChecking(false)
  }

  return (
    <div style={{ animation: 'fadeInUp 0.5s ease' }}>
      <Toast {...toast} />

      <SectionHeader
        badge="Sızıntı İstihbaratı"
        title="Veri İhlali & Dark Web Taraması"
        subtitle="E-posta adresinizin sızdırılıp sızdırılmadığını kontrol edin. Dark web, veri ihlalleri ve sızıntı veritabanlarında arama yapın."
      />

      {/* Stats Cards */}
      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16, marginBottom: 32 }}>
          <Card style={{ textAlign: 'center', padding: '20px' }}>
            <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Toplam İhlal</p>
            <p style={{ fontSize: 28, fontWeight: 800, color: theme.danger }}>{stats.total_breaches || stats.total || 0}</p>
          </Card>
          <Card style={{ textAlign: 'center', padding: '20px' }}>
            <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Sızdırılan Hesap</p>
            <p style={{ fontSize: 28, fontWeight: 800, color: theme.warning }}>{(stats.total_compromised || stats.compromised || 0).toLocaleString('tr-TR')}</p>
          </Card>
          <Card style={{ textAlign: 'center', padding: '20px' }}>
            <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Yeni Sızıntı (7g)</p>
            <p style={{ fontSize: 28, fontWeight: 800, color: theme.primary }}>{stats.recent_breaches || stats.recent || 0}</p>
          </Card>
          <Card style={{ textAlign: 'center', padding: '20px' }}>
            <p style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', fontWeight: 600, letterSpacing: '1px', marginBottom: 8 }}>Dark Web Kaynak</p>
            <p style={{ fontSize: 28, fontWeight: 800, color: theme.success }}>{stats.dark_web_sources || stats.sources || '12'}</p>
          </Card>
        </div>
      )}

      {/* Main Grid: Explanation + Check */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 48 }}>
        {/* LEFT: Info + Services */}
        <div>
          <Card style={{ marginBottom: 24 }}>
            <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span>🔓</span> Sızıntı Kontrolü Nedir?
            </h3>
            <p style={{ fontSize: 13, color: theme.textDim, lineHeight: 1.7 }}>
              Veri ihlalleri, hackerların şirket veritabanlarını ele geçirmesiyle milyonlarca kullanıcının 
              e-posta, şifre ve kişisel bilgilerinin internete sızmasına neden olur. Bu modül, 
              <strong style={{ color: '#fff' }}> Have I Been Pwned (HIBP)</strong>, 
              <strong style={{ color: '#fff' }}> Dark Web forumları</strong> ve 
              <strong style={{ color: '#fff' }}> sızıntı veritabanlarını</strong> tarar.
            </p>
          </Card>

          {/* Breach Sources */}
          <Card>
            <h3 style={{ fontSize: 14, fontWeight: 700, color: '#fff', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
              <span>📡</span> Taranan Kaynaklar
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[
                { name: 'Have I Been Pwned', desc: '13M+ sızdırılmış hesap', color: theme.danger },
                { name: 'Dark Web Forumları', desc: 'Underground pazarlar, leak siteleri', color: theme.warning },
                { name: 'Breach Forums', desc: 'Sızıntı veritabanları', color: theme.primary },
                { name: 'Telegram Leak Kanalları', desc: 'Otomatik sızıntı botları', color: theme.accent },
                { name: 'KVKK Veritabanı', desc: 'Türkiye veri ihlal bildirimleri', color: theme.success },
              ].map((src, i) => (
                <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '10px 14px', background: theme.surface, borderRadius: theme.radiusSm }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: src.color, flexShrink: 0 }} />
                  <div>
                    <p style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>{src.name}</p>
                    <p style={{ fontSize: 11, color: theme.textMuted }}>{src.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* RIGHT: Check Form */}
        <Card>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span>🔍</span> E-posta Sızıntı Kontrolü
          </h3>
          <p style={{ fontSize: 13, color: theme.textDim, marginBottom: 16 }}>
            E-posta adresinizi aşağıya girin, veri ihlallerinde sızdırılıp sızdırılmadığını kontrol edelim.
          </p>
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="ornek@email.com"
              style={{
                flex: 1, padding: '14px 18px', borderRadius: theme.radiusSm,
                background: theme.bg, border: `1px solid ${theme.border}`,
                color: '#fff', fontSize: 14, fontFamily: theme.mono, outline: 'none',
              }}
              onKeyDown={e => e.key === 'Enter' && handleCheck()}
            />
            <GlowButton onClick={handleCheck} loading={checking} disabled={!email || !email.includes('@')}>
              {checking ? 'Taranıyor...' : '🔍 Sorgula'}
            </GlowButton>
          </div>

          {/* Additional Services */}
          <div style={{ marginTop: 16 }}>
            <p style={{ fontSize: 12, color: theme.textMuted, fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '1px' }}>
              Diğer Servisler
            </p>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <button onClick={() => { setActiveSection('zombie'); setToast({ message: 'Zombie hesap dedektörü yakında!', type: 'success', visible: true }); setTimeout(() => setToast(t => ({...t, visible: false})), 2000) }}
                style={{ padding: '12px', background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radiusSm, cursor: 'pointer', color: theme.textMuted, fontSize: 12, textAlign: 'center' }}>
                🧟 Zombie Hesap Detektörü
              </button>
              <button onClick={() => { setActiveSection('kvkk'); setToast({ message: 'KVKK raporlama yakında!', type: 'success', visible: true }); setTimeout(() => setToast(t => ({...t, visible: false})), 2000) }}
                style={{ padding: '12px', background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radiusSm, cursor: 'pointer', color: theme.textMuted, fontSize: 12, textAlign: 'center' }}>
                📋 KVKK Başvuru Raporu
              </button>
              <button onClick={() => { setActiveSection('darkweb'); setToast({ message: 'Dark web taraması yakında!', type: 'success', visible: true }); setTimeout(() => setToast(t => ({...t, visible: false})), 2000) }}
                style={{ padding: '12px', background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radiusSm, cursor: 'pointer', color: theme.textMuted, fontSize: 12, textAlign: 'center' }}>
                🌑 Dark Web Taraması
              </button>
              <button onClick={() => { setActiveSection('psychology'); setToast({ message: 'Psikolojik analiz yakında!', type: 'success', visible: true }); setTimeout(() => setToast(t => ({...t, visible: false})), 2000) }}
                style={{ padding: '12px', background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radiusSm, cursor: 'pointer', color: theme.textMuted, fontSize: 12, textAlign: 'center' }}>
                🧠 Saldırgan Psikolojisi
              </button>
            </div>
          </div>

          {/* Check Result */}
          {result && (
            <div style={{ animation: 'scaleIn 0.3s ease', marginTop: 24, padding: 20, background: theme.bg, borderRadius: theme.radiusSm, border: `1px solid ${theme.border}` }}>
              {result.compromised || result.is_breached ? (
                <>
                  <div style={{ textAlign: 'center', marginBottom: 16 }}>
                    <span style={{ fontSize: 48 }}>⚠️</span>
                    <p style={{ color: theme.danger, fontSize: 18, fontWeight: 700, marginTop: 8 }}>Sızıntı Tespit Edildi!</p>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                    {result.breaches && result.breaches.map((b, i) => (
                      <div key={i} style={{
                        padding: '10px 14px', background: theme.accentDim, borderRadius: theme.radiusSm,
                        borderLeft: `3px solid ${theme.accent}`,
                      }}>
                        <p style={{ fontSize: 12, fontWeight: 600, color: '#fff' }}>{b.name || b.source || 'Bilinmeyen'}</p>
                        <p style={{ fontSize: 11, color: theme.textMuted }}>{b.date ? new Date(b.date).toLocaleDateString('tr-TR') : ''} — {b.data_classes?.join(', ') || b.data || ''}</p>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <div style={{ textAlign: 'center', padding: 20 }}>
                  <span style={{ fontSize: 48 }}>✅</span>
                  <p style={{ color: theme.success, fontSize: 18, fontWeight: 700, marginTop: 8 }}>Sızıntı Bulunamadı</p>
                  <p style={{ color: theme.textMuted, fontSize: 13, marginTop: 4 }}>{email} adresi bilinen sızıntılarda yok</p>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>

      {/* Recent Breaches Table */}
      <Card>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 16, display: 'flex', gap: 8, alignItems: 'center' }}>
          <span>📋</span> Son Tespit Edilen Sızıntılar
        </h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: `2px solid ${theme.border}`, color: theme.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: '1px' }}>
                <th style={{ textAlign: 'left', padding: '12px 8px' }}>İhlal</th>
                <th style={{ textAlign: 'left', padding: '12px 8px' }}>Şirket</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Sızan Veri</th>
                <th style={{ textAlign: 'center', padding: '12px 8px' }}>Boyut</th>
                <th style={{ textAlign: 'right', padding: '12px 8px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {(!stats ? [] : [
                { name: 'Collection #1', company: 'Multiple', data: 'Email, Password', size: '773M', date: '2019-01' },
                { name: 'LinkedIn', company: 'LinkedIn', data: 'Email, Password', size: '500M', date: '2021-06' },
                { name: 'Facebook', company: 'Meta', data: 'Phone, Email, Name', size: '533M', date: '2021-04' },
                { name: 'Twitter', company: 'X Corp', data: 'Email, Username', size: '235M', date: '2022-12' },
              ]).map((breach, i) => (
                <tr key={i} style={{ borderBottom: `1px solid ${theme.border}` }}
                  onMouseEnter={e => e.currentTarget.style.background = theme.surface}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                >
                  <td style={{ padding: '10px 8px' }}>
                    <span style={{ color: '#fff', fontWeight: 600 }}>{breach.name}</span>
                  </td>
                  <td style={{ padding: '10px 8px', color: theme.textMuted }}>{breach.company}</td>
                  <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                    <span style={{ color: theme.text, fontSize: 12 }}>{breach.data}</span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                    <span style={{ padding: '2px 8px', borderRadius: '10px', fontSize: 11, background: theme.primaryDim, color: theme.primary }}>
                      {breach.size}
                    </span>
                  </td>
                  <td style={{ padding: '10px 8px', textAlign: 'right', color: theme.textMuted, fontSize: 11 }}>{breach.date}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      {/* Password & Intervention Section */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginTop: 32 }}>
        <Card>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span>🛡️</span> Şifre Güvenlik Önerileri
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { icon: '🔑', title: 'Eşsiz Şifre Kullanın', desc: 'Her platform için farklı şifre oluşturun' },
              { icon: '📏', title: 'Uzunluk Önemli', desc: 'En az 12 karakter, büyük/küçük harf + rakam + sembol' },
              { icon: '🔄', title: 'Düzenli Değiştirin', desc: '90 günde bir şifrelerinizi yenileyin' },
              { icon: '🔐', title: '2FA Açın', desc: 'İki faktörlü kimlik doğrulama kullanın' },
              { icon: '🕵️', title: 'Parola Yöneticisi', desc: 'Bitwarden, 1Password gibi araçlar kullanın' },
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start', padding: '10px 14px', background: theme.surface, borderRadius: theme.radiusSm }}>
                <span style={{ fontSize: 24 }}>{item.icon}</span>
                <div>
                  <p style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>{item.title}</p>
                  <p style={{ fontSize: 12, color: theme.textMuted }}>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card>
          <h3 style={{ fontSize: 16, fontWeight: 700, color: '#fff', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
            <span>🚨</span> Sızıntı Sonrası Müdahale
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              { step: '01', title: 'Panik Yapmayın', desc: 'Sakin olun ve adım adım ilerleyin' },
              { step: '02', title: 'Şifrenizi Hemen Değiştirin', desc: 'Sızdırılan platformdaki şifrenizi yenileyin' },
              { step: '03', title: 'Tüm Platformları Güncelleyin', desc: 'Aynı şifreyi kullandığınız yerleri değiştirin' },
              { step: '04', title: '2FA Aktifleştirin', desc: 'Tüm kritik hesaplarda 2FA açın' },
              { step: '05', title: 'Hesap Aktivitesini Kontrol Edin', desc: 'Şüpheli girişleri inceleyin' },
              { step: '06', title: 'İzlemeye Devam Edin', desc: 'Bu modül ile düzenli kontrol yapın' },
            ].map((item, i) => (
              <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                <span style={{
                  width: 28, height: 28, borderRadius: '50%',
                  background: theme.primaryDim, color: theme.primary,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 12, fontWeight: 700, flexShrink: 0,
                }}>{item.step}</span>
                <div>
                  <p style={{ fontSize: 13, fontWeight: 600, color: '#fff' }}>{item.title}</p>
                  <p style={{ fontSize: 12, color: theme.textMuted }}>{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  )
}
