/* eslint-disable react-refresh/only-export-components -- Shared hooks, primitives and formatters for lazy module entries. */
import { Component, useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Globe, CheckCircle, XCircle, Link2, AtSign } from 'lucide-react'

const API = import.meta.env.VITE_API_BASE_URL || '/api/v2'

function normalizeStatus(status) {
  const s = String(status || '').toLowerCase()
  return s === 'active' || s === 'online'
}

function useWindowWidth() {
  const [w, setW] = useState(typeof window !== 'undefined' ? window.innerWidth : 1200)
  useEffect(() => {
    const fn = () => setW(window.innerWidth)
    window.addEventListener('resize', fn, { passive: true })
    return () => window.removeEventListener('resize', fn)
  }, [])
  return w
}

class ModuleErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding:'96px 24px', maxWidth:900, margin:'0 auto' }}>
          <div style={{ padding:24, borderRadius:theme.radiusMd, background:theme.surface, border:`1px solid ${theme.border}`, boxShadow:theme.cardShadow }}>
            <p style={{ fontSize:12, fontWeight:600, color:theme.warning, marginBottom:12 }}>IOC Modülü Hatası</p>
            <h2 style={{ fontSize:28, fontWeight:600, color:'#fff', marginBottom:12 }}>Bu sekme geçici olarak yüklenemedi.</h2>
            <p style={{ color:theme.textMuted, fontSize:15, lineHeight:1.7, marginBottom:20 }}>IOC ekranında beklenmeyen bir render hatası oluştu. Sayfayı yenileyerek tekrar deneyebilirsin.</p>
            <button onClick={() => window.location.reload()} style={{ padding:'12px 18px', borderRadius:theme.radiusSm, border:'none', background:theme.gradientPrimary, color:'#000', fontWeight:600, cursor:'pointer' }}>Yeniden Yükle</button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

const theme = {
  // shadcn/ui "zinc" koyu paleti — siyah-beyaz; renk yalnızca anlam taşır.
  bg: '#09090b',
  bgDeep: '#09090b',
  surface: '#09090b',
  surface2: '#18181b',
  surface3: '#0f0f11',
  border: '#27272a',
  borderSoft: '#1f1f23',
  borderLight: 'rgba(39,39,42,0.6)',
  primary: '#fafafa',
  primaryDim: 'rgba(250,250,250,0.06)',
  primarySoft: 'rgba(250,250,250,0.1)',
  accent: '#ef4444',
  accentDim: 'rgba(239,68,68,0.1)',
  accentSoft: 'rgba(239,68,68,0.16)',
  violet: '#a1a1aa',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  text: '#fafafa',
  textMuted: '#a1a1aa',
  textSubtle: '#71717a',
  textDim: '#71717a',
  font: "'Geist', 'Inter', sans-serif",
  mono: "'Geist Mono', 'JetBrains Mono', monospace",
  navFont: "'Geist', 'Inter', sans-serif",
  radius: '8px',
  radiusSm: '6px',
  radiusMd: '8px',
  radiusLg: '12px',
  radiusXl: '16px',
  glow: 'none',
  cardShadow: '0 1px 2px rgba(0,0,0,0.3)',
  cardShadowHover: '0 1px 2px rgba(0,0,0,0.3)',
  gradientHero: 'none',
  gradientPrimary: '#fafafa',
  gradientAccent: '#ef4444',
  gradientSurface: '#09090b',
  gradientGlow: 'transparent',
  gridPattern: 'none',
  gridPatternSize: 'auto',
  shadow: {
    card: '0 1px 2px rgba(0,0,0,0.3)',
    glow: '0 1px 2px rgba(0,0,0,0.3)',
    glowStrong: '0 1px 2px rgba(0,0,0,0.3)',
  },
  ease: {
    out: 'cubic-bezier(0.16, 1, 0.3, 1)',
    spring: 'cubic-bezier(0.16, 1, 0.3, 1)',
  },
}

function HeroBackdrop() {
  // shadcn teması: dekoratif parıltı/ızgara yok.
  return null
}
function Spinner({ size = 20 }) {
  return <span style={{ display:'inline-block', width:size, height:size, border:'2px solid rgba(255,255,255,0.2)', borderTop:'2px solid #fff', borderRadius:'50%', animation:'spin 0.8s linear infinite' }} />
}

function Toast({ message, type='success', visible }) {
  if (!visible) return null
  const ok = type === 'success'
  return <div role="status" style={{ position:'fixed', bottom:24, right:24, zIndex:9999, padding:'12px 16px', borderRadius:8, background:'#09090b', border:'1px solid #27272a', color:'#fafafa', fontWeight:500, fontSize:14, boxShadow:'0 1px 2px rgba(0,0,0,0.3)', animation:'fadeInUp 0.2s ease', display:'flex', alignItems:'center', gap:10, maxWidth:420 }}>{ok?<CheckCircle size={16} color="#22c55e"/>:<XCircle size={16} color="#ef4444"/>}{message}</div>
}
function RiskBadge({ level, size='sm' }) {
  const colors = { critical:{bg:'rgba(239,68,68,0.12)',text:'#f87171',bd:'rgba(239,68,68,0.3)'}, high:{bg:'rgba(239,68,68,0.12)',text:'#f87171',bd:'rgba(239,68,68,0.3)'}, medium:{bg:'rgba(245,158,11,0.12)',text:'#fbbf24',bd:'rgba(245,158,11,0.3)'}, low:{bg:'rgba(34,197,94,0.12)',text:'#4ade80',bd:'rgba(34,197,94,0.3)'}, safe:{bg:'rgba(34,197,94,0.12)',text:'#4ade80',bd:'rgba(34,197,94,0.3)'} }
  const c = colors[level] || {bg:'#18181b',text:'#a1a1aa',bd:'#27272a'}
  const labels = { critical:'Kritik', high:'Yüksek', medium:'Orta', low:'Düşük', safe:'Güvenli' }
  return <span style={{ display:'inline-flex', alignItems:'center', padding:size==='sm'?'2px 8px':'4px 12px', background:c.bg, color:c.text, border:`1px solid ${c.bd}`, borderRadius:6, fontSize:size==='sm'?12:13, fontWeight:500 }}>{labels[level]||level}</span>
}
function StatusDot({ active }) {
  return <span style={{ display:'inline-block', width:8, height:8, borderRadius:'50%', background:active?theme.success:theme.danger, marginRight:6 }} />
}
function Card({ children, style, ...props }) {
  return <div style={{ background:'#09090b', border:'1px solid #27272a', borderRadius:12, padding:24, boxShadow:'0 1px 2px rgba(0,0,0,0.3)', ...style }} {...props}>{children}</div>
}
function GlowButton({ children, onClick, disabled, loading, variant='primary', style, ...props }) {
  // shadcn/ui Button: düz, sade; primary = beyaz zemin + siyah yazı, diğerleri outline.
  const isPrimary = variant === 'primary'
  const off = disabled || loading
  return <button onClick={onClick} disabled={off}
    onMouseEnter={e=>{ if(!off) e.currentTarget.style.background = isPrimary ? 'rgba(250,250,250,0.9)' : '#27272a' }}
    onMouseLeave={e=>{ e.currentTarget.style.background = isPrimary ? '#fafafa' : 'transparent' }}
    style={{ height:40, padding:'0 16px', borderRadius:6, cursor:off?'not-allowed':'pointer', fontSize:14, fontWeight:500, fontFamily:theme.font, background:isPrimary?'#fafafa':'transparent', color:isPrimary?'#18181b':'#fafafa', border:isPrimary?'1px solid transparent':'1px solid #27272a', transition:'background 0.15s ease', opacity:off?0.5:1, display:'inline-flex', alignItems:'center', justifyContent:'center', gap:8, whiteSpace:'nowrap', ...style }} {...props}>{loading&&<Spinner size={16}/>}{children}</button>
}
function CountUp({ end }) {
  // Sayı animasyonsuz, doğrudan gösterilir.
  return <>{(Number(end) || 0).toLocaleString('tr-TR')}</>
}
// Modül başlığı artık kabukta (ModulesApp) tek tip gösteriliyor; modül içinde
// tekrar başlık basılmaz. İmza, mevcut çağrılar kırılmasın diye korunuyor.
// eslint-disable-next-line no-unused-vars
function SectionHeader({ badge, title, subtitle }) {
  return null
}
function IkBolt({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
}

function IkSearch({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
}

function IkChart({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>
}

function IkMail({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="2,4 12,13 22,4"/></svg>
}

function IkBuilding({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="1"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
}

function IkBox({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
}

function IkShieldDoc({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L4 6v6c0 5.5 3.6 10.7 8 12 4.4-1.3 8-6.5 8-12V6L12 2z"/><line x1="9" y1="12" x2="15" y2="12"/><line x1="9" y1="9" x2="12" y2="9"/></svg>
}

function IkScope({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
}

function IkArrow({ size=14, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/></svg>
}

function IkWarn({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
}

function IkCrypto({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M11.767 19.089c4.924.868 6.14-6.025 1.216-6.894m-1.216 6.894L5.86 18.047m5.908 1.042-.347 1.97m1.563-8.864c4.924.869 6.14-6.025 1.215-6.893m-1.215 6.893-3.94-.694m5.155-6.2L8.29 5.328m5.908 1.042.348-1.97M7.48 20.364l3.126-17.727"/></svg>
}

function IkAlert({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
}

function IkClipboard({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><rect x="8" y="2" width="8" height="4" rx="1"/></svg>
}

function IkCamera({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></svg>
}

function IkMonitor({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
}

function IkChat({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
}

function IkPerson({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
}

function IkGrid({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
}

function IkCheck2({ size=14, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
}

function IkGlobe2({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>
}

function IkRadar({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M5.5 14.5A9 9 0 0 0 12 21a9 9 0 1 0-6.5-6.5"/><path d="M8 12a4 4 0 1 0 8 0 4 4 0 0 0-8 0"/><line x1="12" y1="12" x2="12" y2="3"/></svg>
}

function IkLink2({ size=16, color='currentColor' }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
}

function PlatformStatCounter({ target, suffix, label, color, fmt }) {
  // Sayı animasyonsuz, doğrudan gösterilir.
  const val = target || 0
  return (
    <div style={{ textAlign:'center', minWidth:90 }}>
      <div style={{ fontSize:24, fontWeight:600, color, lineHeight:1, fontFamily:theme.font }}>
        {fmt ? fmt(val) : val}{suffix}
      </div>
      <div style={{ fontSize:12, color:theme.textMuted, marginTop:6, fontWeight:500 }}>{label}</div>
    </div>
  )
}

function RiskGauge({ score, label, showPercentage = false, size = 'md', safetyMode = false }) {
  const sizeMap = {
    sm: { width: 80, height: 80, radius: 32, stroke: 6, fontSize: 16 },
    md: { width: 120, height: 120, radius: 40, stroke: 8, fontSize: 22 },
    lg: { width: 160, height: 160, radius: 56, stroke: 10, fontSize: 28 }
  }
  const { width, height, radius, stroke, fontSize } = sizeMap[size] || sizeMap.md
  
  // Skor animasyonsuz, doğrudan gösterilir.
  const displayScore = Math.round(Math.min(Number(score) || 0, 100))

  const c = 2 * Math.PI * radius
  const o = c - (Math.min(displayScore, 100) / 100) * c
  const color = safetyMode
    ? (score > 75 ? theme.success : score > 50 ? theme.primary : score > 25 ? theme.warning : theme.danger)
    : (score > 75 ? theme.danger : score > 50 ? theme.warning : score > 25 ? theme.primary : theme.success)
  const center = width / 2
  
  return <div style={{ display:'inline-flex', flexDirection:'column', alignItems:'center' }}>
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      <circle cx={center} cy={center} r={radius} fill="none" stroke={theme.border} strokeWidth={stroke}/>
      <circle 
        cx={center} cy={center} r={radius} fill="none" stroke={color} strokeWidth={stroke} 
        strokeDasharray={c} strokeDashoffset={o} 
        transform={`rotate(-90 ${center} ${center})`} 
        
        strokeLinecap="round"
      />
      <text x={center} y={center} textAnchor="middle" dominantBaseline="central" fill="#fafafa" fontSize={fontSize} fontWeight="600" fontFamily="Geist, Inter, sans-serif">
        {showPercentage ? `${displayScore}%` : displayScore}
      </text>
    </svg>
    <p style={{ fontSize: size === 'lg' ? 14 : 12, color:theme.textMuted, marginTop:10, fontWeight:600 }}>{label}</p>
  </div>
}

export { API, normalizeStatus, useWindowWidth, ModuleErrorBoundary, theme, Spinner, Toast, RiskBadge, StatusDot, Card, GlowButton, CountUp, SectionHeader, IkBolt, IkSearch, IkChart, IkMail, IkBuilding, IkBox, IkShieldDoc, IkScope, IkArrow, IkWarn, IkAlert, IkClipboard, IkCamera, IkMonitor, IkChat, IkPerson, IkGrid, IkCheck2, IkGlobe2, IkRadar, IkLink2, PlatformStatCounter, RiskGauge }
