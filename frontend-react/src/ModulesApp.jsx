import { Component, useState, useEffect, useRef, useCallback } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'
import gsap from 'gsap'
import { Shield, ShieldAlert, AlertTriangle, Activity, Globe, Search, Copy, Check, Wifi, Database, TrendingUp, Zap, Bug, Mail, Server, Hash, Radio, Eye, ChevronRight, BarChart3, Lock, Download, BrainCircuit, RadioTower, MapPin, LockKeyhole, CheckCircle, XCircle, Tag, AlertOctagon, Lightbulb, Link2, FileText, AtSign, Target } from 'lucide-react'
import logoImg from './assets/logo.png'
import TurkeyHeatmapSection from './components/TurkeyHeatmapSection.jsx'
import OnboardingOverlay from './components/OnboardingOverlay.jsx'
import { MODULES_URL, HOME_URL } from './lib/links'

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
          <div style={{ padding:32, borderRadius:theme.radiusMd, background:theme.surface, border:`1px solid ${theme.border}`, boxShadow:theme.cardShadow }}>
            <p style={{ fontSize:12, fontWeight:800, color:theme.warning, textTransform:'uppercase', letterSpacing:'1.5px', marginBottom:12 }}>IOC Modülü Hatası</p>
            <h2 style={{ fontSize:28, fontWeight:800, color:'#fff', marginBottom:12 }}>Bu sekme geçici olarak yüklenemedi.</h2>
            <p style={{ color:theme.textMuted, fontSize:15, lineHeight:1.7, marginBottom:20 }}>IOC ekranında beklenmeyen bir render hatası oluştu. Sayfayı yenileyerek tekrar deneyebilirsin.</p>
            <button onClick={() => window.location.reload()} style={{ padding:'12px 18px', borderRadius:theme.radiusSm, border:'none', background:theme.gradientPrimary, color:'#000', fontWeight:700, cursor:'pointer' }}>Yeniden Yükle</button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

const theme = {
  bg: '#080c14',
  bgDeep: '#05080f',
  surface: '#0f1629',
  surface2: '#1a2342',
  surface3: '#0c1322',
  border: '#1e2a4a',
  borderSoft: '#162038',
  borderLight: 'rgba(30,42,74,0.5)',
  primary: '#00d4ff',
  primaryDim: 'rgba(0,212,255,0.1)',
  primarySoft: 'rgba(0,212,255,0.18)',
  accent: '#ff6b35',
  accentDim: 'rgba(255,107,53,0.1)',
  accentSoft: 'rgba(255,107,53,0.18)',
  violet: '#9f7aea',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  text: '#e2e8f0',
  textMuted: '#64748b',
  textSubtle: '#475569',
  textDim: '#475569',
  font: "'Inter', sans-serif",
  mono: "'JetBrains Mono', monospace",
  navFont: 'ui-monospace, SFMono-Regular, "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace',
  radius: '12px',
  radiusSm: '8px',
  radiusMd: '12px',
  radiusLg: '18px',
  radiusXl: '24px',
  glow: '0 0 40px rgba(0,212,255,0.08)',
  cardShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.5)',
  cardShadowHover: '0 35px 60px -15px rgba(0, 212, 255, 0.15)',
  gradientHero: 'radial-gradient(ellipse at 50% 0%, rgba(0,212,255,0.18) 0%, transparent 60%), radial-gradient(ellipse at 50% 100%, rgba(159,122,234,0.12) 0%, transparent 65%)',
  gradientPrimary: 'linear-gradient(135deg, #00d4ff, #0099cc)',
  gradientAccent: 'linear-gradient(135deg, #ff6b35, #c9472b)',
  gradientSurface: 'linear-gradient(145deg, #0f1629 0%, #1a2342 100%)',
  gradientGlow: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.4), transparent)',
  gridPattern: `
    linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px)
  `,
  gridPatternSize: '48px 48px',
  shadow: {
    card: '0 10px 30px rgba(0,0,0,0.35)',
    glow: '0 0 40px rgba(0,212,255,0.18)',
    glowStrong: '0 0 60px rgba(0,212,255,0.35)',
  },
  ease: {
    out: 'cubic-bezier(0.16, 1, 0.3, 1)',
    spring: 'cubic-bezier(0.175, 0.885, 0.32, 1.275)',
  },
}

function HeroBackdrop() {
  return (
    <div aria-hidden style={{ position:'fixed', top:0, left:0, right:0, bottom:0, pointerEvents:'none', overflow:'hidden', zIndex:-1 }}>
      <div style={{
        position:'absolute',
        inset:0,
        backgroundImage:theme.gridPattern,
        backgroundSize:theme.gridPatternSize,
        maskImage:'radial-gradient(ellipse at 50% 40%, #000 35%, transparent 75%)',
        WebkitMaskImage:'radial-gradient(ellipse at 50% 40%, #000 35%, transparent 75%)',
        opacity:0.7
      }} />
      <div style={{ position:'absolute', inset:0, background:theme.gradientHero }} />
      <div style={{
        position:'absolute',
        top:'20%',
        left:'50%',
        transform:'translateX(-50%)',
        width:720,
        height:720,
        borderRadius:'50%',
        background:'radial-gradient(circle, rgba(0,212,255,0.18) 0%, transparent 70%)',
        filter:'blur(20px)'
      }} />
    </div>
  )
}

function Spinner({ size = 20 }) {
  return <span style={{ display:'inline-block', width:size, height:size, border:'2px solid rgba(255,255,255,0.2)', borderTop:'2px solid #fff', borderRadius:'50%', animation:'spin 0.8s linear infinite' }} />
}

function Toast({ message, type='success', visible }) {
  if (!visible) return null
  return <div style={{ position:'fixed', bottom:30, right:30, zIndex:9999, padding:'14px 24px', borderRadius:theme.radiusSm, background:type==='success'?'#22c55e':'#ef4444', color:'#fff', fontWeight:600, fontSize:14, boxShadow:'0 10px 40px rgba(0,0,0,0.4)', animation:'fadeInUp 0.3s ease', display:'flex', alignItems:'center', gap:8 }}>{type==='success'?<CheckCircle size={16}/>:<XCircle size={16}/>}{message}</div>
}

function RiskBadge({ level, size='sm' }) {
  const colors = { critical:{bg:'rgba(239,68,68,0.2)',text:'#ef4444'}, high:{bg:'rgba(255,107,53,0.2)',text:'#ff6b35'}, medium:{bg:'rgba(245,158,11,0.2)',text:'#f59e0b'}, low:{bg:'rgba(34,197,94,0.2)',text:'#22c55e'}, safe:{bg:'rgba(0,212,255,0.2)',text:'#00d4ff'} }
  const c = colors[level] || {bg:'rgba(100,116,139,0.2)',text:'#64748b'}
  const labels = { critical:'Kritik', high:'Yüksek', medium:'Orta', low:'Düşük', safe:'Güvenli' }
  return <span style={{ display:'inline-block', padding:size==='sm'?'3px 10px':'6px 16px', background:c.bg, color:c.text, borderRadius:'20px', fontSize:size==='sm'?11:13, fontWeight:700, textTransform:'uppercase', letterSpacing:'0.5px' }}>{labels[level]||level}</span>
}

function StatusDot({ active }) {
  return <span style={{ display:'inline-block', width:8, height:8, borderRadius:'50%', background:active?theme.success:theme.danger, boxShadow:`0 0 8px ${active?theme.success:theme.danger}66`, marginRight:6 }} />
}

function Card({ children, style, ...props }) {
  const [h,sH]=useState(false)
  return <motion.div onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)} initial={false} animate={{ scale:h?1.02:1, boxShadow:h?theme.shadow.glow:theme.shadow.card }} transition={{ duration:0.3, ease:theme.ease.spring }} style={{ background:theme.gradientSurface, border:`1px solid ${h?theme.primary+'66':theme.border}`, borderRadius:theme.radiusMd, padding:24, ...style }} {...props}>{children}</motion.div>
}

function GlowButton({ children, onClick, disabled, loading, variant='primary', style, ...props }) {
  const isPrimary=variant==='primary'
  return <motion.button onClick={onClick} disabled={disabled||loading} initial={false} whileHover={disabled||loading ? undefined : { scale:1.02, boxShadow:isPrimary?'0 8px 30px rgba(0,212,255,0.4)':`0 8px 30px ${theme.primary}33` }} whileTap={disabled||loading ? undefined : { scale:0.98 }} style={{ padding:'14px 32px', borderRadius:theme.radiusSm, cursor:disabled?'not-allowed':'pointer', fontSize:14, fontWeight:700, letterSpacing:'0.5px', fontFamily:theme.navFont, background:isPrimary?theme.gradientPrimary:'transparent', color:isPrimary?'#000':theme.primary, border:isPrimary?'none':`1px solid ${theme.primary}44`, transition:'all 0.3s ease', opacity:disabled?0.5:1, display:'inline-flex', alignItems:'center', gap:8, boxShadow:isPrimary?'0 4px 20px rgba(0,212,255,0.3)':'none', ...style }} {...props}>{loading&&<Spinner size={18}/>}{children}</motion.button>
}

function CountUp({ end, duration=1500 }) {
  const [val,setVal]=useState(0);const ref=useRef(null)
  useEffect(()=>{const start=performance.now();const animate=(now)=>{const elapsed=now-start;const progress=Math.min(elapsed/duration,1);const eased=1-Math.pow(1-progress,3);setVal(Math.floor(eased*end));if(progress<1)ref.current=requestAnimationFrame(animate)};ref.current=requestAnimationFrame(animate);return()=>cancelAnimationFrame(ref.current)},[end,duration])
  return <>{val.toLocaleString('tr-TR')}</>
}

function SectionHeader({ badge, title, subtitle }) {
  return <motion.div initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} transition={{ duration:0.5, ease:theme.ease.out }} style={{ textAlign:'center', marginBottom:48 }}>
    <motion.span initial={{ opacity:0, scale:0.9 }} animate={{ opacity:1, scale:1 }} transition={{ delay:0.1, duration:0.4, ease:theme.ease.spring }} style={{ display:'inline-block', padding:'6px 16px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'20px', fontSize:11, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'1.5px', marginBottom:16 }}>{badge}</motion.span>
    <motion.h1 initial={{ opacity:0, y:10 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.2, duration:0.5, ease:theme.ease.out }} style={{ fontSize:36, fontWeight:800, color:'#fff', marginBottom:12, letterSpacing:'-1px' }}>{title}</motion.h1>
    <motion.p initial={{ opacity:0, y:10 }} animate={{ opacity:1, y:0 }} transition={{ delay:0.3, duration:0.5, ease:theme.ease.out }} style={{ color:theme.textMuted, fontSize:16, maxWidth:600, margin:'0 auto', lineHeight:1.6 }}>{subtitle}</motion.p>
  </motion.div>
}

/* ── Custom SVG Icon Palette ─────────────────────────────────── */
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

function translateSignalCategory(category) {
  const labels = {
    prize_scam: 'Ödül Dolandırıcılığı',
    bank_scam: 'Banka Sahteciliği',
    delivery_scam: 'Kargo / Teslimat Sahteciliği',
    authority_scam: 'Resmi Kurum Taklidi',
    investment_scam: 'Yatırım Dolandırıcılığı',
    romance_scam: 'Romantik Tuzak',
    credential_harvest: 'Kimlik Bilgisi Toplama',
    urgency_compound: 'Aciliyet Bileşimi',
    reply_to_mismatch: 'Reply-To Uyuşmazlığı',
    display_name_mismatch: 'Görünen Ad Taklidi',
    sender_domain_suspicious: 'Şüpheli Gönderici Domaini',
    subject_urgency: 'Konu Satırı Aciliyeti',
  }
  return labels[category] || category
}

function parseEmailPreview(rawMessage) {
  const lines = String(rawMessage || '').split(/\r?\n/)
  const header = {}
  let bodyIndex = lines.findIndex(line => line.trim() === '')
  if (bodyIndex < 0) bodyIndex = Math.min(lines.length, 20)

  for (const line of lines.slice(0, bodyIndex)) {
    const match = line.match(/^\s*(From|Reply-To|Subject|Date):\s*(.*)$/i)
    if (match) header[match[1].toLowerCase()] = match[2].trim()
  }

  const from = header.from || ''
  const replyTo = header['reply-to'] || ''
  const subject = header.subject || ''
  const date = header.date || ''
  const fromDomain = (from.match(/@([^>\s]+)/) || [])[1] || ''
  const replyDomain = (replyTo.match(/@([^>\s]+)/) || [])[1] || ''
  const replyToMismatch = Boolean(fromDomain && replyDomain && fromDomain.toLowerCase() !== replyDomain.toLowerCase())

  return { from, replyTo, subject, date, fromDomain, replyDomain, replyToMismatch }
}

export default function ModulesApp() {
  const [page, setPage] = useState('ai-analyzer')
  const [prefillPhishingUrl, setPrefillPhishingUrl] = useState('')
  const [prefillIocQuery, setPrefillIocQuery] = useState('')
  const [prefillVictimAtlasProfile, setPrefillVictimAtlasProfile] = useState(null)
  const [scrolled, setScrolled] = useState(false)
  const isMobile = useWindowWidth() < 768

  function navigateTo(targetPage, prefillValue = '', profileData = null) {
    if (targetPage === 'phishing-detector') setPrefillPhishingUrl(prefillValue)
    if (targetPage === 'honeypot') setPrefillIocQuery(prefillValue)
    if (targetPage === 'victim-atlas' && profileData) setPrefillVictimAtlasProfile(profileData)
    setPage(targetPage)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }
  const reducedMotion = useReducedMotion() ?? false
  useEffect(()=>{const onScroll=()=>setScrolled(window.scrollY>20);window.addEventListener('scroll',onScroll,{passive:true});return()=>window.removeEventListener('scroll',onScroll)},[])

  const tabs = [
    {id:'ai-analyzer',      label:'AI Analiz',          Icon: BrainCircuit},
    {id:'phishing-detector',label:'Phishing',             Icon: RadioTower},
    {id:'victim-atlas',     label:'Mağduriyet Atlası',    Icon: MapPin},
    {id:'honeypot',         label:'IOC / Tuzak',          Icon: Bug},
    {id:'breach-intel',     label:'Sızıntı',              Icon: ShieldAlert},
    {id:'password-shield',  label:'Şifre Kalkanı',        Icon: LockKeyhole},
  ]

  return <div style={{ minHeight:'100vh', background:theme.bg, color:theme.text, position:'relative' }}>
    <HeroBackdrop />
    <style>{`
      @keyframes spin { to { transform:rotate(360deg) } }
      @keyframes fadeInUp { from { opacity:0; transform:translateY(20px) } to { opacity:1; transform:translateY(0) } }
      @keyframes slideInLeft { from { opacity:0; transform:translateX(-30px) } to { opacity:1; transform:translateX(0) } }
      @keyframes slideInRight { from { opacity:0; transform:translateX(30px) } to { opacity:1; transform:translateX(0) } }
      @keyframes scaleIn { from { opacity:0; transform:scale(0.9) } to { opacity:1; transform:scale(1) } }
      @keyframes floatPulse { 0% { transform:translateY(0px) } 50% { transform:translateY(-4px) } 100% { transform:translateY(0px) } }
      @keyframes cardFlip { 0% { transform:rotateY(0deg) } 100% { transform:rotateY(180deg) } }
      @keyframes cardFlipBack { 0% { transform:rotateY(180deg) } 100% { transform:rotateY(0deg) } }
      @keyframes glowPulse { 0%, 100% { box-shadow: 0 0 20px rgba(0,212,255,0.3) } 50% { box-shadow: 0 0 40px rgba(0,212,255,0.6) } }
      @keyframes shimmer { 0% { background-position: -200% 0 } 100% { background-position: 200% 0 } }
      * { scrollbar-width:thin; scrollbar-color:${theme.border} transparent; }
      ::-webkit-scrollbar { width:6px }
      ::-webkit-scrollbar-track { background:transparent }
      ::-webkit-scrollbar-thumb { background:${theme.border}; border-radius:3px }
    `}</style>

    <nav style={{ position:'fixed', top:0, left:0, right:0, zIndex:1000, background:scrolled?'rgba(8,12,20,0.92)':'rgba(8,12,20,0.55)', backdropFilter:'blur(20px)', WebkitBackdropFilter:'blur(20px)', borderBottom:`1px solid ${scrolled?theme.border:'transparent'}`, transition:'background 220ms ease, border-color 220ms ease', padding:'0 24px' }}>
      <div style={{ maxWidth:1400, margin:'0 auto', display:'flex', alignItems:'center', justifyContent:'space-between', height:70 }}>
        <a
          href={MODULES_URL}
          style={{ display:'flex', alignItems:'center', gap:12, textDecoration:'none', cursor:'pointer' }}
        >
          <img src={logoImg} alt="AegisNexus" width={40} height={40} style={{ objectFit:'contain', display:'block' }} />
          <span style={{ fontSize:20, fontWeight:700, color:'#fff', letterSpacing:'-0.5px' }}>Aegis<span style={{ color:theme.primary }}>Nexus</span></span>
          <span style={{ fontSize:10, fontWeight:700, color:theme.primary, background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:6, padding:'3px 8px', letterSpacing:'2px', textTransform:'uppercase', marginLeft:2 }}>Modüller</span>
        </a>
        <div style={{ display:'flex', gap:4, background:theme.surface, borderRadius:theme.radiusSm, padding:3 }}>
          {tabs.map(t => <motion.button key={t.id} onClick={()=>setPage(t.id)} initial={false} whileHover={reducedMotion ? undefined : { scale:1.02 }} whileTap={reducedMotion ? undefined : { scale:0.98 }} title={t.label} style={{ padding: isMobile ? '8px 10px' : '8px 18px', borderRadius:'6px', border:'none', cursor:'pointer', fontSize:13, fontWeight:600, fontFamily:theme.navFont, background:page===t.id?theme.primary:'transparent', color:page===t.id?'#000':theme.textMuted, transition:'all 0.2s ease', display:'flex', alignItems:'center', gap:6, position:'relative' }}>
            <t.Icon size={14} />{!isMobile && <span>{t.label}</span>}
            {page===t.id && <motion.span initial={{scaleX:0}} animate={{scaleX:1}} transition={{duration:0.3}} style={{ position:'absolute', bottom:0, left:0, right:0, height:2, background:theme.primary, borderRadius:1 }} />}
          </motion.button>)}
        </div>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          {!isMobile && (
            <motion.a href={HOME_URL} style={{ fontSize:13, color:theme.textMuted, textDecoration:'none', padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, transition:'all 0.2s' }}
              whileHover={{ scale:1.02, borderColor:theme.primary+'44', color:theme.primary }}
              whileTap={{ scale:0.98 }}>← Ana Sayfa</motion.a>
          )}
        </div>
      </div>
    </nav>

    <OnboardingOverlay />

    <motion.main initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} transition={{ duration:0.5, ease:theme.ease.out }} style={{ paddingTop:86, maxWidth:1400, margin:'0 auto', padding: isMobile ? '86px 12px 0' : '86px 24px 0' }}>
      {page==='ai-analyzer' && <AIAnalyzer onGoVictimAtlas={()=>setPage('victim-atlas')} onNavigate={navigateTo} />}
      {page==='phishing-detector' && <PhishingDetector initialUrl={prefillPhishingUrl} onClearPrefill={()=>setPrefillPhishingUrl('')} />}
      {page==='victim-atlas' && <VictimAtlas onOpenAIAnalyzer={()=>setPage('ai-analyzer')} initialProfile={prefillVictimAtlasProfile} onClearProfile={()=>setPrefillVictimAtlasProfile(null)} />}
      {page==='honeypot' && <ModuleErrorBoundary><HoneypotIOC initialIocQuery={prefillIocQuery} onClearPrefill={()=>setPrefillIocQuery('')} /></ModuleErrorBoundary>}
      {page==='breach-intel' && <BreachIntelMaintenance />}
      {page==='password-shield' && <PasswordShield />}
    </motion.main>
    <footer style={{ borderTop:`1px solid ${theme.border}`, padding:'24px', textAlign:'center', color:theme.textMuted, fontSize:13, marginTop:80 }}>
      <div style={{ maxWidth:1400, margin:'0 auto' }}>
        <p>AegisNexus Modüller &copy; 2026</p>
        <div style={{ display:'flex', gap:24, justifyContent:'center', marginTop:12 }}>
          <a href={API+'/docs'} style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">API Docs</a>
          <a href={HOME_URL} style={{ color:theme.primary, textDecoration:'none' }} target="_blank">Ana Sayfa</a>
        </div>
      </div>
    </footer>
  </div>
}

/* ===============================================
   AI ANALYZER
   =============================================== */
function AIAnalyzer({ onGoVictimAtlas, onNavigate }) {
  const [message, setMessage] = useState('')
  const [messageType, setMessageType] = useState('text')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [demoLoading, setDemoLoading] = useState(null)
  const isMobile = useWindowWidth() < 768
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })
  const resultRef = useRef(null)
  const emailPreview = messageType === 'email' ? parseEmailPreview(message) : null

  async function handleAnalyze() {
    if (!message || message.length < 10) { showToast('En az 10 karakter girin', 'error'); return }
    setAnalyzing(true); setResult(null)
    try {
      const r = await fetch(`${API}/ai-analyzer/analyze`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ message, message_type:messageType }),
      })
      if (!r.ok) { const e=await r.json(); throw new Error(e.detail||'Analiz hatasi') }
      const d = await r.json(); setResult(d)
      setTimeout(()=>resultRef.current?.scrollIntoView({behavior:'smooth',block:'start'}),200)
    } catch(e) { showToast('Analiz hatasi: '+e.message, 'error') }
    setAnalyzing(false)
  }

  function showToast(msg, type='success') { setToast({message:msg,type,visible:true}); setTimeout(()=>setToast(t=>({...t,visible:false})),3000) }

  async function handleDemo(demoKey, text) {
    setDemoLoading(demoKey)
    setMessageType('text')
    setMessage(text)
    setResult(null)
    await new Promise(r => setTimeout(r, 400))
    setDemoLoading(null)
    setAnalyzing(true)
    try {
      const r = await fetch(`${API}/ai-analyzer/analyze`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ message: text, message_type: 'text' }),
      })
      if (!r.ok) { const e=await r.json(); throw new Error(e.detail||'Analiz hatasi') }
      const d = await r.json(); setResult(d)
      setTimeout(()=>resultRef.current?.scrollIntoView({behavior:'smooth',block:'start'}),200)
    } catch(e) { showToast('Demo analiz hatasi: '+e.message,'error') }
    setAnalyzing(false)
  }

  const DEMO_SCENARIOS = [
    {
      key: 'ptt',
      Icon: IkBox,
      title: 'PTT Kargo Tuzağı',
      desc: 'Gümrük ücreti sahte SMS',
      text: 'PTT KARGO: Gondeniniz (TR88291047) teslim edilemedi. Adres dogrulama ve 14,90 TL gumruk isleme ucreti odenmeden kargo iade edilecektir. Son gun: bugun!\n\nOdeme ve Adres Guncelle: https://ptt-kargo-odeme.top/islem?id=TR88291047&son=2026-05-10\n\nBu mesaj PTT tarafindan gonderilmistir.',
    },
    {
      key: 'akbank',
      Icon: IkBuilding,
      title: 'Akbank Hesap Askıya Alma',
      desc: 'Sahte güvenlik SMS\'i',
      text: 'AKBANK: Hesabiniza tanimsiz cihazdan giris yapildi. Giris engellendi, hesabiniz gecici kisitlamaya alindi. 2 saat icinde dogrulamazsiniz hesabiniz kapatilacak.\n\nHesap Dogrulama: https://akbank-guvenlik.xyz/hesap-dogrula?s=91kT3pRm&islem=acil\n\nAkbank Musteri Hizmetleri: 444 2 525',
    },
    {
      key: 'sgk',
      Icon: IkShieldDoc,
      title: 'SGK / e-Devlet Kimlik Avı',
      desc: 'Resmi kurum taklit e-posta',
      text: 'e-Devlet Bildirimi: SGK kaydinizdaki 1.247,00 TL gecikmiş prim borcunuz icin yasal surec baslatilmaktadir. TC kimliginizi ve e-Devlet sifrenizle giris yaparak borcunuzu odeyebilirsiniz.\n\nBorc Sorgula: https://edevlet-sgk-sorgula.net/borc-odeme?tc=XXXXXXXXXX&dogrulama=TR2026\n\nSosyal Guvenlik Kurumu Baskanligi',
    },
  ]

  const examples = [
    ...(messageType === 'email'
      ? [
          {
            label: 'Garanti BBVA Phishing Maili',
            text: 'From: Garanti BBVA Güvenlik <bildirim@garanti-guvenlik.net>\nReply-To: destek@garanti-bbva-help.xyz\nSubject: ⚠️ Hesabınız 24 Saat İçinde Askıya Alınacak — Kimlik Doğrulama Zorunlu\nDate: Sat, 10 May 2026 08:14:33 +0300\n\nSayın Değerli Müşterimiz,\n\nSistemimizde hesabınıza ait kimliği belirsiz bir IP adresinden oturum açma girişimi tespit edilmiştir. Hesabınızın güvenliğini korumak amacıyla lütfen aşağıdaki doğrulama adımını tamamlayınız.\n\n▶ Hesabımı Doğrula: https://garanti-guvenlik.net/dogrula?musteri=4471&token=8f3kL9xZ2mQ\n\nBu işlemi 24 saat içinde tamamlamazsanız hesabınız geçici olarak kısıtlanacaktır.\n\nSaygılarımızla,\nGaranti BBVA Güvenlik ve Dolandırıcılık Önleme Birimi\nTel: 0212 318 18 18',
          },
          {
            label: 'SGK / E-Devlet Kimlik Avı',
            text: 'From: e-Devlet Kapısı <bildirim@edevlet-bildirim.org>\nReply-To: destek@edevlet-portal-tr.com\nSubject: SGK Prim Borcunuz Hakkında Acil Bildirim — Yasal Süreç Başlatılıyor\nDate: Sat, 10 May 2026 09:41:00 +0300\n\nSayın Vatandaşımız,\n\nSGK kayıtlarınızda 1.247,00 TL tutarında gecikmiş prim borcunuz tespit edilmiştir. Yasal işlem başlatılmadan önce borcunuzu e-Devlet üzerinden ödeyebilirsiniz.\n\n▶ Borç Sorgula ve Öde: https://edevlet-sgk-sorgula.net/borc-odeme?tc=XXXXXXXXXX&dogrulama=TR2026\n\nYukarıdaki linke tıklayarak TC Kimlik numaranız ve e-Devlet şifrenizle giriş yapıp borcunuzu ödeyebilirsiniz.\n\nSosyal Güvenlik Kurumu\nBaşkanlık İletişim Merkezi: 170',
          },
        ]
      : [
          {
            label: 'Kripto Yatırım Dolandırıcılığı',
            text: 'ACIL BILDIRIM: Kripto portfoyunuze 0.47 BTC (yaklasik 44.800 TL) yatirim odulu tanimlanmistir. Cekebilmek icin once 350 TL aktivasyon ucreti yatirilmasi gerekmektedir. Islem gecerliligi: 3 SAAT!\n\nCekim Paneli: https://btc-kazanc-platform.xyz/cek?ref=TK8821&kullanici=tr_user\n\nDestek Hatti: +90 532 901 44 21\nTelegram: @btckazanc_destek',
          },
          {
            label: 'Akbank Hesap Askıya Alma SMS',
            text: 'AKBANK: Hesabiniza tanimsiz cihazdan giris yapildi. Giris engellendi, hesabiniz gecici kisitlamaya alindi. 2 saat icinde dogrulamazsiniz hesabiniz kapatilacak.\n\nHesap Dogrulama: https://akbank-guvenlik.xyz/hesap-dogrula?s=91kT3pRm&islem=acil\n\nAkbank Musteri Hizmetleri: 444 2 525',
          },
          {
            label: 'PTT Kargo Ücret Tuzağı',
            text: 'PTT KARGO: Gondeniniz (TR88291047) teslim edilemedi. Adres dogrulama ve 14,90 TL gumruk isleme ucreti odenmeden kargo iade edilecektir. Son gun: bugun!\n\nOdeme ve Adres Guncelle: https://ptt-kargo-odeme.top/islem?id=TR88291047&son=2026-05-10\n\nBu mesaj PTT tarafindan gonderilmistir.',
          },
        ])
  ]

  const sa = result?.security_assessment||{}
  const da = result?.detailed_analysis||{}
  const score = typeof sa?.score==='number'?Math.round(sa.score):(result?.security_assessment?.score !== undefined ? Math.round(result.security_assessment.score) : 50)
  const isPhishing = result?.security_assessment?.is_phishing === true
  const isScam = result?.security_assessment?.is_scam === true
  const recs = result?.recommendations||[]
  const beliefs = da?.ai_analysis?.psychological_triggers||da?.psychological_triggers||[]
  const threats = da?.ai_analysis?.identified_threats||da?.identified_threats||[]
  const suspects = da?.ai_analysis?.suspicious_elements||da?.suspicious_elements||[]
  const parsedEmail = result?.parsed_email || da?.parsed_email || null
  const emailSignals = result?.email_signals || da?.email_signals || parsedEmail?.email_signals || null

  return <div>
    <Toast {...toast} />
    
    {/* Hero Section - Main Site Style */}
    <motion.div 
      initial={{ opacity:0, y:30 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.8, ease:theme.ease.out }}
      style={{ 
        position:'relative',
        padding:'120px 24px 80px',
        marginBottom:32,
        overflow:'hidden'
      }}
    >
      <div aria-hidden style={{ position:'absolute', inset:0, pointerEvents:'none', overflow:'hidden' }}>
        <div style={{ position:'absolute', inset:0, backgroundImage:theme.gridPattern, backgroundSize:theme.gridPatternSize, maskImage:'radial-gradient(ellipse at 50% 40%, #000 35%, transparent 75%)', WebkitMaskImage:'radial-gradient(ellipse at 50% 40%, #000 35%, transparent 75%)', opacity:0.7 }} />
        <div style={{ position:'absolute', inset:0, background:theme.gradientHero }} />
        <div style={{ position:'absolute', top:'20%', left:'50%', transform:'translateX(-50%)', width:'600px', height:'600px', background:theme.primary, borderRadius:'50%', filter:'blur(120px)', opacity:0.15 }} />
        <div style={{ position:'absolute', bottom:'20%', right:'20%', width:'400px', height:'400px', background:theme.accent, borderRadius:'50%', filter:'blur(100px)', opacity:0.1 }} />
      </div>
      
      <div style={{ position:'relative', zIndex:1, maxWidth:1200, margin:'0 auto' }}>
        <motion.div 
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.2, duration:0.6, ease:theme.ease.out }}
          style={{ textAlign:'center', marginBottom:48 }}
        >
          <span style={{ display:'inline-block', padding:'10px 24px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'30px', fontSize:13, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'3px', marginBottom:24 }}>AI Analiz Modülü</span>
          <h1 style={{ fontSize: isMobile ? 32 : 56, fontWeight:800, color:'#fff', marginBottom:20, letterSpacing:'-2px', lineHeight:1.1 }}>Yapay Zeka ile Güvenlik Analizi</h1>
          <p style={{ color:theme.textMuted, fontSize:18, maxWidth:760, margin:'0 auto', lineHeight:1.6 }}>SMS, e-posta veya metin içeriğini yapıştırın. Yapay zeka, phishing, smishing ve sosyal mühendislik saldırılarını otomatik tespit eder ve detaylı risk analizi sunar.</p>
          
          {/* Platform Stats Counters */}
          <div style={{ display:'flex', justifyContent:'center', gap: isMobile ? 20 : 48, flexWrap:'wrap', margin:'28px auto 0', maxWidth:640 }}>
            {[
              { target:1500000, suffix:'+', label:'Korunan URL', color:theme.primary, fmt:(n) => n >= 1000000 ? (n/1000000).toFixed(1)+'M' : n >= 1000 ? (n/1000).toFixed(0)+'K' : n },
              { target:30,      suffix:'+', label:'Türk Kurumu', color:theme.warning, fmt:(n) => n },
              { target:17,      suffix:'',  label:'Gov Kuralı',  color:theme.success, fmt:(n) => n },
            ].map((stat,i) => (
              <PlatformStatCounter key={stat.label} target={stat.target} suffix={stat.suffix} label={stat.label} color={stat.color} fmt={stat.fmt} delay={i * 0.2} />
            ))}
          </div>
          
          <div style={{ marginTop:20 }}>
            <GlowButton variant="secondary" onClick={onGoVictimAtlas}><MapPin size={14}/> Mağduriyet Atlasına Geç</GlowButton>
          </div>
        </motion.div>
      </div>
    </motion.div>


    {/* Demo Scenarios */}
    <motion.div
      initial={{ opacity:0, y:16 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.35, duration:0.5, ease:theme.ease.out }}
      style={{ maxWidth:1200, margin:'0 auto 28px' }}
    >
      <p style={{ fontSize:11, fontWeight:800, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'2.5px', marginBottom:14, display:'flex', alignItems:'center', gap:8 }}><IkBolt size={13} color={theme.textMuted}/> Canlı Demo — Gerçek Phishing Senaryoları</p>
      <div style={{ display:'grid', gridTemplateColumns:`repeat(${isMobile ? 1 : 3}, 1fr)`, gap:10 }}>
        {DEMO_SCENARIOS.map(sc => {
          const isLoading = demoLoading === sc.key || (analyzing && message === sc.text)
          return (
            <motion.button
              key={sc.key}
              onClick={() => !analyzing && !demoLoading && handleDemo(sc.key, sc.text)}
              disabled={!!analyzing || !!demoLoading}
              whileHover={!analyzing && !demoLoading ? { borderColor:theme.primary+'66' } : undefined}
              whileTap={!analyzing && !demoLoading ? { scale:0.98 } : undefined}
              style={{
                padding:'16px 18px',
                borderRadius:theme.radiusMd,
                background:theme.surface,
                border:`1px solid ${isLoading ? theme.primary+'66' : theme.border}`,
                cursor: analyzing || demoLoading ? 'not-allowed' : 'pointer',
                textAlign:'left',
                transition:'border-color 0.2s ease',
                opacity: (analyzing || demoLoading) && !isLoading ? 0.4 : 1,
              }}
            >
              <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
                <span style={{ color:isLoading ? theme.primary : theme.textMuted, flexShrink:0 }}><sc.Icon size={16}/></span>
                <span style={{ fontSize:13, fontWeight:700, color:isLoading ? theme.primary : theme.text }}>{sc.title}</span>
                {isLoading && (
                  <motion.span
                    animate={{ rotate:360 }}
                    transition={{ repeat:Infinity, duration:0.8, ease:'linear' }}
                    style={{ marginLeft:'auto', width:14, height:14, borderRadius:'50%', border:`2px solid ${theme.primary}`, borderTopColor:'transparent', display:'block', flexShrink:0 }}
                  />
                )}
              </div>
              <p style={{ fontSize:12, color:theme.textMuted, margin:0, lineHeight:1.4 }}>{sc.desc}</p>
            </motion.button>
          )
        })}
      </div>
    </motion.div>

    {/* Main Content - Glassmorphism Cards */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.4, duration:0.6, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap:24, marginBottom:48 }}
    >
      <Card style={{ 
        background:'rgba(255,255,255,0.03)',
        backdropFilter:'blur(10px)',
        WebkitBackdropFilter:'blur(10px)',
        border:`1px solid ${theme.border}`,
        padding:32
      }}>
        <motion.h3 
          initial={{ opacity:0, x:-20 }}
          animate={{ opacity:1, x:0 }}
          transition={{ delay:0.5, duration:0.4 }}
          style={{ fontSize:20, fontWeight:700, color:'#fff', marginBottom:24, display:'flex', gap:10, alignItems:'center' }}
        >
          <IkSearch size={18} color={theme.primary}/> Analiz Edilecek Metin
        </motion.h3>
        
        <motion.div 
          initial={{ opacity:0, y:10 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.6, duration:0.4 }}
          style={{ display:'flex', gap:10, marginBottom:20, flexWrap:'wrap' }}
        >
          {[{id:'text',label:'Metin',Icon:FileText},{id:'email',label:'Mail Taslağı',Icon:AtSign}].map((c,i)=>
            <motion.button 
              key={c.id} 
              onClick={()=>setMessageType(c.id)} 
              whileHover={{ scale:1.05 }}
              whileTap={{ scale:0.95 }}
              initial={{ opacity:0, y:10 }}
              animate={{ opacity:1, y:0 }}
              transition={{ delay:0.7 + i*0.1, duration:0.3 }}
              style={{ 
                padding:'10px 18px', 
                borderRadius:'24px', 
                border:'1px solid', 
                cursor:'pointer', 
                fontSize:13, 
                fontWeight:600, 
                background:messageType===c.id?theme.primary:'rgba(255,255,255,0.05)', 
                borderColor:messageType===c.id?theme.primary:theme.border, 
                color:messageType===c.id?'#000':theme.textMuted,
                transition:'all 0.3s ease'
              }}
            >
              <c.Icon size={13}/> {c.label}
            </motion.button>
          )}
        </motion.div>

        {messageType === 'email' && (
          <motion.div
            initial={{ opacity:0, y:10 }}
            animate={{ opacity:1, y:0 }}
            transition={{ delay:0.75, duration:0.35 }}
            style={{
              marginBottom:18,
              padding:16,
              borderRadius:theme.radius.md,
              background:'rgba(0,212,255,0.06)',
              border:`1px solid ${theme.primary}33`
            }}
          >
            <p style={{ fontSize:12, fontWeight:800, color:theme.primary, textTransform:'uppercase', letterSpacing:'1.6px', marginBottom:10, display:'flex', alignItems:'center', gap:6 }}><IkMail size={12} color={theme.primary}/> E-posta Önizleme</p>
            <div style={{ display:'grid', gap:8, fontSize:13, color:theme.text }}>
              <div><strong>Gönderen:</strong> {emailPreview?.from || 'Eksik'}</div>
              <div><strong>Konu:</strong> {emailPreview?.subject || 'Eksik'}</div>
              <div><strong>Tarih:</strong> {emailPreview?.date || 'Eksik'}</div>
              <div><strong>Reply-To:</strong> {emailPreview?.replyTo || 'Yok'}</div>
              {emailPreview?.replyToMismatch && <div style={{ color:theme.warning, fontWeight:700, display:'flex', alignItems:'center', gap:6 }}><IkWarn size={13} color={theme.warning}/> Reply-To farklı domain</div>}
            </div>
          </motion.div>
        )}
        
        <motion.textarea 
          initial={{ opacity:0 }}
          animate={{ opacity:1 }}
          transition={{ delay:0.8, duration:0.4 }}
          value={message} 
          onChange={e=>setMessage(e.target.value)} 
          placeholder={messageType === 'email' ? 'From, Subject ve gövde dahil tüm e-postayı yapıştırın...' : 'Analiz edilecek metni buraya yapistirin veya yazin...'} 
          rows={8} 
          style={{ 
            width:'100%', 
            padding:20, 
            borderRadius:theme.radius.md,
            background:'rgba(255,255,255,0.05)',
            border:`1px solid ${theme.border}`,
            color:'#fff', 
            fontSize:15, 
            resize:'vertical', 
            outline:'none', 
            lineHeight:1.7,
            fontFamily:theme.mono,
            transition:'border-color 0.3s ease'
          }} 
        />
        
        <motion.div 
          initial={{ opacity:0 }}
          animate={{ opacity:1 }}
          transition={{ delay:0.9, duration:0.4 }}
          style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:16 }}
        >
          <span style={{ fontSize:13, color:theme.textMuted, fontFamily:theme.mono }}>{message.length} karakter</span>
          <motion.button
            onClick={handleAnalyze}
            disabled={analyzing || message.length<10}
            whileHover={{ scale:1.02, boxShadow:'0 8px 30px rgba(0,212,255,0.4)' }}
            whileTap={{ scale:0.98 }}
            style={{
              padding:'14px 32px',
              borderRadius:theme.radius.md,
              cursor:analyzing?'not-allowed':'pointer',
              fontSize:15,
              fontWeight:700,
              letterSpacing:'0.5px',
              background:analyzing?'#444':theme.gradientPrimary,
              color:analyzing?'#888':'#000',
              border:'none',
              display:'inline-flex',
              alignItems:'center',
              gap:10,
              opacity:analyzing?0.5:1,
              boxShadow:analyzing?'none':'0 4px 20px rgba(0,212,255,0.3)',
              transition:'all 0.3s ease'
            }}
          >
            {analyzing ? 'Analiz Ediliyor...' : <><IkSearch size={15} color="#000"/> Analiz Et</>}
          </motion.button>
        </motion.div>
        
        {messageType === 'email' && examples.length > 0 && (
          <motion.div 
            initial={{ opacity:0, y:10 }}
            animate={{ opacity:1, y:0 }}
            transition={{ delay:1.0, duration:0.4 }}
            style={{ marginTop:24 }}
          >
            <p style={{ fontSize:11, color:theme.textMuted, fontWeight:700, marginBottom:10, textTransform:'uppercase', letterSpacing:'2px', display:'flex', alignItems:'center', gap:6 }}><IkMail size={12} color={theme.textMuted}/> E-posta Örnekleri</p>
            {examples.map((ex,i)=>
              <motion.button 
                key={i} 
                onClick={()=>setMessage(ex.text)} 
                initial={{ opacity:0, x:-10 }}
                animate={{ opacity:1, x:0 }}
                transition={{ delay:1.1 + i*0.1, duration:0.3 }}
                whileHover={{ background:'rgba(0,212,255,0.1)', borderColor:theme.primary, x:4 }}
                style={{ padding:'12px 16px', borderRadius:theme.radius.md, border:`1px solid ${theme.border}`, background:'rgba(255,255,255,0.03)', cursor:'pointer', textAlign:'left', fontSize:13, color:theme.textMuted, lineHeight:1.5, transition:'all 0.3s ease', display:'block', width:'100%', marginBottom:8 }}
              >
                <span style={{ color:theme.primary, fontWeight:700, fontSize:11, display:'block', marginBottom:3 }}>{ex.label}</span>
                {ex.text.substring(0,70)}...
              </motion.button>
            )}
          </motion.div>
        )}
      </Card>
      
      <Card 
        ref={resultRef} 
        style={{ 
          background:'rgba(255,255,255,0.03)',
          backdropFilter:'blur(10px)',
          WebkitBackdropFilter:'blur(10px)',
          border:`1px solid ${theme.border}`,
          padding:32,
          minHeight:500
        }}
      >
        <motion.h3 
          initial={{ opacity:0, x:20 }}
          animate={{ opacity:1, x:0 }}
          transition={{ delay:0.5, duration:0.4 }}
          style={{ fontSize:20, fontWeight:700, color:'#fff', marginBottom:24, display:'flex', gap:10, alignItems:'center' }}
        >
          <IkChart size={18} color={theme.primary}/> Analiz Sonuçları
        </motion.h3>
        
        {!result&&!analyzing&&
          <motion.div 
            initial={{ opacity:0, scale:0.9 }}
            animate={{ opacity:1, scale:1 }}
            transition={{ delay:0.6, duration:0.4 }}
            style={{ textAlign:'center', padding:'80px 20px', color:theme.textMuted }}
          >
            <span style={{ display:'flex', justifyContent:'center', marginBottom:20, opacity:0.35 }}><IkSearch size={56} color={theme.textMuted}/></span>
            <p style={{ fontSize:16, marginBottom:8 }}>Henüz analiz yapılmadı</p>
            <p style={{ fontSize:14, opacity:0.7 }}>Sol taraftaki metni girin ve "Analiz Et" butonuna tıklayın</p>
          </motion.div>
        }
        
        {analyzing&&
          <motion.div 
            initial={{ opacity:0 }}
            animate={{ opacity:1 }}
            style={{ textAlign:'center', padding:'80px 20px' }}
          >
            <Spinner size={48}/>
            <motion.p 
              initial={{ opacity:0, y:10 }}
              animate={{ opacity:1, y:0 }}
              transition={{ delay:0.3 }}
              style={{ marginTop:20, color:theme.textMuted, fontSize:15 }}
            >
              AI analiz ediyor...
            </motion.p>
          </motion.div>
        }
        
        {result&&<ResultContent score={score} threatLevel={sa.threat_level||'medium'} isPhishing={isPhishing} isScam={isScam} sa={sa} da={da} recs={recs} beliefs={beliefs} threats={threats} suspects={suspects} result={result} parsedEmail={parsedEmail} emailSignals={emailSignals} messageLength={message.length} onNavigate={onNavigate} rawText={message} />}
      </Card>
    </motion.div>
    
  </div>
}

function CrossModulePanel({ urlItems, parsedEmail, onNavigate }) {
  const [phishResults, setPhishResults] = useState({})
  const [iocResults, setIocResults] = useState({})
  const [loading, setLoading] = useState(true)

  const urls = urlItems
    .map(item => (typeof item === 'string' ? item : item?.url))
    .filter(Boolean)
    .slice(0, 5)
  const emailFrom = parsedEmail?.from || ''
  const emailDomain = parsedEmail?.fromDomain || ''

  useEffect(() => {
    if (!urls.length && !emailFrom) { setLoading(false); return }
    const checks = []
    for (const url of urls) {
      const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`
      checks.push(
        fetch(`${API}/phishing/check-url`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: normalized, force_fresh: false })
        }).then(r => r.json()).then(d => setPhishResults(prev => ({ ...prev, [url]: d }))).catch(() => {})
      )
    }
    if (emailFrom) {
      checks.push(
        fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(emailFrom)}`)
          .then(r => r.json())
          .then(d => setIocResults(prev => ({ ...prev, [emailFrom]: (d.results || d.data || d.iocs || []).slice(0, 3) })))
          .catch(() => {})
      )
    }
    Promise.all(checks).finally(() => setLoading(false))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!urls.length && !emailFrom) return null

  const SEVERITY_COLORS = {
    phishing: { bg: 'rgba(239,68,68,0.12)', border: '#ef444455', text: '#f87171' },
    high: { bg: 'rgba(239,68,68,0.10)', border: '#ef444433', text: '#f87171' },
    medium: { bg: 'rgba(245,158,11,0.10)', border: '#f59e0b33', text: '#fbbf24' },
    low: { bg: 'rgba(34,197,94,0.08)', border: '#22c55e33', text: '#34d399' },
    safe: { bg: 'rgba(34,197,94,0.08)', border: '#22c55e33', text: '#34d399' },
  }

  function getRiskStyle(r) {
    if (!r) return SEVERITY_COLORS.medium
    const verdict = (r.verdict || r.risk_level || '').toLowerCase()
    const isPhish = r.is_phishing || verdict === 'phishing' || (r.risk_score || 0) >= 75
    if (isPhish) return SEVERITY_COLORS.phishing
    const score = r.risk_score || 0
    if (score >= 50) return SEVERITY_COLORS.medium
    return SEVERITY_COLORS.safe
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.7, duration: 0.5 }}
      style={{ marginBottom: 20 }}
    >
      <div style={{
        background: 'linear-gradient(135deg, rgba(0,212,255,0.06) 0%, rgba(159,122,234,0.04) 100%)',
        border: `1px solid ${theme.primary}33`,
        borderRadius: theme.radiusMd,
        overflow: 'hidden'
      }}>
        <div style={{ padding: '14px 20px', borderBottom: `1px solid ${theme.border}`, display: 'flex', alignItems: 'center', gap: 10 }}>
          <Globe size={15} color={theme.primary} />
          <span style={{ fontSize: 13, fontWeight: 800, color: '#fff', letterSpacing: '0.5px' }}>Çapraz Modül Analizi</span>
          {loading && <span style={{ marginLeft: 'auto', fontSize: 11, color: theme.textMuted }}>Kontrol ediliyor...</span>}
        </div>
        <div style={{ padding: '14px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {urls.map((url, i) => {
            const r = phishResults[url]
            const st = getRiskStyle(r)
            const riskLabel = r ? (r.is_phishing ? 'Phishing' : `Risk ${r.risk_score ?? '?'}/100`) : (loading ? '...' : '?')
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', borderRadius: 8, background: st.bg, border: `1px solid ${st.border}` }}>
                <Link2 size={13} color={st.text} style={{ flexShrink: 0 }} />
                <span style={{ flex: 1, fontFamily: theme.mono, fontSize: 11, color: '#ccc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{url}</span>
                <span style={{ fontSize: 11, fontWeight: 700, color: st.text, flexShrink: 0 }}>{riskLabel}</span>
                {onNavigate && (
                  <motion.button
                    whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}
                    onClick={() => onNavigate('phishing-detector', url)}
                    style={{ padding: '5px 12px', borderRadius: 6, border: `1px solid ${theme.primary}44`, background: theme.primaryDim, color: theme.primary, fontSize: 11, fontWeight: 700, cursor: 'pointer', flexShrink: 0 }}
                  >Phishing'de Aç →</motion.button>
                )}
              </div>
            )
          })}
          {emailFrom && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', borderRadius: 8, background: (iocResults[emailFrom]?.length > 0) ? 'rgba(239,68,68,0.1)' : 'rgba(34,197,94,0.07)', border: `1px solid ${(iocResults[emailFrom]?.length > 0) ? '#ef444433' : '#22c55e33'}` }}>
              <AtSign size={13} color={(iocResults[emailFrom]?.length > 0) ? '#f87171' : '#34d399'} style={{ flexShrink: 0 }} />
              <span style={{ flex: 1, fontFamily: theme.mono, fontSize: 11, color: '#ccc', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{emailFrom}{emailDomain && emailDomain !== emailFrom ? ` · @${emailDomain}` : ''}</span>
              <span style={{ fontSize: 11, fontWeight: 700, color: (iocResults[emailFrom]?.length > 0) ? '#f87171' : '#34d399', flexShrink: 0 }}>
                {loading ? '...' : (iocResults[emailFrom]?.length > 0)
                  ? <><IkWarn size={11} color="#f87171" style={{marginRight:3}}/>{iocResults[emailFrom].length} IOC Kaydı</>
                  : <><IkCheck2 size={11} color="#34d399" style={{marginRight:3}}/>Temiz</>}
              </span>
              {onNavigate && (
                <motion.button
                  whileHover={{ scale: 1.04 }} whileTap={{ scale: 0.97 }}
                  onClick={() => onNavigate('honeypot', emailFrom)}
                  style={{ padding: '5px 12px', borderRadius: 6, border: `1px solid ${theme.violet}44`, background: 'rgba(159,122,234,0.1)', color: theme.violet, fontSize: 11, fontWeight: 700, cursor: 'pointer', flexShrink: 0 }}
                >IOC'de Aç →</motion.button>
              )}
            </div>
          )}
        </div>
      </div>
    </motion.div>
  )
}

function FraudProfileBanner({ text, attackMethod, onGoVictimAtlas }) {
  const [profile, setProfile] = useState(null)
  const [done, setDone] = useState(false)

  useEffect(() => {
    if (!text || text.length < 20) { setDone(true); return }
    fetch(`${API}/victim-atlas/fraud-profiles/match`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text.slice(0, 3000), attack_method: attackMethod || '' })
    }).then(r => r.json()).then(d => { if (d.matched && d.profile) setProfile(d.profile) }).catch(() => {}).finally(() => setDone(true))
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!done || !profile) return null

  const SEV = {
    critical: { bg: 'rgba(239,68,68,0.13)', border: '#ef444455', accent: '#f87171', label: 'KRİTİK' },
    high:     { bg: 'rgba(245,158,11,0.12)', border: '#f59e0b55', accent: '#fbbf24', label: 'YÜKSEK' },
    medium:   { bg: 'rgba(0,212,255,0.08)', border: '#00d4ff44', accent: '#00d4ff', label: 'ORTA' },
    low:      { bg: 'rgba(34,197,94,0.08)', border: '#22c55e44', accent: '#34d399', label: 'DÜŞÜK' },
  }
  const s = SEV[profile.severity] || SEV.high
  const tl = (text || '').toLowerCase()
  const displayProfile = { ...profile }
  if (/ptt.*kargo|kargo.*ptt/.test(tl)) {
    displayProfile.name_tr = 'PTT Kargo / Gümrük Ücreti Tuzağı'
    displayProfile.description = 'PTT Kargo adına sahte SMS gönderilerek \'gümrük işlem ücreti\' bahanesiyle kart bilgileri ve kişisel veriler çalınır. Bağlantılar ptt.gov.tr dışındaki sahte alan adlarına yönlendirir.'
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.97, y: 12 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      transition={{ duration: 0.5, ease: [0.23, 1, 0.32, 1] }}
      style={{ marginBottom: 20 }}
    >
      <div style={{
        background: s.bg,
        border: `1px solid ${s.border}`,
        borderRadius: theme.radiusMd,
        padding: '18px 22px',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div aria-hidden style={{ position: 'absolute', inset: 0, background: `radial-gradient(ellipse at 0% 50%, ${s.accent}18 0%, transparent 65%)`, pointerEvents: 'none' }} />
        <div style={{ position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <IkAlert size={20} color={s.accent}/>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: 10, fontWeight: 800, letterSpacing: '2.5px', color: s.accent, textTransform: 'uppercase' }}>
                Dolandırıcılık Profili Tespit Edildi · {s.label}
              </span>
              <h4 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#fff', letterSpacing: '-0.3px', marginTop: 2 }}>{displayProfile.name_tr}</h4>
            </div>
            <span style={{ padding: '4px 10px', borderRadius: 20, background: `${s.accent}22`, border: `1px solid ${s.accent}44`, fontSize: 11, fontWeight: 700, color: s.accent, flexShrink: 0 }}>
              %{profile.confidence} güven
            </span>
          </div>
          <p style={{ margin: 0, fontSize: 13, color: theme.textMuted, lineHeight: 1.6, marginBottom: 14 }}>{displayProfile.description}</p>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap' }}>
            {profile.case_count > 0 && (
              <span style={{ fontSize: 12, color: theme.textMuted }}>
                <span style={{ color: s.accent, fontWeight: 700 }}>{profile.case_count}</span> benzer vaka kayıtlı
              </span>
            )}
            {profile.avg_loss_try && (
              <span style={{ fontSize: 12, color: theme.textMuted }}>
                Ort. kayıp: <span style={{ color: s.accent, fontWeight: 700 }}>₺{Number(profile.avg_loss_try).toLocaleString('tr-TR')}</span>
              </span>
            )}
            {onGoVictimAtlas && (
              <motion.button
                whileHover={{ scale: 1.04, boxShadow: `0 4px 20px ${s.accent}40` }}
                whileTap={{ scale: 0.97 }}
                onClick={() => {
                  const t = (text || '').toLowerCase()
                  let q = profile.atlas_search_q || ''
                  if (/ptt.*kargo|kargo.*ptt/.test(t)) q = 'ptt-kargo-odeme.top'
                  else if (/akbank/.test(t)) q = 'akbank-guvenlik.xyz'
                  else if (/sgk|e-devlet|edevlet/.test(t)) q = 'edevlet-sgk-sorgula.net'
                  onGoVictimAtlas({ ...profile, atlas_search_q: q })
                }}
                style={{ marginLeft: 'auto', padding: '8px 18px', borderRadius: 8, background: `linear-gradient(135deg, ${s.accent}33, ${s.accent}11)`, border: `1px solid ${s.accent}55`, color: s.accent, fontSize: 12, fontWeight: 700, cursor: 'pointer', letterSpacing: '0.3px' }}
              >Mağduriyet Atlasında Gör →</motion.button>
            )}
          </div>
        </div>
      </div>
    </motion.div>
  )
}

function ResultContent({ score, threatLevel, isPhishing, sa, da, recs, beliefs, threats, suspects, result, onNavigate, rawText, parsedEmail: passedParsedEmail }) {
  const [showAllRecommendations, setShowAllRecommendations] = useState(false)

  const hardOverride = da?.hard_override || false
  const cleanSummary = result?.summary?.startsWith('[') ? null : result?.summary
  const urlItems = Array.isArray(da?.url_analysis) ? da.url_analysis : []
  const normalizedRecs = Array.isArray(recs) ? recs : []

  const cleanRecText = (text) => {
    let cleaned = String(text || '')
    // Remove parenthetical comments/meta-commentary
    cleaned = cleaned.replace(/\s*\([^)]*parse[^)]*\)/gi, '')
    cleaned = cleaned.replace(/\s*\([^)]*türk[^)]*\)/gi, '')
    cleaned = cleaned.replace(/\s*\([^)]*açık[^)]*\)/gi, '')
    cleaned = cleaned.replace(/\s*\([^)]*görsel[^)]*\)/gi, '')
    cleaned = cleaned.replace(/\s*\([^)]*hatalar[^)]*\)/gi, '')
    // Clean up multiple spaces
    cleaned = cleaned.replace(/\s+/g, ' ').trim()
    return cleaned
  }

  const parsedRecs = normalizedRecs.map(rec => {
    if (typeof rec === 'string') {
      return { priority:'LOW', text:cleanRecText(rec), action:'' }
    }
    return {
      priority:String(rec?.priority || 'LOW').toUpperCase(),
      text:cleanRecText(rec?.description || rec?.message || JSON.stringify(rec)),
      action:rec?.action || ''
    }
  })

  const visibleRecs = showAllRecommendations ? parsedRecs : parsedRecs.slice(0, 4)
  const hiddenRecCount = Math.max(0, parsedRecs.length - 4)

  return <motion.div 
    initial={{ opacity:0, scale:0.95 }}
    animate={{ opacity:1, scale:1 }}
    transition={{ duration:0.5, ease:theme.ease.out }}
  >
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.1, duration:0.4 }}
      style={{ 
        position:'relative',
        display:'flex', 
        gap:32, 
        alignItems:'stretch', 
        marginBottom:22, 
        flexWrap:'wrap',
        background: 'linear-gradient(135deg, rgba(0,212,255,0.1) 0%, rgba(255,0,128,0.05) 100%)',
        borderRadius: theme.radius.lg,
        padding: '24px 28px',
        border: `1px solid ${theme.border}`,
        backdropFilter: 'blur(10px)'
      }}
    >
      {hardOverride && (
        <span
          title="Hard override aktif"
          style={{
            position:'absolute',
            top:12,
            right:12,
            width:18,
            height:18,
            borderRadius:'50%',
            background:theme.accentDim,
            color:theme.accent,
            border:`1px solid ${theme.accent}66`,
            display:'inline-flex',
            alignItems:'center',
            justifyContent:'center',
            fontSize:11,
            fontWeight:900
          }}
        >
          !
        </span>
      )}

      <div style={{ flex:1, minWidth:280, display:'flex', flexDirection:'column', gap:16 }}>
        <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
          <span style={{ 
            padding:'10px 20px', 
            borderRadius:'28px', 
            fontSize:15, 
            fontWeight:800, 
            background: isPhishing ? 'linear-gradient(135deg, #ff4444, #ff6b6b)' : 'linear-gradient(135deg, #00d4ff, #0099cc)',
            color: '#fff',
            boxShadow: isPhishing ? '0 4px 15px rgba(255,68,68,0.3)' : '0 4px 15px rgba(0,212,255,0.3)'
          }}>
            <span style={{ display:'inline-flex', alignItems:'center', gap:6 }}>{isPhishing ? <ShieldAlert size={16}/> : <Shield size={16}/>}{isPhishing ? 'TEHLİKELİ' : 'GÜVENLİ'}</span>
          </span>
          <RiskBadge level={threatLevel} size="lg" />
        </div>
        
        <div style={{ 
          padding: '14px 18px', 
          background: 'rgba(0,0,0,0.2)', 
          borderRadius: theme.radius.md,
          border: `1px solid ${theme.border}`
        }}>
          <p style={{ fontSize:15, color:theme.text, margin:0, display:'flex', gap:10, flexWrap:'wrap' }}>
            <span>
              <span style={{ color:theme.textMuted }}>Güvenlik Durumu:</span>{' '}
              <strong style={{ color:score > 70 ? theme.danger : score > 40 ? theme.warning : theme.success }}>
                {sa.safety_status || 'Bilinmiyor'}
              </strong>
            </span>
            <span style={{ color:theme.textMuted }}>·</span>
            <span>
              <span style={{ color:theme.textMuted }}>Gerekli Aksiyon:</span>{' '}
              <strong style={{ color:theme.primary }}>{sa.action_required || 'YOK'}</strong>
            </span>
          </p>
        </div>
      </div>
    </motion.div>
    
    <motion.div
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.2, duration:0.4 }}
      style={{ display:'flex', justifyContent:'center', marginBottom:24 }}
    >
      <Card style={{ 
        padding:'32px', 
        background:'rgba(255,255,255,0.03)',
        border:`1px solid ${theme.border}`,
        display:'flex',
        flexDirection:'column',
        alignItems:'center',
        gap:16
      }}>
        <RiskGauge score={100 - Math.max(0, Math.min(100, Number(score) || 0))} label="Güvenilirlik Skoru" size="lg" safetyMode={true}/>
      </Card>
    </motion.div>

    <FraudProfileBanner text={rawText || ''} attackMethod={sa?.scam_type || da?.attack_method || result?.scam_type || ''} onGoVictimAtlas={onNavigate ? (profile) => onNavigate('victim-atlas', '', profile) : undefined} />

    {(urlItems.length > 0 || passedParsedEmail?.from) && (
      <CrossModulePanel urlItems={urlItems} parsedEmail={passedParsedEmail} onNavigate={onNavigate} />
    )}

    {/* Risk Breakdown Card */}
    {(() => {
      const bd = da?.advanced_breakdown || result?.detailed_analysis?.advanced_breakdown || result?.advanced_breakdown
      if (!bd) return null
      const rows = [
        { key:'domain_risk',   label:'Domain Riski',    val: bd.domain_risk,   desc:'Taklit edilen kurum / sahte domain tespiti' },
        { key:'s_url',         label:'URL Skoru',       val: bd.s_url,         desc:'URL yapısal analizi (TLD, path, brand)' },
        { key:'ssl_score',     label:'SSL / Güven',     val: bd.ssl_score != null ? (1 - bd.ssl_score) : null, desc:'SSL sertifikası ve güven sinyali' },
        { key:'db_similarity', label:'DB Benzerliği',   val: bd.db_similarity, desc:'Bilinen phishing URL veritabanıyla eşleşme' },
      ].filter(r => r.val != null && Number.isFinite(r.val))
      if (!rows.length) return null
      return (
        <motion.div
          initial={{ opacity:0, y:12 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.25, duration:0.4 }}
          style={{ marginBottom:16 }}
        >
          <Card style={{ background:'rgba(255,255,255,0.03)', border:`1px solid ${theme.border}`, padding:'18px 20px' }}>
            <p style={{ fontSize:12, fontWeight:800, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'2px', marginBottom:14, display:'flex', alignItems:'center', gap:6 }}><IkScope size={13} color={theme.textMuted}/> Risk Dağılımı — Neden Bu Skor?</p>
            <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
              {rows.map((row, i) => {
                const pct = Math.min(Math.round(row.val * 100), 100)
                const barColor = pct >= 80 ? theme.danger : pct >= 50 ? theme.warning : theme.primary
                return (
                  <div key={row.key}>
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:5 }}>
                      <span style={{ fontSize:13, fontWeight:700, color:theme.text }}>{row.label}</span>
                      <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                        <span style={{ fontSize:11, color:theme.textMuted }}>{row.desc}</span>
                        <span style={{ fontSize:13, fontWeight:800, color:barColor, minWidth:36, textAlign:'right' }}>{pct}%</span>
                        <span style={{ fontSize:10, fontWeight:800, padding:'3px 8px', borderRadius:999, background:`${barColor}22`, color:barColor, border:`1px solid ${barColor}44` }}>
                          {pct >= 80 ? 'KRİTİK' : pct >= 50 ? 'YÜKSEK' : 'ORTA'}
                        </span>
                      </div>
                    </div>
                    <div style={{ height:7, borderRadius:999, background:'rgba(255,255,255,0.07)', overflow:'hidden' }}>
                      <motion.div
                        initial={{ width:0 }}
                        animate={{ width:`${pct}%` }}
                        transition={{ delay: 0.3 + i * 0.1, duration:0.8, ease:'easeOut' }}
                        style={{ height:'100%', borderRadius:999, background:`linear-gradient(90deg, ${barColor}aa, ${barColor})`, boxShadow:`0 0 8px ${barColor}55` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </Card>
        </motion.div>
      )
    })()}

    {cleanSummary &&
      <motion.div
        initial={{ opacity:0, y:10 }}
        animate={{ opacity:1, y:0 }}
        transition={{ delay:0.3, duration:0.4 }}
      >
        <Card style={{ 
          padding:20, 
          marginBottom:20, 
          maxHeight:140, 
          overflowY:'auto',
          background:'rgba(255,255,255,0.03)',
          border:`1px solid ${theme.border}`
        }}>
          <p style={{ fontSize:14, lineHeight:1.7, color:theme.text, whiteSpace:'pre-wrap' }}>{cleanSummary}</p>
        </Card>
      </motion.div>
    }

    
    {parsedRecs.length > 0 &&
      <motion.div
        initial={{ opacity:0, y:16 }}
        animate={{ opacity:1, y:0 }}
        transition={{ delay:0.5, duration:0.4 }}
        style={{ marginBottom:16 }}
      >
        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
          <p style={{ fontSize:12, fontWeight:800, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'2px', margin:0, display:'flex', alignItems:'center', gap:6 }}>
            <IkArrow size={12} color={theme.textMuted}/> Önerilen Aksiyonlar
          </p>
          <span style={{ marginLeft:'auto', padding:'3px 10px', borderRadius:99, fontSize:10, fontWeight:700, background:theme.primaryDim, color:theme.primary, border:`1px solid ${theme.primary}22` }}>
            {parsedRecs.length}
          </span>
        </div>
        <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
          {visibleRecs.map((rec, i) => (
            <motion.div
              key={i}
              initial={{ opacity:0, x:-8 }}
              animate={{ opacity:1, x:0 }}
              transition={{ delay:0.55 + i*0.06, duration:0.3 }}
              style={{
                display:'flex', alignItems:'flex-start', gap:10,
                padding:'11px 14px',
                background:'rgba(0,0,0,0.2)',
                borderRadius:8,
                borderLeft:`2px solid ${theme.primary}44`,
              }}
            >
              <span style={{ color:theme.primary, flexShrink:0, marginTop:1 }}><IkArrow size={12} color={theme.primary}/></span>
              <span style={{ fontSize:13, color:theme.text, lineHeight:1.6 }}>{rec.text}</span>
            </motion.div>
          ))}
        </div>
        {hiddenRecCount > 0 && (
          <button
            type="button"
            onClick={() => setShowAllRecommendations(prev => !prev)}
            style={{ marginTop:10, border:'none', background:'transparent', color:theme.textMuted, fontSize:12, fontWeight:600, cursor:'pointer', padding:0 }}
          >
            {showAllRecommendations ? 'Daha az göster' : `+${hiddenRecCount} daha göster`}
          </button>
        )}
      </motion.div>
    }

  </motion.div>
}

function PlatformStatCounter({ target, suffix, label, color, fmt, delay = 0 }) {
  const [val, setVal] = useState(0)
  const hasAnimated = useRef(false)
  const elRef = useRef(null)

  useEffect(() => {
    const observer = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting && !hasAnimated.current) {
        hasAnimated.current = true
        const obj = { v: 0 }
        gsap.to(obj, {
          v: target,
          duration: 2.0,
          delay,
          ease: 'power2.out',
          onUpdate() { setVal(Math.round(obj.v)) }
        })
      }
    }, { threshold: 0.3 })
    if (elRef.current) observer.observe(elRef.current)
    return () => observer.disconnect()
  }, [target, delay])

  return (
    <div ref={elRef} style={{ textAlign:'center', minWidth:90 }}>
      <div style={{ fontSize:28, fontWeight:900, color, lineHeight:1, letterSpacing:'-1px', fontFamily:"'Inter', sans-serif" }}>
        {fmt ? fmt(val) : val}{suffix}
      </div>
      <div style={{ fontSize:11, color:theme.textMuted, marginTop:5, fontWeight:700, textTransform:'uppercase', letterSpacing:'1.5px' }}>{label}</div>
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
  
  const [displayScore, setDisplayScore] = useState(0)
  const tweenRef = useRef(null)

  useEffect(() => {
    if (tweenRef.current) tweenRef.current.kill()
    const obj = { val: 0 }
    tweenRef.current = gsap.to(obj, {
      val: Math.min(score, 100),
      duration: 1.2,
      ease: 'power2.out',
      onUpdate() { setDisplayScore(Math.round(obj.val)) }
    })
    return () => { if (tweenRef.current) tweenRef.current.kill() }
  }, [score])

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
        style={{ filter: `drop-shadow(0 0 8px ${color}50)` }} 
        strokeLinecap="round"
      />
      <text x={center} y={center} textAnchor="middle" dominantBaseline="central" fill="#fff" fontSize={fontSize} fontWeight="800" fontFamily="Inter, sans-serif">
        {showPercentage ? `${displayScore}%` : displayScore}
      </text>
    </svg>
    <p style={{ fontSize: size === 'lg' ? 14 : 12, color:theme.textMuted, marginTop:10, fontWeight:700, letterSpacing:0.5 }}>{label}</p>
  </div>
}

/* ===============================================
   PHISHING RESULT (Enhanced Threat Intel Display)
   =============================================== */
function PhishingResult({ result, url }) {
  const ti = result.threat_intel || {}
  const sa = ti.screenshot_analysis || {}
  const screenshotB64 = sa.screenshot_b64 || null
  const indicators = Array.isArray(sa.threat_indicators) ? sa.threat_indicators : []
  const vt = ti.virustotal || {}
  const gsb = ti.google_safe_browsing || {}
  const aipdb = ti.abuseipdb || {}
  const urlhaus = ti.urlhaus || {}
  const shDomain = ti.spamhaus_domain || {}
  const shIp = ti.spamhaus_ip || {}
  const tf = ti.threatfox || {}

  const srcCards = [
    { key:'urlhaus', Icon:IkLink2, name:'URLhaus', data:urlhaus, isBad:urlhaus.listed===true, isClean:urlhaus.listed===false, badLabel:'LISTED', cleanLabel:'CLEAN', detail:urlhaus.listed?`Tehdit: ${urlhaus.threat_type||'unknown'}`:'Kara listede değil', penalty:40 },
    { key:'spamhaus_domain', Icon:IkShieldDoc, name:'Spamhaus Domain', data:shDomain, isBad:shDomain.listed===true, isClean:shDomain.listed===false&&shDomain.available, badLabel:'LISTED', cleanLabel:'CLEAN', detail:shDomain.listed?`Listeler: ${(shDomain.lists||[]).join(', ')||'-'}`:shDomain.zrd?'Sıfır itibar (ZRD)':'Temiz', penalty:35 },
    { key:'spamhaus_ip', Icon:IkGlobe2, name:'Spamhaus IP', data:shIp, isBad:shIp.listed===true, isClean:shIp.listed===false&&shIp.available, badLabel:'LISTED', cleanLabel:'CLEAN', detail:shIp.listed?`Listeler: ${(shIp.lists||[]).join(', ')||'-'}`:'Temiz', penalty:30 },
    { key:'threatfox', Icon:IkBolt, name:'ThreatFox', data:tf, isBad:tf.found===true, isClean:tf.found===false&&tf.available, badLabel:'FOUND', cleanLabel:'NOT FOUND', detail:tf.found?`${tf.malware_family||'unknown'} (conf: ${tf.confidence||0}%)`:'IOC bulunamadı', penalty:25 },
    { key:'virustotal', Icon:IkShieldDoc, name:'VirusTotal', data:vt, isBad:(vt.malicious||0)>=1, isClean:vt.available&&(vt.malicious||0)===0, badLabel:`${vt.malicious||0} MAL`, cleanLabel:'CLEAN', detail:vt.available?(vt.source==='whitelist'?'Whitelist domain (güvenilir)':`${vt.malicious||0} motor tehlikeli`):'Sonuç yok', penalty:40 },
    { key:'gsb', Icon:IkSearch, name:'Google Safe Browsing', data:gsb, isBad:gsb.threat===true, isClean:gsb.available&&!gsb.threat, badLabel:'THREAT', cleanLabel:'SAFE', detail:gsb.threat?gsb.threat_type||'Tehdit':'Güvenli', penalty:50 },
    { key:'abuseipdb', Icon:IkScope, name:'AbuseIPDB (Local)', data:aipdb, isBad:(aipdb.abuse_score||0)>=30, isClean:aipdb.available&&(aipdb.abuse_score||0)<30, badLabel:`${aipdb.abuse_score||0}%`, cleanLabel:'CLEAN', detail:aipdb.available?`Suistimal: %${aipdb.abuse_score||0}`:'Sonuç yok', penalty:25 },
    { key:'screenshot', Icon:IkCamera, name:'Screenshot Analyzer', data:sa, isBad:(sa.risk_score||0)>50, isClean:sa.available&&(sa.risk_score||0)<=30, badLabel:sa.risk_level||'HIGH', cleanLabel:'SAFE', detail:(!sa.available&&screenshotB64)?'Screenshot alındı (AI analizi devre dışı)':(sa.verdict||'Analiz yok'), penalty:sa.available?Math.round((sa.risk_score||50)*0.6):0, hasDataOverride: !!screenshotB64 || !!sa.verdict, badgeOverride: (!sa.available&&screenshotB64)?'CAPTURED':null },
  ]

  const openScreenshot = () => {
    if (!screenshotB64) return
    const w = window.open('','_blank')
    if(w){w.document.write(`<html><head><title>Screenshot</title><style>body{margin:0;background:#111;display:flex;align-items:center;justify-content:center;min-height:100vh}img{max-width:100%;height:auto}</style></head><body><img src="data:image/png;base64,${screenshotB64}"/></body></html>`);w.document.close()}
  }

  return (
  <motion.div initial={{opacity:0,y:30}} animate={{opacity:1,y:0}} transition={{duration:0.6,ease:theme.ease.out}} style={{marginBottom:48}}>
    {/* Hero Result Card */}
    {(() => { const safetyScore = result.safety_score ?? result.score ?? 0; return (
    <Card style={{background:'rgba(255,255,255,0.03)',backdropFilter:'blur(10px)',WebkitBackdropFilter:'blur(10px)',border:`1px solid ${safetyScore<50?theme.accent+'40':theme.primary+'40'}`,marginBottom:24}}>
      <div style={{display:'flex',gap:32,alignItems:'flex-start',flexWrap:'wrap'}}>
        {/* Left: Gauge + Screenshot */}
        <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:16,minWidth:200}}>
          <RiskGauge score={safetyScore} label="Güvenilirlik Skoru" size="lg" safetyMode={true}/>
          <span style={{padding:'8px 20px',borderRadius:'24px',fontSize:14,fontWeight:700,background:safetyScore<50?theme.accentDim:theme.primaryDim,color:safetyScore<50?theme.accent:theme.primary}}>{result.risk_level||'Bilinmiyor'}</span>
          {screenshotB64&&(
            <motion.div initial={{opacity:0,scale:0.9}} animate={{opacity:1,scale:1}} transition={{delay:0.3,duration:0.4}} style={{position:'relative',cursor:'pointer'}} onClick={openScreenshot}>
              <img src={`data:image/png;base64,${screenshotB64}`} alt="Site screenshot" style={{width:200,height:'auto',maxHeight:150,objectFit:'cover',borderRadius:theme.radius.md,border:`1px solid ${theme.border}`,boxShadow:'0 4px 20px rgba(0,0,0,0.4)',opacity:0.9,transition:'opacity 0.3s ease'}} onMouseEnter={e=>e.target.style.opacity=1} onMouseLeave={e=>e.target.style.opacity=0.9}/>
              <span style={{position:'absolute',bottom:6,right:6,padding:'3px 8px',borderRadius:6,fontSize:9,fontWeight:700,background:'rgba(0,0,0,0.7)',color:theme.primary,letterSpacing:0.5,display:'flex',alignItems:'center',gap:4}}><IkSearch size={9} color={theme.primary}/> BÜYÜT</span>
            </motion.div>
          )}
        </div>
        {/* Right: Details */}
        <div style={{flex:1,minWidth:300}}>
          <p style={{fontSize:14,color:theme.textMuted,wordBreak:'break-all',marginBottom:16,fontFamily:theme.mono,lineHeight:1.6}}>{url}</p>
          {result.details&&Array.isArray(result.details)&&result.details.length>0&&(
            <div style={{marginBottom:16}}>
              <p style={{fontSize:12,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'1.5px',marginBottom:10,display:'flex',alignItems:'center',gap:6}}><IkShieldDoc size={12} color={theme.textMuted}/> Tespitler</p>
              <div style={{display:'flex',flexDirection:'column',gap:5,maxHeight:220,overflowY:'auto'}}>
                {result.details.slice(0,12).map((d,i)=>{
                  const isDanger=d.includes('🚨')||d.includes('❌')||/tehlike|kritik|phishing|malware/i.test(d)
                  const isWarn=d.includes('⚠️')||/uyar|şüpheli|dikkat/i.test(d)
                  const isSafe=d.includes('✅')||/temiz|güvenli/i.test(d)
                  const isScreen=d.includes('📸')||/screenshot/i.test(d)
                  const DetailIcon=isScreen?IkCamera:isDanger?IkAlert:isWarn?IkWarn:isSafe?IkCheck2:IkShieldDoc
                  const iconColor=isDanger?theme.accent:isWarn?theme.warning:isSafe?theme.success:theme.primary
                  const stripped=d.replace(/[\u{1F000}-\u{1FFFF}\u{2600}-\u{26FF}]/gu,'').replace(/[📸🛡️⚠️❌✅🚨ℹ️]/g,'').trim()
                  const techMatch=stripped.match(/^(.+?)\s*(\([^)]*(?:risk|ceza|penalty|conf|score|ağırlık)[^)]*\))(.*)$/i)
                  const mainText=techMatch?techMatch[1].trim()+techMatch[3]:stripped
                  const techNote=techMatch?techMatch[2]:null
                  return (
                    <motion.div key={i} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.08+i*0.03,duration:0.28}}
                      style={{padding:'9px 12px',background:isDanger?'rgba(255,0,64,0.08)':isWarn?'rgba(255,193,7,0.06)':isSafe?'rgba(34,197,94,0.05)':theme.primaryDim,borderRadius:8,borderLeft:isDanger?`3px solid ${theme.accent}`:isWarn?`3px solid ${theme.warning}`:isSafe?`3px solid ${theme.success}`:`3px solid ${theme.primary}`,display:'flex',alignItems:'flex-start',gap:9}}
                    >
                      <span style={{flexShrink:0,marginTop:2}}><DetailIcon size={13} color={iconColor}/></span>
                      <span style={{flex:1,minWidth:0}}>
                        <span style={{fontSize:13,color:theme.text,lineHeight:1.55,fontWeight:isDanger||isWarn?600:400}}>{mainText}</span>
                        {techNote&&<span style={{fontSize:10,color:theme.textMuted,marginLeft:6,opacity:0.65,fontFamily:theme.mono}}>{techNote}</span>}
                      </span>
                    </motion.div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </Card>
    )})()}

    {/* Threat Intel Source Cards */}
    <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{delay:0.2,duration:0.5}} style={{marginBottom:24}}>
      <p style={{fontSize:13,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'2px',marginBottom:16,display:'flex',alignItems:'center',gap:7}}><IkRadar size={13} color={theme.textMuted}/> Tehdit İstihbaratı Kaynakları</p>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill, minmax(220px, 1fr))',gap:12}}>
        {srcCards.map((src,i)=>{
          const hasData=src.hasDataOverride||(src.data&&(src.data.available!==false||src.isBad||src.isClean))
          const statusColor=src.isBad?theme.accent:src.isClean?theme.success:theme.textMuted
          const bgColor=src.isBad?'rgba(255,0,64,0.06)':src.isClean?'rgba(34,197,94,0.06)':'rgba(255,255,255,0.02)'
          const borderColor=src.isBad?theme.accent+'40':src.isClean?theme.success+'40':theme.border
          return (
            <motion.div key={src.key} initial={{opacity:0,y:15}} animate={{opacity:1,y:0}} transition={{delay:0.3+i*0.05,duration:0.35}} style={{padding:'16px 18px',background:bgColor,border:`1px solid ${borderColor}`,borderRadius:theme.radius.md,position:'relative',overflow:'hidden'}}>
              <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:statusColor}}/>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
                <span style={{fontSize:14,fontWeight:700,color:'#fff',display:'flex',alignItems:'center',gap:6}}><src.Icon size={13} color={statusColor}/> {src.name}</span>
                {src.isBad&&<span style={{padding:'3px 8px',borderRadius:6,fontSize:9,fontWeight:800,background:theme.accentDim,color:theme.accent,textTransform:'uppercase',letterSpacing:0.5}}>-{src.penalty}</span>}
              </div>
              <div style={{marginBottom:8}}>
                <span style={{display:'inline-block',padding:'4px 10px',borderRadius:8,fontSize:11,fontWeight:700,background:src.isBad?theme.accentDim:src.isClean?'rgba(34,197,94,0.15)':'rgba(255,255,255,0.05)',color:statusColor,letterSpacing:0.3}}>
                  {hasData?(src.badgeOverride||(src.isBad?src.badLabel:src.isClean?src.cleanLabel:'N/A')):'—'}
                </span>
              </div>
              <p style={{fontSize:12,color:theme.textMuted,lineHeight:1.4,margin:0}}>{hasData?src.detail:'Veri yok'}</p>
            </motion.div>
          )
        })}
      </div>
    </motion.div>

    {/* Screenshot Threat Indicators */}
    {indicators.length>0&&(
      <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{delay:0.5,duration:0.4}} style={{marginBottom:24}}>
        <p style={{fontSize:13,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'2px',marginBottom:16,display:'flex',alignItems:'center',gap:7}}><IkGrid size={13} color={theme.textMuted}/> Görsel Tehdit İndikatörleri</p>
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill, minmax(280px, 1fr))',gap:10}}>
          {indicators.map((ind,j)=>{
            const t=ind.type||'visual'
            const IcComp=t==='url'?IkLink2:t==='domain'?IkGlobe2:t==='ip'?IkMonitor:IkScope
            return (
              <motion.div key={j} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.6+j*0.05,duration:0.3}} style={{padding:'12px 16px',background:'rgba(255,107,53,0.06)',border:`1px solid ${theme.accent}30`,borderRadius:theme.radius.md,borderLeft:`3px solid ${theme.accent}`}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <IcComp size={14} color={theme.accent}/>
                  <span style={{fontSize:12,fontWeight:700,color:theme.accent,textTransform:'uppercase',letterSpacing:0.5}}>{t}</span>
                </div>
                <p style={{fontSize:13,color:theme.text,fontFamily:theme.mono,margin:'0 0 4px 0',wordBreak:'break-all'}}>{ind.value||'—'}</p>
                {ind.reason&&<p style={{fontSize:11,color:theme.textMuted,margin:0,lineHeight:1.4}}>{ind.reason}</p>}
              </motion.div>
            )
          })}
        </div>
      </motion.div>
    )}

    {/* Sources Summary */}
    {result.sources&&Array.isArray(result.sources)&&result.sources.length>0&&(
      <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{delay:0.6,duration:0.4}}>
        <p style={{fontSize:13,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'2px',marginBottom:16,display:'flex',alignItems:'center',gap:7}}><IkClipboard size={13} color={theme.textMuted}/> Taranan Kaynaklar</p>
        <div style={{display:'flex',flexDirection:'column',gap:6}}>
          {result.sources.map((s,i)=>{
            const isFail=typeof s.status==='string'&&(s.status.includes('Başarısız')||s.status.includes('timeout')||s.status.includes('error'))
            const isOk=typeof s.status==='string'&&(s.status.includes('CLEAN')||s.status.includes('SAFE')||s.status.includes('Tamamlandı')||s.status.includes('Ulaşılabilir')||s.status.includes('temiz'))
            return (
              <motion.div key={i} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.7+i*0.03,duration:0.3}} style={{padding:'10px 16px',background:isFail?'rgba(255,0,64,0.06)':isOk?'rgba(34,197,94,0.04)':'rgba(255,255,255,0.03)',borderRadius:10,fontSize:13,display:'flex',gap:10,alignItems:'center',borderLeft:isFail?`3px solid ${theme.accent}`:isOk?`3px solid ${theme.success}`:`3px solid ${theme.border}`}}>
                <span style={{color:theme.textMuted}}>Kaynak:</span>
                <span style={{color:'#fff',fontWeight:600}}>{s.name}</span>
                <span style={{marginLeft:'auto',color:isFail?theme.danger:isOk?theme.success:theme.textMuted,fontSize:12}}>{s.status}</span>
              </motion.div>
            )
          })}
        </div>
      </motion.div>
    )}
  </motion.div>
  )
}

/* ===============================================
   PHISHING DETECTOR
   =============================================== */
function PhishingDetector({ initialUrl = '', onClearPrefill }) {
  const isMobile = useWindowWidth() < 768
  const [url, setUrl] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [latestFeeds, setLatestFeeds] = useState([])
  const [scanHistory, setScanHistory] = useState([])
  const [stats, setStats] = useState(null)
  const [pageNum, setPageNum] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [latestTotal, setLatestTotal] = useState(0)
  const [loadingLatest, setLoadingLatest] = useState(false)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })
  const [searchResults, setSearchResults] = useState([])
  const [showDropdown, setShowDropdown] = useState(false)
  const searchTimeoutRef = useRef(null)
  const [jobId, setJobId] = useState(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [pollCount, setPollCount] = useState(0)
  const MAX_POLLS = 120
  const [showRetryButton, setShowRetryButton] = useState(false)
  const prefillProcessed = useRef('')

  useEffect(() => {
    if (initialUrl && initialUrl !== prefillProcessed.current) {
      prefillProcessed.current = initialUrl
      setUrl(initialUrl)
      onClearPrefill?.()
      setTimeout(() => handleCheck(false, initialUrl), 150)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUrl])

  function showToast(msg,t='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(t=>({...t,visible:false})),3000)}

  const loadLatest = useCallback(async (p=1) => {
    try{
      setLoadingLatest(true)
      const r=await fetch(`${API}/phishing/latest-paged?limit=20&page=${p}`)
      if(!r.ok) throw new Error('Son veriler alınamadı')
      const d=await r.json()
      setLatestFeeds(d.data||d.latest||[])
      setTotalPages(d.total_pages||Math.ceil((d.total||0)/20)||1)
      setPageNum(d.page||p)
      setLatestTotal(d.total||0)
    }catch(e){
      showToast('Son phishing verileri yüklenemedi: '+e.message,'error')
    } finally {
      setLoadingLatest(false)
    }
  }, [])

  const loadScanHistory = useCallback(async (p=1) => {
    try {
      const r = await fetch(`${API}/phishing/scan-history?limit=30&page=${p}`)
      if(!r.ok) throw new Error('Tarama gecmisi alınamadı')
      const d = await r.json()
      const items = d.data || d.history || []
      const seen = new Set()
      const deduped = items.filter(item => {
        if (!item?.url) return false
        if (seen.has(item.url)) return false
        seen.add(item.url)
        return true
      })
      setScanHistory(deduped)
    } catch {
      setScanHistory([])
    }
  }, [])

  const loadStats = useCallback(async () => {
    try{
      const r=await fetch(`${API}/phishing/stats`)
      if(!r.ok) throw new Error('Istatistik endpoint hatasi')
      const d=await r.json()
      setStats(d)
    }catch(e){
      showToast('Istatistikler yüklenemedi: '+e.message,'error')
    }
  }, [])

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(()=>{loadLatest(1);loadScanHistory(1);loadStats()},[loadLatest, loadScanHistory, loadStats])

  // Real-time autocomplete with debouncing
  useEffect(() => {
    if (url.length < 1) return
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    
    searchTimeoutRef.current = setTimeout(async () => {
      try {
        const r = await fetch(`${API}/phishing/search?url=${encodeURIComponent(url)}`)
        const d = await r.json()
        if (d.status === 'success' || d.results || d.data) {
          setSearchResults(d.results || d.data || [])
          setShowDropdown(true)
        } else {
          setSearchResults([])
          setShowDropdown(false)
        }
      } catch {
        setSearchResults([])
        setShowDropdown(false)
      }
    }, 150)
    
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [url])

  const submitCheckRequest = useCallback(async (normalizedInput, forceFresh = false) => {
    const r = await fetch(`${API}/phishing/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: normalizedInput, force_fresh: forceFresh }),
    })
    if(!r.ok) throw new Error(`URL kontrol hatasi (${r.status})`)
    return r.json()
  }, [])

  async function handleCheck(forceFreshOrEvent = false, urlOverride = null) {
    // Event handler olarak kullanıldığında (onClick), React event object gelir - ignore et
    const forceFresh = typeof forceFreshOrEvent === 'boolean' ? forceFreshOrEvent : false
    const urlToCheck = urlOverride || url
    if(!urlToCheck){showToast('Lutfen bir URL girin','error');return}
    setChecking(true);setResult(null);setJobId(null);setAnalyzing(false);setPollCount(0);setShowRetryButton(false)
    try{
      const normalizedInput = /^https?:\/\//i.test(urlToCheck) ? urlToCheck : `https://${urlToCheck}`
      new URL(normalizedInput)
      const d = await submitCheckRequest(normalizedInput, forceFresh)
      if(d.status==='analyzing' && d.job_id){
        setResult(d)
        setJobId(d.job_id)
        setAnalyzing(true)
      } else {
        setResult(d)
        setShowRetryButton(false)
      }
      loadScanHistory(1)
    }catch(e){
      const errMsg = e?.message || (typeof e === 'string' ? e : 'Bilinmeyen hata')
      showToast('URL kontrol hatasi: '+errMsg,'error')
    }
    setChecking(false)
  }

  useEffect(()=>{
    if(!jobId||!analyzing) return
    if(pollCount>=MAX_POLLS){
      const tryRecoverFromCache = async () => {
        setAnalyzing(false)
        setJobId(null)
        try {
          const normalizedInput = /^https?:\/\//i.test(url) ? url : `https://${url}`
          const d = await submitCheckRequest(normalizedInput, false)
          if(d.status==='complete'){
            setResult(d)
            setShowRetryButton(false)
            loadScanHistory(1)
            return
          } else if(d.status==='analyzing') {
            setShowRetryButton(true)
            return
          }
        } catch (err) {
          void err
        }
        setShowRetryButton(true)
        showToast('Analiz zaman asimi. "Yeniden Tara" ile tekrar deneyin.','error')
      }
      void tryRecoverFromCache()
      return
    }
    const timer=setTimeout(async()=>{
      try{
        const r=await fetch(`${API}/phishing/result/${jobId}`)
        const d=await r.json()
        if(d.status==='complete'){
          setResult(d)
          setAnalyzing(false)
          setJobId(null)
          setShowRetryButton(false)
          loadScanHistory(1)
        } else if(d.status==='timeout' || d.status==='error'){
          setResult(d)
          setAnalyzing(false)
          setJobId(null)
          setShowRetryButton(true)
        } else {
          setPollCount(c=>c+1)
        }
      }catch{
        setPollCount(c=>c+1)
      }
    },3000)
    return ()=>clearTimeout(timer)
  },[jobId,analyzing,pollCount,url,loadScanHistory,submitCheckRequest])

  const totalUrls=stats?.stats?.total_urls||stats?.total_urls||0
  const phCount=stats?.stats?.phishing_count||stats?.phishing_count||0
  const safeCount=stats?.stats?.safe_count||stats?.safe_count||0

  return <div>
    <Toast {...toast}/>
    
    {/* Hero Section - Main Site Style */}
    <motion.div 
      initial={{ opacity:0, y:30 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.8, ease:theme.ease.out }}
      style={{ 
        position:'relative',
        padding: isMobile ? '70px 16px 50px' : '120px 24px 80px',
        marginBottom:32
      }}
    >
      <div aria-hidden style={{ position:'absolute', inset:0, pointerEvents:'none', overflow:'hidden' }}>
        <div style={{ position:'absolute', inset:0, backgroundImage:theme.gridPattern, backgroundSize:theme.gridPatternSize, maskImage:'radial-gradient(ellipse at 50% 40%, #000 35%, transparent 75%)', WebkitMaskImage:'radial-gradient(ellipse at 50% 40%, #000 35%, transparent 75%)', opacity:0.7 }} />
        <div style={{ position:'absolute', inset:0, background:theme.gradientHero }} />
        <div style={{ position:'absolute', top:'20%', left:'50%', transform:'translateX(-50%)', width:'600px', height:'600px', background:theme.primary, borderRadius:'50%', filter:'blur(120px)', opacity:0.15 }} />
        <div style={{ position:'absolute', bottom:'20%', right:'20%', width:'400px', height:'400px', background:theme.accent, borderRadius:'50%', filter:'blur(100px)', opacity:0.1 }} />
      </div>
      
      <div style={{ position:'relative', zIndex:1, maxWidth:1200, margin:'0 auto' }}>
        <motion.div 
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.2, duration:0.6, ease:theme.ease.out }}
          style={{ textAlign:'center', marginBottom:48 }}
        >
          <span style={{ display:'inline-block', padding:'10px 24px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'30px', fontSize:13, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'3px', marginBottom:24 }}>Phishing Dedektörü</span>
          <h1 style={{ fontSize: isMobile ? 32 : 56, fontWeight:800, color:'#fff', marginBottom:20, letterSpacing:'-2px', lineHeight:1.1 }}>URL Güvenlik Tarama Motoru</h1>
          <p style={{ color:theme.textMuted, fontSize:18, maxWidth:700, margin:'0 auto', lineHeight:1.6 }}>{totalUrls.toLocaleString('tr-TR')}+ phishing URL veritabanı ile anlık güvenlik kontrolü. Gerçek zamanlı tehdit tespiti ve detaylı analiz raporu.</p>
        </motion.div>

        {/* Search Section - Glassmorphism */}
        <motion.div 
          initial={{ opacity:0, y:30 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.4, duration:0.6, ease:theme.ease.out }}
          style={{ maxWidth:800, margin:'0 auto', position:'relative', zIndex:200 }}
        >
          <div style={{ 
            background:'rgba(255,255,255,0.05)', 
            backdropFilter:'blur(20px)', 
            WebkitBackdropFilter:'blur(20px)',
            border:`1px solid ${theme.primary}33`,
            borderRadius:theme.radius.lg,
            padding:8,
            boxShadow:'0 8px 32px rgba(0,0,0,0.3)',
            position:'relative'
          }}>
            <div style={{ display:'flex', gap:12, flexDirection: isMobile ? 'column' : 'row' }}>
              <input 
                value={url} 
                onChange={e=>setUrl(e.target.value)} 
                placeholder="https://ornek.com/supheli-link" 
                style={{ 
                  flex:1, 
                  padding:'20px 28px', 
                  borderRadius:theme.radius.md,
                  background:'rgba(255,255,255,0.05)',
                  border:'none',
                  color:'#fff', 
                  fontSize:17, 
                  outline:'none',
                  fontFamily:theme.mono,
                  letterSpacing:'0.5px'
                }} 
                onKeyDown={e=>e.key==='Enter'&&handleCheck()}
              />
              <motion.button 
                onClick={handleCheck}
                disabled={checking}
                whileHover={{ scale:1.02, boxShadow:'0 8px 30px rgba(0,212,255,0.4)' }}
                whileTap={{ scale:0.98 }}
                style={{
                  padding:'20px 40px',
                  borderRadius:theme.radius.md,
                  cursor:checking?'not-allowed':'pointer',
                  fontSize:16,
                  fontWeight:700,
                  letterSpacing:'0.5px',
                  background:checking?'#444':theme.gradientPrimary,
                  color:checking?'#888':'#000',
                  border:'none',
                  display:'inline-flex',
                  alignItems:'center',
                  gap:10,
                  opacity:checking?0.5:1,
                  boxShadow:checking?'none':'0 4px 20px rgba(0,212,255,0.3)',
                  transition:'all 0.3s ease'
                }}
              >
                {checking ? (
                  <><motion.span animate={{rotate:360}} transition={{repeat:Infinity,duration:1,ease:'linear'}} style={{display:'inline-flex'}}><IkSearch size={16} color="#888"/></motion.span> Taranıyor...</>
                ) : (
                  <><IkSearch size={16} color="#000"/> Tara</>
                )}
              </motion.button>
            </div>
          </div>

          {/* Autocomplete Dropdown — outside overflow:hidden parent */}
          <AnimatePresence>
            {showDropdown && searchResults.length > 0 && (
              <motion.div
                initial={{ opacity:0, y:-6 }}
                animate={{ opacity:1, y:0 }}
                exit={{ opacity:0, y:-6 }}
                transition={{ duration:0.15, ease:theme.ease.out }}
                style={{
                  position:'absolute',
                  top:'calc(100% + 8px)',
                  left:0,
                  right:0,
                  background:'rgba(8,12,20,0.98)',
                  backdropFilter:'blur(20px)',
                  WebkitBackdropFilter:'blur(20px)',
                  borderRadius:theme.radius.md,
                  border:`1px solid ${theme.border}`,
                  maxHeight:320,
                  overflowY:'auto',
                  zIndex:9999,
                  boxShadow:'0 16px 48px rgba(0,0,0,0.6)'
                }}
              >
                {searchResults.slice(0, 10).map((item, i) => (
                  <div
                    key={i}
                    onClick={() => {
                      setUrl(item.url || '')
                      setShowDropdown(false)
                      setTimeout(() => handleCheck(), 100)
                    }}
                    style={{
                      padding:'12px 20px',
                      borderBottom:`1px solid ${theme.border}`,
                      cursor:'pointer',
                      transition:'background 0.15s ease'
                    }}
                    onMouseEnter={e=>e.currentTarget.style.background='rgba(0,212,255,0.08)'}
                    onMouseLeave={e=>e.currentTarget.style.background='transparent'}
                  >
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                      <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:12, wordBreak:'break-all', flex:1, marginRight:12 }}>{item.url||'-'}</span>
                      <span style={{ padding:'3px 10px', borderRadius:10, fontSize:10, flexShrink:0, background:(item.risk_score||0)<50?theme.accentDim:theme.primaryDim, color:(item.risk_score||0)<50?theme.accent:theme.primary }}>{item.risk_level||'Bilinmiyor'}</span>
                    </div>
                    <div style={{ display:'flex', gap:16, fontSize:11, color:theme.textMuted }}>
                      <span>Güvenilirlik: <b style={{ color:(item.risk_score||0)<50?theme.accent:(item.risk_score||0)<80?theme.warning:theme.success }}>{item.risk_score??'-'}</b></span>
                      <span>Domain: {item.domain||'-'}</span>
                    </div>
                  </div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Scan History Preview */}
        {scanHistory.length > 0 && (
          <motion.div
            initial={{ opacity:0, y:20 }}
            animate={{ opacity:1, y:0 }}
            transition={{ delay:0.6, duration:0.6, ease:theme.ease.out }}
            style={{ 
              maxWidth:900, 
              margin:'32px auto 0',
              background:'rgba(255,255,255,0.03)',
              backdropFilter:'blur(10px)',
              WebkitBackdropFilter:'blur(10px)',
              borderRadius:theme.radius.lg,
              border:`1px solid ${theme.border}`,
              overflow:'hidden'
            }}
          >
            <div style={{ padding:'14px 20px', borderBottom:`1px solid ${theme.border}`, display:'flex', alignItems:'center', justifyContent:'space-between' }}>
              <span style={{ fontSize:13, fontWeight:700, color:'#fff', letterSpacing:'0.5px', display:'flex', alignItems:'center', gap:6 }}><IkClipboard size={13} color={theme.textMuted}/> Son Taranan URL'ler</span>
              <span style={{ fontSize:11, color:theme.textMuted }}>{scanHistory.length} tarama</span>
            </div>
            <div style={{ maxHeight:280, overflowY:'auto', overflowX:'hidden' }}>
              {scanHistory.slice(0, 10).map((item, i) => {
                const risk = item.risk_level || item.risk || ''
                const isPhishing = risk === 'phishing' || risk === 'high'
                const isSafe = risk === 'safe' || risk === 'low'
                const riskColor = isPhishing ? '#f87171' : isSafe ? '#34d399' : theme.textMuted
                const dotColor = isPhishing ? '#f87171' : isSafe ? '#34d399' : theme.textMuted
                return (
                  <div
                    key={i}
                    onClick={() => { setUrl(item.url); setTimeout(() => handleCheck(), 100) }}
                    style={{ 
                      display:'flex', 
                      alignItems:'center', 
                      gap:10, 
                      padding:'10px 20px',
                      borderBottom: i < Math.min(scanHistory.length, 10) - 1 ? `1px solid ${theme.border}33` : 'none',
                      cursor:'pointer',
                      transition:'background 0.15s ease'
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,212,255,0.07)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <span style={{ width:7, height:7, borderRadius:'50%', background:dotColor, flexShrink:0, display:'inline-block', marginTop:1 }}/>
                    <span style={{ 
                      flex:1, 
                      fontFamily:theme.mono, 
                      fontSize:12, 
                      color:theme.textSecondary || '#ccc',
                      overflow:'hidden',
                      textOverflow:'ellipsis',
                      whiteSpace:'nowrap'
                    }}>{item.url}</span>
                    {risk && <span style={{ fontSize:10, color:riskColor, flexShrink:0, fontWeight:600, textTransform:'uppercase', letterSpacing:'0.5px' }}>{risk}</span>}
                  </div>
                )
              })}
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>

    {/* C1: Derin Analiz Progress Bar */}
    <AnimatePresence>
      {analyzing && (() => {
        const elapsed = Math.round(pollCount * 3)
        const pct = Math.min((pollCount / MAX_POLLS) * 100, 95)
        const STEPS = [
          { at:0,  label:'Siteye bağlanılıyor...',           icon:IkGlobe2 },
          { at:5,  label:'Screenshot alınıyor...',            icon:IkCamera },
          { at:15, label:'VirusTotal sorgulanıyor...',        icon:IkShieldDoc },
          { at:22, label:'AbuseIPDB kontrol ediliyor...',     icon:IkScope },
          { at:30, label:'Spamhaus / URLhaus taranıyor...',   icon:IkRadar },
          { at:40, label:'AI içerik analizi yapılıyor...',    icon:IkSearch },
          { at:55, label:'ML sınıflandırması tamamlanıyor...', icon:IkChart },
          { at:70, label:'Risk skoru hesaplanıyor...',        icon:IkWarn },
        ]
        const activeStep = [...STEPS].reverse().find(s => pct >= s.at) || STEPS[0]
        const StepIcon = activeStep.icon
        return (
          <motion.div
            initial={{ opacity:0, y:-10 }}
            animate={{ opacity:1, y:0 }}
            exit={{ opacity:0, y:-10 }}
            transition={{ duration:0.3, ease:theme.ease.out }}
            style={{
              maxWidth:900,
              margin:'0 auto 24px',
              padding:'20px 24px',
              background:'rgba(0,212,255,0.05)',
              border:`1px solid ${theme.primary}33`,
              borderRadius:theme.radius.md,
              display:'flex',
              alignItems:'center',
              gap:20,
              backdropFilter:'blur(8px)',
              WebkitBackdropFilter:'blur(8px)'
            }}
          >
            {/* Radar pulse icon */}
            <div style={{ position:'relative', width:44, height:44, flexShrink:0 }}>
              {[0,1,2].map(ring => (
                <motion.div
                  key={ring}
                  animate={{ scale:[1, 2.6], opacity:[0.55, 0] }}
                  transition={{ repeat:Infinity, duration:2.2, delay:ring * 0.7, ease:'easeOut' }}
                  style={{ position:'absolute', inset:0, borderRadius:'50%', border:`1.5px solid ${theme.primary}` }}
                />
              ))}
              <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center', background:`${theme.primary}18`, borderRadius:'50%', border:`1px solid ${theme.primary}44` }}>
                <StepIcon size={18} color={theme.primary}/>
              </div>
            </div>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                <p style={{ margin:0, fontSize:14, fontWeight:700, color:theme.primary }}>Derin Analiz Devam Ediyor</p>
                <span style={{ fontSize:11, color:theme.textMuted, fontFamily:theme.mono }}>{elapsed}s</span>
              </div>
              <AnimatePresence mode="wait">
                <motion.p
                  key={activeStep.label}
                  initial={{ opacity:0, y:4 }}
                  animate={{ opacity:1, y:0 }}
                  exit={{ opacity:0, y:-4 }}
                  transition={{ duration:0.25 }}
                  style={{ margin:'0 0 10px', fontSize:12, color:theme.textMuted }}
                >
                  {activeStep.label}
                </motion.p>
              </AnimatePresence>
              <div style={{ position:'relative', height:4, background:theme.border, borderRadius:2, overflow:'hidden' }}>
                <motion.div
                  animate={{ width:`${pct}%` }}
                  transition={{ duration:0.5 }}
                  style={{ height:'100%', background:theme.gradientPrimary, borderRadius:2 }}
                />
                <motion.div
                  animate={{ x:['-100%', '200%'] }}
                  transition={{ repeat:Infinity, duration:1.6, ease:'easeInOut' }}
                  style={{ position:'absolute', top:0, left:0, height:'100%', width:'40%', background:'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)', borderRadius:2 }}
                />
              </div>
            </div>
          </motion.div>
        )
      })()}
    </AnimatePresence>

    {showRetryButton && !analyzing && (
      <div style={{ display:'flex', justifyContent:'center', margin:'0 auto 20px' }}>
        <motion.button
          onClick={() => handleCheck(true)}
          whileHover={{ scale:1.02 }}
          whileTap={{ scale:0.98 }}
          style={{
            padding:'10px 18px',
            borderRadius:theme.radius.md,
            border:`1px solid ${theme.warning}`,
            background:'rgba(245,158,11,0.12)',
            color:theme.warning,
            fontWeight:700,
            cursor:'pointer'
          }}
        >
          Yeniden Tara
        </motion.button>
      </div>
    )}

    {/* Result Display — show immediately even during deep analysis */}
    {result && <PhishingResult result={result} url={url} />}

    {/* Stats Grid */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.5, duration:0.6, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:20, marginBottom:48 }}
    >
      {[
        { label:'Toplam URL', value:totalUrls, color:theme.primary },
        { label:'Phishing', value:phCount, color:theme.danger },
        { label:'Guvenli', value:safeCount, color:theme.success },
        { label:'Bugun Taranan', value:stats?.stats?.today_scans||0, color:theme.warning }
      ].map((stat, i) => (
        <motion.div
          key={i}
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.6 + i * 0.1, duration:0.5, ease:theme.ease.spring }}
        >
          <Card style={{ 
            textAlign:'center', 
            padding:'32px 20px',
            background:'rgba(255,255,255,0.03)',
            backdropFilter:'blur(10px)',
            WebkitBackdropFilter:'blur(10px)',
            border:`1px solid ${theme.border}`
          }}>
            <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:700, letterSpacing:'2px', marginBottom:12 }}>{stat.label}</p>
            <p style={{ fontSize:40, fontWeight:800, color:stat.color }}><CountUp end={stat.value}/></p>
          </Card>
        </motion.div>
      ))}
    </motion.div>
    {/* Latest Phishing Data Table */}
    <motion.div
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.7, duration:0.5, ease:theme.ease.out }}
    >
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}>
          <span>📋</span> Son Phishing Verileri
          <span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>{latestTotal.toLocaleString('tr-TR')} kayıt • {totalPages} sayfa</span>
        </h3>
        <div style={{ overflowX:'auto', maxHeight:500, overflowY:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}>
              <tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:10, textTransform:'uppercase', letterSpacing:'1px' }}>
                <th style={{ textAlign:'left', padding:'12px 8px' }}>URL</th>
                <th style={{ textAlign:'left', padding:'12px 8px' }}>Domain</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Hedef</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Durum</th>
                <th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {latestFeeds.length===0&&<tr><td colSpan={5} style={{ textAlign:'center', padding:32, color:theme.textMuted }}>{loadingLatest?'Veri yukleniyor...':'Kayit bulunamadi'}</td></tr>}
              {latestFeeds.map((item,i)=>(
                <motion.tr 
                  key={item.id||i}
                  initial={{ opacity:0, y:10 }}
                  animate={{ opacity:1, y:0 }}
                  transition={{ delay:0.8 + i * 0.02, duration:0.3, ease:theme.ease.out }}
                  style={{ borderBottom:`1px solid ${theme.border}`, cursor:'pointer' }}
                  onClick={()=>{setUrl(item.url);setTimeout(()=>handleCheck(),100)}}
                  whileHover={{ background:theme.surface }}
                >
                  <td style={{ padding:'10px 8px', maxWidth:300, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}><span style={{ color:theme.text, fontSize:12, fontFamily:theme.mono }}>{item.url}</span></td>
                  <td style={{ padding:'10px 8px' }}><span style={{ color:theme.primary, fontSize:12 }}>{item.domain||'-'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'4px 10px', borderRadius:'10px', fontSize:10, background:theme.accentDim, color:theme.accent }}>{item.target||'Phishing'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:4, fontSize:12 }}><StatusDot active={normalizeStatus(item.status)}/>{item.status||'Bilinmiyor'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:10 }}>{item.submission_time?new Date(item.submission_time).toLocaleDateString('tr-TR'):item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):'-'}</td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages>1&&<div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:20 }}>
          <motion.button 
            onClick={()=>loadLatest(pageNum-1)} 
            disabled={pageNum<=1||loadingLatest}
            whileHover={{ scale:1.02 }}
            whileTap={{ scale:0.98 }}
            style={{ 
              padding:'8px 16px', 
              borderRadius:theme.radiusSm, 
              border:`1px solid ${theme.border}`, 
              background:theme.surface, 
              color:pageNum<=1?theme.textMuted:'#fff', 
              cursor:pageNum<=1?'not-allowed':'pointer', 
              fontSize:13, 
              fontWeight:600,
              opacity:pageNum<=1?0.5:1
            }}
          >
            ← Onceki
          </motion.button>
          <span style={{ padding:'8px 16px', color:theme.textMuted, fontSize:13 }}>Sayfa {pageNum} / {totalPages}</span>
          <motion.button 
            onClick={()=>loadLatest(pageNum+1)} 
            disabled={pageNum>=totalPages||loadingLatest}
            whileHover={{ scale:1.02 }}
            whileTap={{ scale:0.98 }}
            style={{ 
              padding:'8px 16px', 
              borderRadius:theme.radiusSm, 
              border:`1px solid ${theme.border}`, 
              background:theme.surface, 
              color:pageNum>=totalPages?theme.textMuted:'#fff', 
              cursor:pageNum>=totalPages?'not-allowed':'pointer', 
              fontSize:13, 
              fontWeight:600,
              opacity:pageNum>=totalPages?0.5:1
            }}
          >
            Sonraki →
          </motion.button>
        </div>}
      </Card>
    </motion.div>
  </div>
}

/* ===============================================
   VICTIM ATLAS — Forum Tarzı Yeniden Tasarım
   =============================================== */

const ATTACK_ICONS = {
  phishing: 'P',
  smishing: 'S',
  vishing: 'V',
  social_engineering: 'SE',
  malware_assisted: 'M',
  sahte_mobil_uygulama: 'A',
  banka_taklit: 'B',
}

const ATTACK_COLORS = {
  phishing: '#ef4444',
  smishing: '#f59e0b',
  vishing: '#8b5cf6',
  social_engineering: '#ec4899',
  malware_assisted: '#ff6b35',
  sahte_mobil_uygulama: '#06b6d4',
  banka_taklit: '#3b82f6',
}

const LOSS_ICONS = {
  bank_account: 'Banka',
  social_media: 'Sosyal',
  ecommerce: 'E-Ticaret',
  corporate_account: 'Kurumsal',
  crypto_wallet: 'Kripto',
  device_compromise: 'Cihaz',
}

function timeAgo(iso) {
  if (!iso) return ''
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000)
  if (diff < 60) return `${diff}s önce`
  if (diff < 3600) return `${Math.floor(diff/60)}dk önce`
  if (diff < 86400) return `${Math.floor(diff/3600)}sa önce`
  return `${Math.floor(diff/86400)}g önce`
}

function randomNickname() {
  const adj = ['Gizli','Anonim','Kahraman','Bilinçli','Dikkatli','Uyarılı']
  const noun = ['Kullanıcı','Vatandaş','Mağdur','Araştırmacı','Okuyucu','Tanık']
  return adj[Math.floor(Math.random()*adj.length)] + noun[Math.floor(Math.random()*noun.length)] + Math.floor(Math.random()*900+100)
}

/* -- Modal bileşeni -- */
function CaseModal({ c, onClose }) {
  const [tab, setTab] = useState('ozet')
  const [comments, setComments] = useState([])
  const [commentsLoading, setCommentsLoading] = useState(false)
  const [newComment, setNewComment] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [upvoted, setUpvoted] = useState(() => {
    try { return JSON.parse(localStorage.getItem('upvoted') || '{}') } catch { return {} }
  })
  const [nickname] = useState(() => {
    let n = localStorage.getItem('va_nickname')
    if (!n) { n = randomNickname(); localStorage.setItem('va_nickname', n) }
    return n
  })
  const [detail, setDetail] = useState(null)
  const [fraudProfile, setFraudProfile] = useState(null)
  const [fraudLoading, setFraudLoading] = useState(false)

  useEffect(() => {
    document.body.style.overflow = 'hidden'
    fetch(`${API}/victim-atlas/cases/${c.id}`).then(r=>r.json()).then(d=>setDetail(d.data||null)).catch(()=>{})
    return () => { document.body.style.overflow = '' }
  }, [c.id])

  useEffect(() => {
    if (tab !== 'profil' || fraudProfile !== null) return
    setFraudLoading(true)
    const text = [c.case_title, c.critical_warning].filter(Boolean).join(' ')
    fetch(`${API}/victim-atlas/fraud-profiles/match`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: text.slice(0, 2000), attack_method: c.attack_method || '' })
    }).then(r=>r.json()).then(d=>{ setFraudProfile(d.matched && d.profile ? d.profile : false) }).catch(()=>{ setFraudProfile(false) }).finally(()=>setFraudLoading(false))
  }, [tab, c.case_title, c.critical_warning, c.attack_method, fraudProfile])

  useEffect(() => {
    if (tab !== 'yorumlar') return

    let cancelled = false

    void (async () => {
      setCommentsLoading(true)
      try {
        const response = await fetch(`${API}/victim-atlas/cases/${c.id}/comments`)
        const data = await response.json()
        if (!cancelled) setComments(data.data || [])
      } catch {
        if (!cancelled) setComments([])
      } finally {
        if (!cancelled) setCommentsLoading(false)
      }
    })()

    return () => {
      cancelled = true
    }
  }, [tab, c.id])

  async function submitComment() {
    if (newComment.trim().length < 5) return
    setSubmitting(true)
    try {
      await fetch(`${API}/victim-atlas/cases/${c.id}/comments`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ nickname, text: newComment.trim() })
      })
      setNewComment('')
      const r = await fetch(`${API}/victim-atlas/cases/${c.id}/comments`)
      const d = await r.json(); setComments(d.data||[])
    } catch {
      void 0
    } finally {
      setSubmitting(false)
    }
  }

  async function handleUpvote(commentId) {
    const key = `${c.id}_${commentId}`
    if (upvoted[key]) return
    try {
      const r = await fetch(`${API}/victim-atlas/cases/${c.id}/comments/${commentId}/upvote`, { method:'POST' })
      const d = await r.json()
      setComments(prev => prev.map(cm => cm.id===commentId ? {...cm, upvotes: d.upvotes} : cm))
      const next = {...upvoted, [key]: true}
      setUpvoted(next); localStorage.setItem('upvoted', JSON.stringify(next))
    } catch {
      void 0
    }
  }

  const acColor = ATTACK_COLORS[c.attack_method] || theme.primary
  const steps = detail?.defense_steps || []
  const tabs = [
    { id:'ozet', label:'Özet', Icon:IkClipboard },
    { id:'korunma', label:'Korunma', Icon:IkShieldDoc },
    { id:'yorumlar', label:'Yorumlar', Icon:IkChat },
    { id:'benzer', label:'Benzer', Icon:IkLink2 },
    { id:'profil', label:'Profil', Icon:IkPerson },
  ]

  return (
    <div onClick={onClose} style={{ position:'fixed', inset:0, zIndex:2000, background:'rgba(0,0,0,0.75)', backdropFilter:'blur(6px)', display:'flex', alignItems:'center', justifyContent:'center', padding:16 }}>
      <motion.div
        initial={{ opacity:0, scale:0.95, y:20 }}
        animate={{ opacity:1, scale:1, y:0 }}
        exit={{ opacity:0, scale:0.95, y:20 }}
        transition={{ duration:0.25, ease:theme.ease.out }}
        onClick={e=>e.stopPropagation()}
        style={{ width:'100%', maxWidth:760, maxHeight:'90vh', background:theme.surface, border:`1px solid ${acColor}44`, borderRadius:theme.radiusLg, overflow:'hidden', display:'flex', flexDirection:'column', boxShadow:`0 30px 80px rgba(0,0,0,0.6), 0 0 0 1px ${acColor}22` }}
      >
        {/* Header */}
        <div style={{ padding:'20px 24px 0', borderBottom:`1px solid ${theme.border}` }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:12 }}>
            <div style={{ flex:1, paddingRight:12 }}>
              <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:8, flexWrap:'wrap' }}>
                <span style={{ fontSize:12, fontWeight:700, padding:'3px 10px', borderRadius:20, background:`${acColor}22`, color:acColor }}>
                  {ATTACK_ICONS[c.attack_method]} {displayMethod(c)}
                </span>
                <span style={{ fontSize:12, color:theme.textMuted }}>{LOSS_ICONS[c.loss_type]} {displayLossType(c)}</span>
                <span style={{ fontSize:12, padding:'3px 10px', borderRadius:20, background: c.severity_score>=75?'rgba(239,68,68,0.15)':c.severity_score>=55?'rgba(245,158,11,0.15)':'rgba(34,197,94,0.15)', color: c.severity_score>=75?theme.danger:c.severity_score>=55?theme.warning:theme.success, fontWeight:700 }}>Risk {c.severity_score}/100</span>
              </div>
              <h2 style={{ fontSize:18, fontWeight:800, color:'#fff', lineHeight:1.3, margin:0 }}>{c.case_title}</h2>
            </div>
            <button onClick={onClose} style={{ minWidth:32, height:32, borderRadius:'50%', background:theme.surface2, border:`1px solid ${theme.border}`, color:theme.textMuted, cursor:'pointer', fontSize:18, display:'flex', alignItems:'center', justifyContent:'center' }}>×</button>
          </div>
          {/* Tabs */}
          <div style={{ display:'flex', gap:0 }}>
            {tabs.map(t => (
              <button key={t.id} onClick={()=>setTab(t.id)} style={{ padding:'10px 18px', background:'none', border:'none', cursor:'pointer', fontSize:13, fontWeight:600, color: tab===t.id?theme.primary:theme.textMuted, borderBottom: tab===t.id?`2px solid ${theme.primary}`:'2px solid transparent', transition:'all 0.2s', display:'flex', alignItems:'center', gap:6 }}><t.Icon size={13}/>{t.label}</button>
            ))}
          </div>
        </div>

        {/* Body */}
        <div style={{ flex:1, overflowY:'auto', padding:24 }}>

          {/* ÖZET TAB */}
          {tab==='ozet' && (
            <div>
              {/* Kritik uyarı */}
              <div style={{ padding:16, borderRadius:theme.radiusSm, background:'rgba(245,158,11,0.1)', border:'1px solid rgba(245,158,11,0.3)', marginBottom:20, display:'flex', gap:12 }}>
                <IkWarn size={20} color={theme.warning}/>
                <p style={{ color:theme.warning, fontWeight:600, fontSize:14, margin:0, lineHeight:1.6 }}>{c.critical_warning}</p>
              </div>
              {/* Güven & Platform */}
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12, marginBottom:20 }}>
                {[
                  { label:'Risk Skoru', value:`${c.severity_score}/100`, color:theme.danger },
                  { label:'Platform', value:displayPlatform(c), color:theme.text },
                  { label:'Kayıp Tipi', value:displayLossType(c), color:theme.text },
                ].map(item => (
                  <div key={item.label} style={{ padding:'12px 14px', background:theme.surface2, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
                    <p style={{ fontSize:11, color:theme.textMuted, marginBottom:4, textTransform:'uppercase', letterSpacing:'0.5px' }}>{item.label}</p>
                    <p style={{ fontSize:14, fontWeight:700, color:item.color, margin:0 }}>{item.value}</p>
                  </div>
                ))}
              </div>
              {/* Saldırı zinciri */}
              <p style={{ fontSize:12, color:theme.textMuted, fontWeight:700, textTransform:'uppercase', letterSpacing:'1px', marginBottom:12 }}>Saldırı Zinciri</p>
              <div style={{ display:'flex', alignItems:'center', gap:4, flexWrap:'wrap', marginBottom:20 }}>
                {[
                  'İlk Temas',
                  'Güven Kazanma',
                  displayMethod(c),
                  displayLossType(c),
                  'Mağduriyet',
                ].map((step, i, arr) => (
                  <div key={i} style={{ display:'flex', alignItems:'center', gap:4 }}>
                    <div style={{ padding:'6px 12px', borderRadius:20, background: i===arr.length-1?'rgba(239,68,68,0.2)':theme.surface2, border:`1px solid ${i===arr.length-1?theme.danger:theme.border}`, fontSize:12, fontWeight:600, color: i===arr.length-1?theme.danger:theme.text, whiteSpace:'nowrap' }}>
                      {i+1}. {step}
                    </div>
                    {i < arr.length-1 && <span style={{ color:theme.textMuted, fontSize:14 }}>→</span>}
                  </div>
                ))}
              </div>
              {/* Özet metin */}
              {detail?.narrative_summary && (
                <div style={{ padding:16, background:theme.surface2, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
                  <p style={{ fontSize:14, color:theme.text, lineHeight:1.7, margin:0 }}>{detail.narrative_summary}</p>
                </div>
              )}
            </div>
          )}

          {/* KORUNMA TAB */}
          {tab==='korunma' && (
            <div>
              <p style={{ fontSize:14, color:theme.textMuted, marginBottom:20, lineHeight:1.6 }}>Bu tür saldırılardan korunmak için aşağıdaki adımları uygulayın:</p>
              {steps.length===0 && <p style={{ color:theme.textMuted, textAlign:'center', padding:40 }}>Yükleniyor...</p>}
              {steps.map((step, i) => (
                <motion.div key={i} initial={{ opacity:0, x:-10 }} animate={{ opacity:1, x:0 }} transition={{ delay:i*0.07 }}
                  style={{ display:'flex', gap:14, padding:'14px 16px', borderRadius:theme.radiusSm, background:theme.surface2, border:`1px solid ${theme.border}`, marginBottom:10 }}
                  onMouseEnter={e=>{e.currentTarget.style.borderColor=`${acColor}55`;e.currentTarget.style.transform='translateX(4px)'}}
                  onMouseLeave={e=>{e.currentTarget.style.borderColor=theme.border;e.currentTarget.style.transform='none'}}
                >
                  <div style={{ minWidth:28, height:28, borderRadius:'50%', background:`${acColor}22`, border:`1px solid ${acColor}44`, display:'flex', alignItems:'center', justifyContent:'center', color:acColor, fontWeight:800, fontSize:13 }}>{i+1}</div>
                  <p style={{ fontSize:14, color:theme.text, lineHeight:1.6, margin:0 }}>{step}</p>
                </motion.div>
              ))}
            </div>
          )}

          {/* YORUMLAR TAB */}
          {tab==='yorumlar' && (
            <div>
              {/* Yorum yaz */}
              <div style={{ padding:16, background:theme.surface2, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, marginBottom:20 }}>
                <p style={{ fontSize:12, color:theme.textMuted, marginBottom:8 }}>Benzer bir deneyim yaşadınız mı? Paylaşın (anonim):</p>
                <textarea
                  value={newComment}
                  onChange={e=>setNewComment(e.target.value)}
                  placeholder="Deneyiminizi veya uyarınızı yazın..."
                  rows={3}
                  style={{ width:'100%', padding:12, borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:13, resize:'vertical', outline:'none', lineHeight:1.6, boxSizing:'border-box' }}
                />
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:10 }}>
                  <span style={{ fontSize:12, color:theme.textMuted }}>👤 {nickname}</span>
                  <button onClick={submitComment} disabled={submitting||newComment.trim().length<5}
                    style={{ padding:'8px 20px', borderRadius:theme.radiusSm, background:newComment.trim().length>=5?acColor:'#333', color:newComment.trim().length>=5?'#000':'#666', border:'none', cursor:newComment.trim().length>=5?'pointer':'not-allowed', fontWeight:700, fontSize:13 }}>
                    {submitting ? '...' : 'Gönder'}
                  </button>
                </div>
              </div>
              {/* Yorum listesi */}
              {commentsLoading && <p style={{ textAlign:'center', color:theme.textMuted, padding:20 }}>Yükleniyor...</p>}
              {!commentsLoading && comments.length===0 && (
                <div style={{ textAlign:'center', padding:40, color:theme.textMuted }}>
                  <p style={{ fontSize:32, marginBottom:8 }}>💬</p>
                  <p>Henüz yorum yok. İlk yorumu sen yaz!</p>
                </div>
              )}
              {comments.map(cm => (
                <motion.div key={cm.id} initial={{ opacity:0, y:8 }} animate={{ opacity:1, y:0 }}
                  style={{ padding:'14px 16px', background:theme.surface2, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, marginBottom:10 }}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                    <div style={{ display:'flex', gap:8, alignItems:'center' }}>
                      <span style={{ fontSize:13, fontWeight:700, color:theme.primary }}>👤 {cm.nickname}</span>
                      <span style={{ fontSize:11, color:theme.textMuted }}>{timeAgo(cm.created_at)}</span>
                    </div>
                    <button onClick={()=>handleUpvote(cm.id)}
                      style={{ display:'flex', alignItems:'center', gap:4, padding:'4px 10px', borderRadius:20, background: upvoted[`${c.id}_${cm.id}`]?'rgba(0,212,255,0.15)':theme.surface, border:`1px solid ${upvoted[`${c.id}_${cm.id}`]?theme.primary:theme.border}`, color: upvoted[`${c.id}_${cm.id}`]?theme.primary:theme.textMuted, cursor: upvoted[`${c.id}_${cm.id}`]?'default':'pointer', fontSize:12, fontWeight:600 }}>
                      👍 {cm.upvotes}
                    </button>
                  </div>
                  <p style={{ fontSize:13, color:theme.text, lineHeight:1.6, margin:0 }}>{cm.text}</p>
                </motion.div>
              ))}
            </div>
          )}

          {/* BENZER VAKALAR TAB */}
          {tab==='benzer' && <SimilarCases attackMethod={c.attack_method} excludeId={c.id} />}

          {/* DOLANDIRICILIK PROFİLİ TAB */}
          {tab==='profil' && (
            <div>
              {fraudLoading && (
                <div style={{ textAlign:'center', padding:40, color:theme.textMuted }}>
                  <motion.div animate={{ rotate:360 }} transition={{ repeat:Infinity, duration:1.2, ease:'linear' }} style={{ width:32, height:32, borderRadius:'50%', border:`3px solid ${acColor}`, borderTopColor:'transparent', margin:'0 auto 12px' }} />
                  <p style={{ fontSize:13 }}>Profil analiz ediliyor...</p>
                </div>
              )}
              {!fraudLoading && fraudProfile === false && (
                <div style={{ textAlign:'center', padding:40 }}>
                  <p style={{ fontSize:32, marginBottom:10 }}>🔍</p>
                  <p style={{ color:theme.textMuted, fontSize:14 }}>Bu vaka için eşleşen bir dolandırıcılık profili bulunamadı.</p>
                  <p style={{ color:theme.textMuted, fontSize:12, marginTop:6 }}>Profil veritabanı zamanla genişleyecektir.</p>
                </div>
              )}
              {!fraudLoading && fraudProfile && (() => {
                const SEV = {
                  critical: { bg:'rgba(239,68,68,0.12)', border:'#ef444455', accent:'#f87171', label:'KRİTİK' },
                  high:     { bg:'rgba(245,158,11,0.12)', border:'#f59e0b55', accent:'#fbbf24', label:'YÜKSEK' },
                  medium:   { bg:'rgba(0,212,255,0.08)', border:'#00d4ff44', accent:'#00d4ff', label:'ORTA' },
                  low:      { bg:'rgba(34,197,94,0.08)', border:'#22c55e44', accent:'#34d399', label:'DÜŞÜK' },
                }
                const s = SEV[fraudProfile.severity] || SEV.high
                return (
                  <motion.div initial={{ opacity:0, y:12 }} animate={{ opacity:1, y:0 }} transition={{ duration:0.4, ease:[0.23,1,0.32,1] }}>
                    <div style={{ background:s.bg, border:`1px solid ${s.border}`, borderRadius:theme.radiusMd, padding:'20px 22px', marginBottom:20, position:'relative', overflow:'hidden' }}>
                      <div aria-hidden style={{ position:'absolute', inset:0, background:`radial-gradient(ellipse at 0% 50%, ${s.accent}18 0%, transparent 65%)`, pointerEvents:'none' }} />
                      <div style={{ position:'relative', zIndex:1 }}>
                        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
                          <span style={{ fontSize:22 }}>🚨</span>
                          <div style={{ flex:1 }}>
                            <span style={{ fontSize:10, fontWeight:800, letterSpacing:'2.5px', color:s.accent, textTransform:'uppercase' }}>Dolandırıcılık Profili · {s.label}</span>
                            <h3 style={{ margin:0, fontSize:18, fontWeight:800, color:'#fff', letterSpacing:'-0.3px', marginTop:2 }}>{fraudProfile.name_tr}</h3>
                          </div>
                          <span style={{ padding:'4px 12px', borderRadius:20, background:`${s.accent}22`, border:`1px solid ${s.accent}44`, fontSize:12, fontWeight:700, color:s.accent, flexShrink:0 }}>%{fraudProfile.confidence} güven</span>
                        </div>
                        <p style={{ margin:'0 0 16px', fontSize:13, color:theme.textMuted, lineHeight:1.7 }}>{fraudProfile.description}</p>
                        <div style={{ display:'flex', gap:20, flexWrap:'wrap' }}>
                          {fraudProfile.case_count > 0 && (
                            <div style={{ textAlign:'center' }}>
                              <p style={{ margin:0, fontSize:22, fontWeight:800, color:s.accent }}>{fraudProfile.case_count}</p>
                              <p style={{ margin:0, fontSize:11, color:theme.textMuted }}>Kayıtlı Vaka</p>
                            </div>
                          )}
                          {fraudProfile.avg_loss_try && (
                            <div style={{ textAlign:'center' }}>
                              <p style={{ margin:0, fontSize:22, fontWeight:800, color:s.accent }}>₺{Number(fraudProfile.avg_loss_try).toLocaleString('tr-TR')}</p>
                              <p style={{ margin:0, fontSize:11, color:theme.textMuted }}>Ort. Kayıp</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                    {/* Tipik göstergeler */}
                    {fraudProfile.indicators?.length > 0 && (
                      <div>
                        <p style={{ fontSize:12, color:theme.textMuted, fontWeight:700, textTransform:'uppercase', letterSpacing:'1px', marginBottom:10 }}>Tipik Göstergeler</p>
                        <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
                          {fraudProfile.indicators.map((ind, i) => (
                            <motion.div key={i} initial={{ opacity:0, x:-8 }} animate={{ opacity:1, x:0 }} transition={{ delay:i*0.05 }}
                              style={{ display:'flex', alignItems:'flex-start', gap:10, padding:'10px 14px', borderRadius:8, background:theme.surface2, border:`1px solid ${theme.border}` }}>
                              <span style={{ color:s.accent, flexShrink:0, marginTop:1 }}>⚠</span>
                              <span style={{ fontSize:13, color:theme.text, lineHeight:1.5 }}>{ind}</span>
                            </motion.div>
                          ))}
                        </div>
                      </div>
                    )}
                  </motion.div>
                )
              })()}
            </div>
          )}
        </div>
      </motion.div>
    </div>
  )
}

function SimilarCases({ attackMethod, excludeId }) {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  useEffect(() => {
    fetch(`${API}/victim-atlas/cases?attack_method=${attackMethod}&limit=6&hot_set_only=true`)
      .then(r=>r.json()).then(d=>{
        setCases((d.data||[]).filter(c=>c.id!==excludeId).slice(0,4))
      }).catch(()=>setCases([])).finally(()=>setLoading(false))
  }, [attackMethod, excludeId])
  if (loading) return <p style={{ textAlign:'center', color:theme.textMuted, padding:20 }}>Yükleniyor...</p>
  if (!cases.length) return <p style={{ textAlign:'center', color:theme.textMuted, padding:20 }}>Benzer vaka bulunamadı.</p>
  return (
    <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
      {cases.map(c=>(
        <div key={c.id} style={{ padding:'12px 16px', background:theme.surface2, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
          <div style={{ display:'flex', gap:8, marginBottom:4 }}>
            <span style={{ fontSize:11, padding:'2px 8px', borderRadius:12, background:`${ATTACK_COLORS[c.attack_method]||theme.primary}22`, color:ATTACK_COLORS[c.attack_method]||theme.primary, fontWeight:700 }}>{displayMethod(c)}</span>
            <span style={{ fontSize:11, color:theme.textMuted }}>Risk {c.severity_score}/100</span>
          </div>
          <p style={{ fontSize:13, color:'#fff', fontWeight:600, margin:0 }}>{c.case_title}</p>
        </div>
      ))}
    </div>
  )
}

function methodLabel(value='') {
  const labels = {
    phishing: 'Oltalama (Phishing)',
    smishing: 'SMS Oltalamasi (Smishing)',
    vishing: 'Telefon Dolandiriciligi (Vishing)',
    social_engineering: 'Sosyal Muhendislik',
    malware_assisted: 'Zararli Yazilim Destekli',
    sahte_mobil_uygulama: 'Sahte Mobil Uygulama',
    banka_taklit: 'Banka Taklit Senaryosu',
  }
  return labels[value] || value || 'Bilinmiyor'
}

function lossTypeLabel(value='') {
  const labels = {
    bank_account: 'Banka Hesabi',
    social_media: 'Sosyal Medya Hesabi',
    ecommerce: 'E-Ticaret',
    corporate_account: 'Kurumsal Hesap',
    crypto_wallet: 'Kripto Cuzdan',
    device_compromise: 'Cihaz Ele Gecirme',
  }
  return labels[value] || value || 'Bilinmiyor'
}

function platformLabel(value='') {
  const labels = {
    banking: 'Bankacilik',
    ecommerce: 'E-Ticaret',
    instagram: 'Instagram',
    whatsapp: 'WhatsApp',
    telegram: 'Telegram',
    microsoft365: 'Microsoft 365',
    sikayet_platformu: 'Sikayet Platformu',
    general: 'Genel',
    crypto: 'Kripto',
  }
  return labels[value] || value || 'Genel'
}

function displayMethod(c = {}) {
  return c.attack_method_tr || methodLabel(c.attack_method)
}

function displayLossType(c = {}) {
  return c.loss_type_tr || lossTypeLabel(c.loss_type)
}

function displayPlatform(c = {}) {
  return c.target_platform_tr || platformLabel(c.target_platform)
}

function VictimAtlas({ onOpenAIAnalyzer, initialProfile = null, onClearProfile }) {
  const [cases, setCases] = useState([])
  const [stats, setStats] = useState(null)
  const [page, setPage] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [total, setTotal] = useState(0)
  const [query, setQuery] = useState('')
  const [attackMethod, setAttackMethod] = useState('')
  const [lossType, setLossType] = useState('')
  const [loading, setLoading] = useState(false)
  const [selectedCase, setSelectedCase] = useState(null)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  useEffect(() => {
    if (!initialProfile) return
    onClearProfile?.()
    const firstKw = (initialProfile.atlas_search_q || '').split(' ')[0] || ''
    const tryFetch = async (params) => {
      try {
        const r = await fetch(`${API}/victim-atlas/cases?${params.toString()}`)
        const d = await r.json()
        return d.data?.[0] || null
      } catch { return null }
    }
    ;(async () => {
      let found = null
      if (firstKw) {
        const p = new URLSearchParams({ page:'1', limit:'5', confidence_min:'0', hot_set_only:'false' })
        p.set('q', firstKw)
        found = await tryFetch(p)
      }
      if (!found && initialProfile.attack_method) {
        const p = new URLSearchParams({ page:'1', limit:'5', confidence_min:'0', hot_set_only:'false', attack_method: initialProfile.attack_method })
        found = await tryFetch(p)
      }
      if (!found) {
        const p = new URLSearchParams({ page:'1', limit:'5', confidence_min:'0', hot_set_only:'false' })
        found = await tryFetch(p)
      }
      if (found) setSelectedCase(found)
    })()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialProfile])

  const showToast = useCallback((msg, type='success') => {
    setToast({message:msg, type, visible:true})
    setTimeout(()=>setToast(t=>({...t, visible:false})), 2500)
  }, [])

  const loadStats = useCallback(async () => {
    try {
      const r = await fetch(`${API}/victim-atlas/stats`)
      if(!r.ok) throw new Error('stats failed')
      const d = await r.json()
      setStats(d.stats || {})
    } catch {
      setStats(null)
    }
  }, [])

  const loadCases = useCallback(async (nextPage=1) => {
    try {
      setLoading(true)
      const params = new URLSearchParams({
        page: String(nextPage),
        limit: '12',
        confidence_min: '60',
        hot_set_only: 'true',
      })
      if (query.trim()) params.set('q', query.trim())
      if (attackMethod) params.set('attack_method', attackMethod)
      if (lossType) params.set('loss_type', lossType)
      const r = await fetch(`${API}/victim-atlas/cases?${params.toString()}`)
      if(!r.ok) throw new Error(`cases failed (${r.status})`)
      const d = await r.json()
      setCases(d.data || [])
      setPage(d.page || nextPage)
      setTotalPages(d.total_pages || 1)
      setTotal(d.total || 0)
    } catch (e) {
      showToast('Vaka listesi alinamadi: '+e.message, 'error')
      setCases([])
    } finally {
      setLoading(false)
    }
  }, [attackMethod, lossType, query, showToast])

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(()=>{loadStats(); loadCases(1)},[loadStats, loadCases])

  function riskColor(score=0) {
    if (score >= 75) return theme.danger
    if (score >= 55) return theme.warning
    return theme.success
  }

  const methodDist = stats?.attack_method_distribution || {}
  const topMethods = Object.entries(methodDist).sort((a,b)=>b[1]-a[1]).slice(0,6)

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>
    {selectedCase && <CaseModal c={selectedCase} onClose={()=>setSelectedCase(null)} />}

    {/* Hero */}
    <div style={{ textAlign:'center', padding:'48px 24px 32px', position:'relative' }}>
      <span style={{ display:'inline-block', padding:'6px 16px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:20, fontSize:11, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'2px', marginBottom:16 }}>🇹🇷 Türkiye Odaklı</span>
      <h1 style={{ fontSize:40, fontWeight:800, color:'#fff', marginBottom:12, letterSpacing:'-1.5px' }}>Siber Mağduriyet Forumu</h1>
      <p style={{ color:theme.textMuted, fontSize:16, maxWidth:560, margin:'0 auto 32px', lineHeight:1.6 }}>Türkiye'deki dolandırıcılık vakalarını incele, deneyimlerini paylaş ve kendini koru.</p>
      {/* Stats */}
      <div style={{ display:'flex', justifyContent:'center', gap:32, flexWrap:'wrap' }}>
        {[
          { label:'Toplam Vaka', value:stats?.total_cases||0, color:theme.primary },
          { label:'Güncel Hot Set', value:stats?.hot_cases||0, color:theme.accent },
          { label:'Yüksek Güven', value:stats?.high_confidence_cases||0, color:theme.success },
          { label:'Listelenen', value:total||0, color:theme.warning },
        ].map(s=>(
          <div key={s.label} style={{ textAlign:'center' }}>
            <p style={{ fontSize:28, fontWeight:800, color:s.color, margin:0 }}><CountUp end={s.value}/></p>
            <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'0.5px', margin:0 }}>{s.label}</p>
          </div>
        ))}
      </div>
    </div>

    <ModuleErrorBoundary>
      <TurkeyHeatmapSection compact={false} />
    </ModuleErrorBoundary>

    {/* Trend bar */}
    {topMethods.length>0 && (
      <div style={{ display:'flex', alignItems:'center', gap:8, flexWrap:'wrap', padding:'10px 0', marginBottom:20, borderTop:`1px solid ${theme.border}`, borderBottom:`1px solid ${theme.border}` }}>
        <span style={{ fontSize:11, color:theme.textMuted, fontWeight:700, textTransform:'uppercase', whiteSpace:'nowrap' }}>🔥 Trend:</span>
        {topMethods.map(([name,count])=>(
          <button key={name} onClick={()=>{setAttackMethod(name); setTimeout(()=>loadCases(1),0)}}
            style={{ padding:'5px 12px', borderRadius:20, border:`1px solid ${ATTACK_COLORS[name]||theme.primary}44`, background:`${ATTACK_COLORS[name]||theme.primary}15`, color:ATTACK_COLORS[name]||theme.primary, fontSize:11, fontWeight:700, cursor:'pointer', whiteSpace:'nowrap' }}>
            {ATTACK_ICONS[name]} {methodLabel(name)} <span style={{ opacity:0.7 }}>·{count}</span>
          </button>
        ))}
        {attackMethod && <button onClick={()=>{setAttackMethod(''); setTimeout(()=>loadCases(1),0)}} style={{ padding:'5px 12px', borderRadius:20, border:`1px solid ${theme.border}`, background:'none', color:theme.textMuted, fontSize:11, cursor:'pointer' }}>✕ Temizle</button>}
      </div>
    )}

    {/* Search & Filter */}
    <div style={{ display:'flex', gap:10, marginBottom:20, flexWrap:'wrap' }}>
      <input value={query} onChange={e=>setQuery(e.target.value)} onKeyDown={e=>e.key==='Enter'&&loadCases(1)}
        placeholder="🔍  Ara: sahte banka, kargo SMS, Instagram hesap..."
        style={{ flex:1, minWidth:200, padding:'12px 16px', borderRadius:theme.radiusSm, background:theme.surface, border:`1px solid ${theme.border}`, color:'#fff', outline:'none', fontSize:14 }} />
      <select value={attackMethod} onChange={e=>setAttackMethod(e.target.value)}
        style={{ padding:'12px 10px', borderRadius:theme.radiusSm, background:theme.surface, border:`1px solid ${theme.border}`, color:'#fff', fontSize:13 }}>
        <option value="">Tüm Yöntemler</option>
        <option value="banka_taklit">🏦 Banka Taklidi</option>
        <option value="sahte_mobil_uygulama">📲 Sahte Mobil App</option>
        <option value="phishing">🎣 Phishing</option>
        <option value="smishing">📱 Smishing (SMS)</option>
        <option value="vishing">📞 Vishing (Telefon)</option>
        <option value="social_engineering">🎭 Sosyal Mühendislik</option>
        <option value="malware_assisted">🦠 Zararlı Yazılım</option>
      </select>
      <select value={lossType} onChange={e=>setLossType(e.target.value)}
        style={{ padding:'12px 10px', borderRadius:theme.radiusSm, background:theme.surface, border:`1px solid ${theme.border}`, color:'#fff', fontSize:13 }}>
        <option value="">Tüm Kayıplar</option>
        <option value="bank_account">🏧 Banka Hesabı</option>
        <option value="social_media">📸 Sosyal Medya</option>
        <option value="ecommerce">📦 E-Ticaret</option>
        <option value="corporate_account">🏢 Kurumsal</option>
        <option value="crypto_wallet">₿ Kripto</option>
        <option value="device_compromise">💻 Cihaz</option>
      </select>
      <GlowButton onClick={()=>loadCases(1)} loading={loading}>Getir</GlowButton>
    </div>

    {/* Forum list */}
    <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
      {loading && <div style={{ textAlign:'center', padding:40, color:theme.textMuted }}><Spinner size={32}/><p style={{ marginTop:12 }}>Vakalar yükleniyor...</p></div>}
      {!loading && cases.length===0 && (
        <div style={{ textAlign:'center', padding:60, color:theme.textMuted, background:theme.surface, borderRadius:theme.radiusMd, border:`1px solid ${theme.border}` }}>
          <p style={{ fontSize:36, marginBottom:8 }}>🔍</p>
          <p style={{ fontSize:15 }}>Filtreye uygun vaka bulunamadı.</p>
        </div>
      )}
      {cases.map((c, idx) => {
        const ac = ATTACK_COLORS[c.attack_method] || theme.primary
        return (
          <motion.div key={c.id}
            initial={{ opacity:0, y:10 }} animate={{ opacity:1, y:0 }} transition={{ delay:idx*0.04 }}
            onClick={()=>setSelectedCase(c)}
            style={{ display:'flex', gap:0, background:theme.surface, border:`1px solid ${theme.border}`, borderRadius:theme.radiusMd, overflow:'hidden', cursor:'pointer', transition:'all 0.2s ease' }}
            onMouseEnter={e=>{e.currentTarget.style.borderColor=`${ac}55`;e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow=`0 8px 30px ${ac}18`}}
            onMouseLeave={e=>{e.currentTarget.style.borderColor=theme.border;e.currentTarget.style.transform='none';e.currentTarget.style.boxShadow='none'}}
          >
            {/* Sol renk şeridi */}
            <div style={{ width:4, minWidth:4, background:ac, flexShrink:0 }} />
            {/* İçerik */}
            <div style={{ flex:1, padding:'14px 18px', display:'flex', gap:16, alignItems:'center', flexWrap:'wrap' }}>
              <div style={{ display:'inline-flex', alignItems:'center', justifyContent:'center', width:40, height:40, borderRadius:10, background:`${ac}22`, color:ac, fontSize:11, fontWeight:800 }}>{ATTACK_ICONS[c.attack_method] || '!'}</div>
              <div style={{ flex:1, minWidth:200 }}>
                <div style={{ display:'flex', gap:6, alignItems:'center', marginBottom:5, flexWrap:'wrap' }}>
                  <span style={{ fontSize:11, fontWeight:700, padding:'2px 8px', borderRadius:12, background:`${ac}20`, color:ac }}>{displayMethod(c)}</span>
                  <span style={{ fontSize:11, color:theme.textMuted }}>{LOSS_ICONS[c.loss_type]} {displayLossType(c)}</span>
                  <span style={{ fontSize:11, color:theme.textMuted }}>• {displayPlatform(c)}</span>
                </div>
                <p style={{ fontSize:15, fontWeight:700, color:'#fff', margin:'0 0 4px', lineHeight:1.3 }}>{c.case_title}</p>
                <p style={{ fontSize:12, color:theme.textMuted, margin:0, lineHeight:1.5 }}>{c.critical_warning?.slice(0,100)}{c.critical_warning?.length>100?'...':''}</p>
              </div>
              {/* Sağ meta */}
              <div style={{ display:'flex', flexDirection:'column', alignItems:'flex-end', gap:6, flexShrink:0 }}>
                <span style={{ fontSize:12, fontWeight:800, padding:'4px 10px', borderRadius:20, background: c.severity_score>=75?'rgba(239,68,68,0.15)':c.severity_score>=55?'rgba(245,158,11,0.15)':'rgba(34,197,94,0.15)', color:riskColor(c.severity_score) }}>Risk {c.severity_score}</span>
                <span style={{ fontSize:11, color:theme.primary, fontWeight:600 }}>Detay →</span>
              </div>
            </div>
          </motion.div>
        )
      })}
    </div>

    {totalPages>1 && <div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:20 }}>
      <button onClick={()=>loadCases(page-1)} disabled={page<=1||loading} style={{ padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:page<=1?theme.textMuted:'#fff', cursor:page<=1?'not-allowed':'pointer' }}>← Önceki</button>
      <span style={{ padding:'8px 14px', color:theme.textMuted, fontSize:13 }}>Sayfa {page} / {totalPages}</span>
      <button onClick={()=>loadCases(page+1)} disabled={page>=totalPages||loading} style={{ padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:page>=totalPages?theme.textMuted:'#fff', cursor:page>=totalPages?'not-allowed':'pointer' }}>Sonraki →</button>
    </div>}
  </div>
}

function VictimAtlasDefense() { return null }

/* ===============================================
   HONEYPOT / IOC — Redesign
   =============================================== */

const THREAT_META = {
  BOTNET:              { color:'#ef4444', icon: Bug },
  MALWARE:             { color:'#ff6b35', icon: AlertTriangle },
  PAYLOAD_DELIVERY:    { color:'#f59e0b', icon: Zap },
  PHISHING:            { color:'#eab308', icon: Mail },
  'BOTNET.CC':         { color:'#ec4899', icon: Radio },
  SPAM:                { color:'#8b5cf6', icon: Mail },
  'SPAM SOURCE':       { color:'#a855f7', icon: Server },
  'CREDENTIAL HARVESTING': { color:'#06b6d4', icon: Lock },
}

function ThreatIcon({ type, size=14 }) {
  const meta = THREAT_META[type?.toUpperCase()] || { color: theme.primary, icon: Shield }
  const Icon = meta.icon
  return <Icon size={size} color={meta.color} strokeWidth={2} />
}

function CopyBtn({ value }) {
  const [copied, setCopied] = useState(false)
  function handleCopy() {
    navigator.clipboard?.writeText(value).catch(()=>{})
    setCopied(true); setTimeout(()=>setCopied(false), 1800)
  }
  return (
    <button onClick={e=>{e.stopPropagation();handleCopy()}}
      title="Kopyala"
      style={{ background:'none', border:'none', cursor:'pointer', padding:4, color: copied ? theme.success : theme.textMuted, flexShrink:0, lineHeight:0 }}>
      {copied ? <Check size={12} color={theme.success}/> : <Copy size={12}/>}
    </button>
  )
}

function HoneypotIOC({ initialIocQuery = '', onClearPrefill }) {
  const [iocStats, setIocStats] = useState(null)
  const [iocList, setIocList] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searching, setSearching] = useState(false)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })
  const [showDropdown, setShowDropdown] = useState(false)
  const [exportingSTIX, setExportingSTIX] = useState(false)
  const searchTimeoutRef = useRef(null)
  const iocPrefillRef = useRef('')

  useEffect(() => {
    if (initialIocQuery && initialIocQuery !== iocPrefillRef.current) {
      iocPrefillRef.current = initialIocQuery
      setSearchQuery(initialIocQuery)
      onClearPrefill?.()
      setTimeout(() => {
        fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(initialIocQuery)}`)
          .then(r => r.json())
          .then(d => { setSearchResults(d.results||d.data||d.iocs||[]); setShowDropdown(true) })
          .catch(() => {})
      }, 200)
    }
  }, [initialIocQuery, onClearPrefill])

  async function exportSTIX(minRisk = 0) {
    setExportingSTIX(true)
    try {
      const url = `${API}/ioc/export/stix?min_risk_score=${minRisk}&limit=1000`
      const res = await fetch(url)
      if (!res.ok) throw new Error('Export başarısız')
      const blob = await res.blob()
      const downloadUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = downloadUrl
      a.download = `aegisnexus-ioc-stix-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(downloadUrl)
      showToast('STIX 2.1 dosyası indirildi')
    } catch (e) {
      showToast('STIX export hatası: ' + e.message, 'error')
    }
    setExportingSTIX(false)
  }

  async function handleSearch(){if(!searchQuery)return;setSearching(true);try{const r=await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`);const d=await r.json();if(d.status==='success'||d.results){setSearchResults(d.results||d.data||d.iocs||[]);setShowDropdown(true)}else{showToast('Arama sonucu bulunamadi veya hata: '+d.message,'error')}}catch(e){showToast('Arama hatasi: '+e.message,'error')};setSearching(false)}
  function showToast(msg,t='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(v=>({...v,visible:false})),3000)}
  
  // Real-time autocomplete with debouncing
  useEffect(() => {
    if (searchQuery.length < 2) return
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    
    searchTimeoutRef.current = setTimeout(async () => {
      setSearching(true)
      try {
        const r = await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`)
        const d = await r.json()
        if (d.status === 'success' || d.results) {
          setSearchResults(d.results || d.data || d.iocs || [])
          setShowDropdown(true)
        } else {
          setSearchResults([])
          setShowDropdown(false)
        }
      } catch {
        setSearchResults([])
        setShowDropdown(false)
      }
      setSearching(false)
    }, 500)
    
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [searchQuery])
  
  useEffect(() => {
    let cancelled = false

    void (async () => {
      try {
        const statsResponse = await fetch(`${API}/honeypot/ioc/stats`)
        const statsData = await statsResponse.json()
        if (!cancelled) setIocStats(statsData)
      } catch {
        if (!cancelled) setIocStats(null)
      }

      try {
        const levels = ['critical', 'high', 'medium', 'low']
        const allIocs = []
        for (const level of levels) {
          try {
            const response = await fetch(`${API}/honeypot/ioc/by-risk-score?level=${level}&limit=8`)
            const data = await response.json()
            if (data.iocs) allIocs.push(...data.iocs)
          } catch {
            continue
          }
        }
        if (!cancelled) setIocList(allIocs)
      } catch {
        if (cancelled) return
        try {
          const response = await fetch(`${API}/honeypot/ioc/list?limit=25`)
          const data = await response.json()
          setIocList(data.data || data.iocs || [])
        } catch {
          setIocList([])
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [])

  const statsData=iocStats?.stats||iocStats||{}
  const riskDist=statsData?.risk_distribution||iocStats?.risk_distribution||[]
  const topThreats=statsData?.top_threats||iocStats?.top_threats||[]
  const sourceBreakdown=statsData?.source_breakdown||iocStats?.source_breakdown||[]
  const totalIocs=statsData?.total_iocs||iocStats?.total_iocs||iocStats?.total_records||0
  const highRisk=statsData?.high_risk_count||iocStats?.high_risk_count||0
  const mediumRisk=statsData?.medium_risk_count||iocStats?.medium_risk_count||0

  const maxThreat = Math.max(...(topThreats.map(t=>t.count||0)), 1)
  const highRiskPct = totalIocs>0 ? ((highRisk/totalIocs)*100).toFixed(1) : 0

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>

    {/* ── Hero ── */}
    <div style={{ textAlign:'center', padding:'48px 24px 32px' }}>
      <div style={{ display:'inline-flex', alignItems:'center', gap:8, padding:'6px 16px', background:'rgba(239,68,68,0.1)', border:'1px solid rgba(239,68,68,0.3)', borderRadius:20, marginBottom:16 }}>
        <span style={{ width:8, height:8, borderRadius:'50%', background:'#ef4444', display:'inline-block', animation:'glowPulse 1.5s ease-in-out infinite' }}/>
        <span style={{ fontSize:11, fontWeight:700, color:'#ef4444', textTransform:'uppercase', letterSpacing:'2px' }}>Canlı Tehdit Akışı</span>
      </div>
      <h1 style={{ fontSize:40, fontWeight:800, color:'#fff', marginBottom:12, letterSpacing:'-1.5px' }}>Tehdit İstihbaratı & IOC Analizi</h1>
      <p style={{ color:theme.textMuted, fontSize:15, maxWidth:580, margin:'0 auto 32px', lineHeight:1.6 }}>28.000+ tehdit göstergesi. Zararlı IP, domain ve URL'leri sorgula — siber saldırılara karşı anlık uyarı al.</p>

      {/* Stat sayaçları */}
      <div style={{ display:'flex', justifyContent:'center', gap:40, flexWrap:'wrap', marginBottom:40 }}>
        {[
          { label:'Toplam IOC', value:totalIocs, color:theme.primary, Icon:Database },
          { label:'Yüksek Risk', value:highRisk, color:'#ef4444', Icon:AlertTriangle },
          { label:'Orta Risk', value:mediumRisk, color:theme.warning, Icon:Activity },
          { label:'Kaynak', value:sourceBreakdown.length, color:theme.success, Icon:Globe },
        ].map(s=>(
          <div key={s.label} style={{ textAlign:'center' }}>
            <div style={{ display:'flex', justifyContent:'center', marginBottom:6 }}><s.Icon size={18} color={s.color}/></div>
            <p style={{ fontSize:28, fontWeight:800, color:s.color, margin:'0 0 2px' }}><CountUp end={s.value}/></p>
            <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'0.5px', margin:0 }}>{s.label}</p>
          </div>
        ))}
      </div>

      {/* Arama */}
      <div style={{ maxWidth:680, margin:'0 auto', position:'relative' }}>
        <div style={{ display:'flex', gap:10, background:theme.surface, padding:8, borderRadius:theme.radiusLg, border:`1px solid ${theme.border}` }}>
          <div style={{ display:'flex', alignItems:'center', paddingLeft:12, color:theme.textMuted }}><Search size={16}/></div>
          <input value={searchQuery} onChange={e=>{const value=e.target.value;setSearchQuery(value);if(value.length<2)setShowDropdown(false)}} onKeyDown={e=>e.key==='Enter'&&handleSearch()}
            placeholder="IP adresi, domain, URL veya hash girin..."
            style={{ flex:1, padding:'14px 8px', background:'transparent', border:'none', color:'#fff', fontSize:15, outline:'none', fontFamily:theme.mono }}/>
          <button onClick={handleSearch} disabled={searching}
            style={{ padding:'14px 28px', borderRadius:theme.radiusMd, background:searching?'#333':theme.gradientPrimary, color:searching?'#666':'#000', border:'none', cursor:searching?'not-allowed':'pointer', fontWeight:700, fontSize:14, display:'flex', alignItems:'center', gap:8 }}>
            {searching ? <><span style={{ width:14,height:14,border:'2px solid #666',borderTopColor:'transparent',borderRadius:'50%',display:'inline-block',animation:'spin 0.8s linear infinite'}}/> Aranıyor</> : <><Search size={14}/> Sorgula</>}
          </button>
        </div>
        <AnimatePresence>
          {showDropdown && searchResults.length>0 && (
            <motion.div initial={{opacity:0,y:-8}} animate={{opacity:1,y:0}} exit={{opacity:0,y:-8}}
              style={{ position:'absolute', top:'calc(100% + 8px)', left:0, right:0, background:theme.surface, border:`1px solid ${theme.border}`, borderRadius:theme.radiusMd, maxHeight:280, overflowY:'auto', zIndex:100, boxShadow:'0 20px 40px rgba(0,0,0,0.5)' }}>
              {searchResults.slice(0,10).map((item,i)=>(
                <div key={i} onClick={()=>{setSearchQuery(item.value||item.ioc_value||item.ioc||'');setShowDropdown(false);handleSearch()}}
                  style={{ padding:'12px 16px', borderBottom:`1px solid ${theme.border}`, cursor:'pointer', transition:'background 0.15s' }}
                  onMouseEnter={e=>e.currentTarget.style.background=theme.surface2}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:8 }}>
                    <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:12, wordBreak:'break-all', flex:1 }}>{item.value||item.ioc_value||item.ioc||'-'}</span>
                    <span style={{ fontSize:10, padding:'2px 8px', borderRadius:10, background:`${THREAT_META[item.ioc_type?.toUpperCase()]?.color||theme.primary}20`, color:THREAT_META[item.ioc_type?.toUpperCase()]?.color||theme.primary, whiteSpace:'nowrap' }}>{item.ioc_type||item.type||'-'}</span>
                  </div>
                  <div style={{ display:'flex', gap:12, fontSize:11, color:theme.textMuted, marginTop:4 }}>
                    <span style={{ display:'flex', alignItems:'center', gap:4 }}><Shield size={10}/> Risk: <b style={{ color:(item.risk_score||0)>75?'#ef4444':(item.risk_score||0)>40?theme.warning:theme.success }}>{item.risk_score}</b></span>
                    <span style={{ display:'flex', alignItems:'center', gap:4 }}><Database size={10}/> {item.source}</span>
                  </div>
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* STIX Export Button */}
      <div style={{ display:'flex', justifyContent:'center', gap:12, marginTop:20 }}>
        <button onClick={()=>exportSTIX(0)} disabled={exportingSTIX}
          style={{ padding:'10px 20px', borderRadius:theme.radiusSm, background:exportingSTIX?'#333':theme.surface, border:`1px solid ${theme.border}`, color:theme.text, cursor:exportingSTIX?'not-allowed':'pointer', fontSize:13, fontWeight:600, display:'flex', alignItems:'center', gap:8 }}>
          <Download size={14}/>
          {exportingSTIX ? 'İndiriliyor...' : 'STIX 2.1 İndir'}
        </button>
        <button onClick={()=>exportSTIX(50)} disabled={exportingSTIX}
          style={{ padding:'10px 20px', borderRadius:theme.radiusSm, background:exportingSTIX?'#333':'rgba(239,68,68,0.1)', border:`1px solid rgba(239,68,68,0.3)`, color:'#ef4444', cursor:exportingSTIX?'not-allowed':'pointer', fontSize:13, fontWeight:600, display:'flex', alignItems:'center', gap:8 }}>
          <ShieldAlert size={14}/>
          {exportingSTIX ? 'İndiriliyor...' : 'Yüksek Risk (50+)'}
        </button>
      </div>
    </div>

    {/* ── Yüksek risk uyarısı ── */}
    {parseFloat(highRiskPct) > 90 && (
      <div style={{ display:'flex', alignItems:'center', gap:12, padding:'12px 20px', background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.25)', borderRadius:theme.radiusMd, marginBottom:24 }}>
        <AlertTriangle size={18} color='#ef4444'/>
        <p style={{ fontSize:13, color:'#ef4444', fontWeight:600, margin:0 }}>Veritabanındaki IOC'ların <b>%{highRiskPct}'i yüksek risk</b> seviyesindedir. Bu tehditler aktif saldırı altyapılarıyla ilişkilidir.</p>
      </div>
    )}

    {/* ── İkili grid: Risk dağılımı + Tehdit tipi dağılımı ── */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:20, marginBottom:20 }}>
      {/* Risk dağılımı */}
      <Card>
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:20 }}>
          <BarChart3 size={16} color={theme.primary}/>
          <h3 style={{ fontSize:14, fontWeight:700, color:'#fff', margin:0 }}>Risk Dağılımı</h3>
        </div>
        {riskDist.length>0 ? (
          <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
            {riskDist.map((item,i)=>{
              const rColors=['#22c55e','#84cc16','#f59e0b','#ff6b35','#ef4444']
              const c = rColors[i]||theme.primary
              return (
                <div key={i}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                    <span style={{ fontSize:12, color:theme.text, display:'flex', alignItems:'center', gap:6 }}>
                      <span style={{ width:8,height:8,borderRadius:'50%',background:c,display:'inline-block',flexShrink:0 }}/>
                      {item.range}
                    </span>
                    <span style={{ fontSize:12, fontWeight:700, color:c }}>{(item.percentage||0).toFixed(1)}%</span>
                  </div>
                  <div style={{ height:8, background:theme.bg, borderRadius:4, overflow:'hidden' }}>
                    <motion.div initial={{width:0}} animate={{width:`${Math.min(item.percentage||0,100)}%`}} transition={{delay:0.3+i*0.1,duration:0.8,ease:theme.ease.out}}
                      style={{ height:'100%', background:c, borderRadius:4 }}/>
                  </div>
                </div>
              )
            })}
          </div>
        ) : <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>}
      </Card>

      {/* Tehdit Tipi Dağılımı — CSS donut + liste */}
      <Card>
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:20 }}>
          <Zap size={16} color='#ef4444'/>
          <h3 style={{ fontSize:14, fontWeight:700, color:'#fff', margin:0 }}>Tehdit Tipi Dağılımı</h3>
        </div>
        {topThreats.length>0 ? (() => {
          const total = topThreats.reduce((s,t)=>s+(t.count||0),0)||1
          const top5 = topThreats.slice(0,5)
          // CSS conic-gradient donut
          let deg = 0
          const segments = top5.map((t)=>{
            const typeName=(t.type||t.threat_type||t.name||'').toUpperCase()
            const meta=THREAT_META[typeName]||{color:theme.primary}
            const pct=((t.count||0)/total)*100
            const from=deg; deg+=pct*3.6
            return {typeName,meta,pct,from,to:deg,count:t.count||0}
          })
          const conicStr = segments.map(s=>`${s.meta.color} ${s.from}deg ${s.to}deg`).join(', ')
          return (
            <div style={{ display:'flex', gap:24, alignItems:'center' }}>
              {/* Donut */}
              <div style={{ position:'relative', flexShrink:0 }}>
                <div style={{ width:140, height:140, borderRadius:'50%', background:`conic-gradient(${conicStr}, ${theme.border} ${deg}deg 360deg)`, position:'relative' }}/>
                <div style={{ position:'absolute', inset:28, borderRadius:'50%', background:theme.surface, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
                  <span style={{ fontSize:18, fontWeight:800, color:'#fff' }}>{top5.length}</span>
                  <span style={{ fontSize:9, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'0.5px' }}>Tür</span>
                </div>
              </div>
              {/* Legend */}
              <div style={{ flex:1, display:'flex', flexDirection:'column', gap:8 }}>
                {segments.map((s)=>(
                  <div key={s.typeName} style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <div style={{ width:10,height:10,borderRadius:3,background:s.meta.color,flexShrink:0 }}/>
                    <span style={{ fontSize:12, color:theme.text, flex:1 }}>{s.typeName}</span>
                    <span style={{ fontSize:11, fontWeight:700, color:s.meta.color }}>{s.pct.toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )
        })() : <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>}
      </Card>
    </div>

    {/* ── En Yüksek Riskli Aktif IOC'lar ── */}
    <Card style={{ marginBottom:20 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:18 }}>
        <AlertTriangle size={16} color='#ef4444'/>
        <h3 style={{ fontSize:14, fontWeight:700, color:'#fff', margin:0 }}>En Yüksek Riskli Aktif Tehditler</h3>
        <span style={{ fontSize:11, color:theme.textMuted, marginLeft:'auto' }}>Anlık güncelleniyor</span>
      </div>
      {(() => {
        const hotIocs = [...iocList].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,6)
        if (!hotIocs.length) return <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>
        return (
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
            {hotIocs.map((item,i)=>{
              const rs=item.risk_score||0
              const typeName=(item.type||item.ioc_type||'').toUpperCase()
              const meta=THREAT_META[typeName]||{color:'#ef4444',icon:AlertTriangle}
              const Icon=meta.icon
              const val=item.value||item.ioc_value||item.ioc||item.indicator||'-'
              return (
                <motion.div key={i} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{delay:i*0.06}}
                  style={{ padding:'14px 16px', background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${meta.color}33`, position:'relative', overflow:'hidden' }}>
                  <div style={{ position:'absolute', top:0, left:0, width:3, bottom:0, background:meta.color }}/>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ width:22,height:22,borderRadius:6,background:`${meta.color}18`,border:`1px solid ${meta.color}33`,display:'flex',alignItems:'center',justifyContent:'center' }}>
                        <Icon size={12} color={meta.color}/>
                      </div>
                      <span style={{ fontSize:10, fontWeight:700, color:meta.color }}>{typeName||'IOC'}</span>
                    </div>
                    <span style={{ fontSize:13, fontWeight:800, color:'#ef4444' }}>{rs}</span>
                  </div>
                  <div style={{ display:'flex', alignItems:'center', gap:4 }}>
                    <span style={{ fontSize:11, color:theme.primary, fontFamily:theme.mono, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{val}</span>
                    <CopyBtn value={val}/>
                  </div>
                  <p style={{ fontSize:10, color:theme.textMuted, margin:'6px 0 0' }}>{item.source||'-'}</p>
                </motion.div>
              )
            })}
          </div>
        )
      })()}
    </Card>

    {/* ── En çok görülen tehditler (tam liste) ── */}
    <Card style={{ marginBottom:20 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:18 }}>
        <Activity size={16} color={theme.primary}/>
        <h3 style={{ fontSize:14, fontWeight:700, color:'#fff', margin:0 }}>Tehdit Kategorisi Analizi</h3>
      </div>
      {topThreats.length>0 ? topThreats.slice(0,10).map((t,i)=>{
        const typeName=(t.type||t.threat_type||t.name||'').toUpperCase()
        const meta=THREAT_META[typeName]||{color:theme.primary,icon:Shield}
        const Icon=meta.icon
        const barW=((t.count||0)/maxThreat)*100
        return (
          <motion.div key={i} initial={{opacity:0,x:10}} animate={{opacity:1,x:0}} transition={{delay:0.05*i}}
            style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
            <span style={{ fontSize:11, color:theme.textMuted, width:16, textAlign:'right', flexShrink:0 }}>{i+1}</span>
            <div style={{ width:22,height:22,borderRadius:6,background:`${meta.color}18`,border:`1px solid ${meta.color}33`,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0 }}>
              <Icon size={12} color={meta.color}/>
            </div>
            <div style={{ flex:1 }}>
              <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                <span style={{ fontSize:11, fontWeight:700, color:meta.color }}>{typeName}</span>
                <span style={{ fontSize:11, fontWeight:700, color:'#fff' }}>{(t.count||0).toLocaleString('tr-TR')}</span>
              </div>
              <div style={{ height:4, background:theme.bg, borderRadius:2, overflow:'hidden' }}>
                <motion.div initial={{width:0}} animate={{width:`${barW}%`}} transition={{delay:0.1+i*0.04,duration:0.6}}
                  style={{ height:'100%', background:meta.color, borderRadius:2 }}/>
              </div>
            </div>
          </motion.div>
        )
      }) : <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>}
    </Card>

    {/* ── IOC Tablosu ── */}
    <Card style={{ marginBottom:20 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:18 }}>
        <Eye size={16} color={theme.primary}/>
        <h3 style={{ fontSize:14, fontWeight:700, color:'#fff', margin:0 }}>Tüm IOC'lar</h3>
        <span style={{ fontSize:11, color:theme.textMuted, marginLeft:'auto' }}>{iocList.length} kayıt</span>
      </div>
      <div style={{ overflowX:'auto', maxHeight:480, overflowY:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}>
            <tr style={{ color:theme.textMuted, fontSize:10, textTransform:'uppercase', letterSpacing:'1px', borderBottom:`2px solid ${theme.border}` }}>
              <th style={{ width:4, padding:0 }}/>
              <th style={{ textAlign:'left', padding:'11px 12px' }}>Gösterge</th>
              <th style={{ textAlign:'center', padding:'11px 8px' }}>Tür</th>
              <th style={{ textAlign:'center', padding:'11px 8px' }}>Risk</th>
              <th style={{ textAlign:'center', padding:'11px 8px' }}>Kaynak</th>
              <th style={{ textAlign:'right', padding:'11px 12px' }}>Tarih</th>
            </tr>
          </thead>
          <tbody>
            {iocList.length===0 && <tr><td colSpan={6} style={{ textAlign:'center', padding:40, color:theme.textMuted }}>Yükleniyor...</td></tr>}
            {iocList.map((item,i)=>{
              const rs = item.risk_score||0
              const sColor = rs>75?'#ef4444':rs>40?theme.warning:theme.success
              const typeName = (item.type||item.ioc_type||'').toUpperCase()
              const meta = THREAT_META[typeName]||{color:theme.primary}
              const val = item.value||item.ioc_value||item.ioc||item.indicator||'-'
              return (
                <tr key={item.id||i} style={{ borderBottom:`1px solid ${theme.border}` }}
                  onMouseEnter={e=>e.currentTarget.style.background=theme.surface2}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <td style={{ width:3, padding:0, background:sColor }}/>
                  <td style={{ padding:'9px 12px' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11, wordBreak:'break-all' }}>{val}</span>
                      <CopyBtn value={val}/>
                    </div>
                  </td>
                  <td style={{ padding:'9px 8px', textAlign:'center' }}>
                    <span style={{ display:'inline-flex', alignItems:'center', gap:4, padding:'3px 8px', borderRadius:8, background:`${meta.color||theme.primary}18`, color:meta.color||theme.primary, fontSize:10, fontWeight:700 }}>
                      <ThreatIcon type={typeName} size={10}/> {item.type||item.ioc_type||'-'}
                    </span>
                  </td>
                  <td style={{ padding:'9px 8px', textAlign:'center' }}>
                    <span style={{ display:'inline-flex', alignItems:'center', gap:3, padding:'3px 8px', borderRadius:8, background:`${sColor}18`, color:sColor, fontSize:10, fontWeight:800 }}>
                      <Shield size={9}/> {rs||'-'}
                    </span>
                  </td>
                  <td style={{ padding:'9px 8px', textAlign:'center', color:theme.textMuted, fontSize:11 }}>{item.source||'-'}</td>
                  <td style={{ padding:'9px 12px', textAlign:'right', color:theme.textMuted, fontSize:10 }}>{item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):item.date?new Date(item.date).toLocaleDateString('tr-TR'):'-'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>

    {/* ── Proje açıklama kartı (yarışma için) ── */}
    <div style={{ padding:24, background:theme.surface, border:`1px solid ${theme.border}`, borderRadius:theme.radiusMd, display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:20 }}>
      {[
        { icon:Shield, color:theme.primary, title:'IOC Nedir?', desc:'Indicator of Compromise — bir sistemin tehlikeye girdiğine işaret eden zararlı IP, domain, URL veya dosya hash değerleridir.' },
        { icon:Hash, color:theme.warning, title:'Nasıl Kullanılır?', desc:'Bir IP veya domain şüpheli geliyorsa arama kutusuna girerek veritabanımızda tehdit kaydı olup olmadığını anlık sorgulayabilirsiniz.' },
        { icon:Lock, color:theme.success, title:'Neden Önemli?', desc:'AegisNexus, açık tehdit istihbaratı kaynaklarını birleştirerek kişisel ve kurumsal kullanıcıları siber saldırılara karşı önceden uyarır.' },
      ].map(({icon, color, title, desc})=>{
        const SectionIcon = icon
        return (
        <div key={title} style={{ display:'flex', gap:14 }}>
          <div style={{ width:36,height:36,borderRadius:10,background:`${color}18`,border:`1px solid ${color}33`,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0 }}>
            <SectionIcon size={18} color={color}/>
          </div>
          <div>
            <p style={{ fontSize:13, fontWeight:700, color:'#fff', marginBottom:4 }}>{title}</p>
            <p style={{ fontSize:12, color:theme.textMuted, lineHeight:1.6, margin:0 }}>{desc}</p>
          </div>
        </div>
        )
      })}
    </div>
  </div>
}

/* ===============================================
   BREACH INTELLIGENCE
   =============================================== */
function InlineRiskPanel({ riskResult, riskLoading }) {
  if (riskLoading) return (
    <div style={{ maxWidth:900, margin:'0 auto 24px' }}>
      <Card style={{ padding:28, display:'flex', alignItems:'center', gap:16 }}>
        <Spinner size={20} />
        <p style={{ fontSize:14, color:theme.textMuted }}>Birleşik risk skoru hesaplanıyor...</p>
      </Card>
    </div>
  )
  if (!riskResult) return null

  const s = riskResult.composite_score || 0
  function rColor(v) {
    if (v >= 80) return '#ef4444'
    if (v >= 60) return '#f97316'
    if (v >= 35) return '#eab308'
    return '#22c55e'
  }
  const color = rColor(s)
  const R = 52; const circ = 2 * Math.PI * R
  const dash = circ * (1 - s / 100)
  const modIcons = { breach_intel:'Sızıntı', phishing_detector:'Phishing', victim_atlas:'Atlas', honeypot:'IOC' }

  return (
    <div style={{ maxWidth:900, margin:'0 auto 24px' }}>
      <Card style={{ padding:28, background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`, border:`1px solid ${color}33` }}>
        {/* Header */}
        <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:20 }}>
          <Shield size={22} color={theme.primary} />
          <div>
            <p style={{ fontSize:16, fontWeight:800, color:'#fff' }}>Birleşik Dijital Risk Paneli</p>
            <p style={{ fontSize:12, color:theme.textMuted }}>Tüm modüllerden gelen ağırlıklı kompozit skor</p>
          </div>
        </div>

        <div style={{ display:'grid', gridTemplateColumns:'auto 1fr', gap:24, alignItems:'start' }}>
          {/* Gauge */}
          <div style={{ display:'flex', flexDirection:'column', alignItems:'center', gap:8 }}>
            <svg width={120} height={120} viewBox="0 0 120 120">
              <circle cx={60} cy={60} r={R} fill="none" stroke={theme.border} strokeWidth={8}/>
              <circle cx={60} cy={60} r={R} fill="none" stroke={color} strokeWidth={8}
                strokeDasharray={circ} strokeDashoffset={dash}
                strokeLinecap="round"
                transform="rotate(-90 60 60)"
                style={{ transition:'stroke-dashoffset 0.8s ease' }}
              />
              <text x={60} y={55} textAnchor="middle" fill="#fff" fontSize={22} fontWeight={800} fontFamily="monospace">{s}</text>
              <text x={60} y={74} textAnchor="middle" fill={theme.textMuted} fontSize={11}>/100</text>
            </svg>
            <span style={{ padding:'4px 14px', borderRadius:'20px', background:`${color}22`, border:`1px solid ${color}55`, color, fontSize:13, fontWeight:800, letterSpacing:'1px' }}>
              {riskResult.risk_label}
            </span>
          </div>

          {/* Right: module bars + recommendations */}
          <div>
            {/* Module bars */}
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(260px,1fr))', gap:8, marginBottom:16 }}>
              {(riskResult.modules || []).map((m, i) => (
                <div key={i} style={{ padding:'10px 14px', background:theme.bg, borderRadius:theme.radiusSm }}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:5 }}>
                    <span style={{ fontSize:12, color:theme.textMuted }}>{modIcons[m.module]} {m.label}</span>
                    <span style={{ fontSize:12, fontWeight:700, color: rColor(m.score), fontFamily:theme.mono }}>{m.score}<span style={{ fontSize:10, color:theme.textSubtle }}>/{m.weight_pct}%</span></span>
                  </div>
                  <div style={{ height:5, borderRadius:3, background:theme.border, overflow:'hidden' }}>
                    <div style={{ width:`${m.score}%`, height:'100%', borderRadius:3, background: rColor(m.score), transition:'width 0.8s ease' }} />
                  </div>
                </div>
              ))}
            </div>

            {/* Summary */}
            {riskResult.summary && (
              <p style={{ fontSize:13, color:theme.textMuted, lineHeight:1.6, marginBottom:12, padding:'10px 14px', background:theme.bg, borderRadius:theme.radiusSm }}>
                {riskResult.summary}
              </p>
            )}

            {/* Recommendations */}
            {(riskResult.recommendations || []).length > 0 && (
              <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
                {riskResult.recommendations.map((r, i) => (
                  <p key={i} style={{ fontSize:12, color:theme.text, padding:'8px 12px', background:`${color}11`, borderRadius:theme.radiusSm, borderLeft:`3px solid ${color}` }}>{r}</p>
                ))}
              </div>
            )}
          </div>
        </div>
      </Card>
    </div>
  )
}

function UnifiedBreachResult({ breach, risk, riskLoading, email }) {
  const hasBreachData = breach && breach.status !== 'error'
  const breached = hasBreachData && breach.breached

  const cardStyle = (color) => ({
    padding: '20px',
    borderRadius: 18,
    background: 'linear-gradient(180deg, #0e1320 0%, #0a0f1a 100%)',
    border: `1px solid ${color}33`,
    boxShadow: `0 8px 24px rgba(0,0,0,0.4), 0 0 0 1px ${color}11 inset`,
    transition: 'border-color 220ms ease, box-shadow 220ms ease',
  })

  const cardHover = (color) => ({
    enter: (e) => {
      e.currentTarget.style.borderColor = `${color}88`
      e.currentTarget.style.boxShadow = `0 12px 32px rgba(0,0,0,0.5), 0 0 20px ${color}22`
    },
    leave: (e) => {
      e.currentTarget.style.borderColor = `${color}33`
      e.currentTarget.style.boxShadow = `0 8px 24px rgba(0,0,0,0.4), 0 0 0 1px ${color}11 inset`
    },
  })

  function SLabel({ children }) {
    return <p style={{ fontSize: 11, fontWeight: 700, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '1.4px', marginBottom: 14 }}>{children}</p>
  }

  return (
    <div style={{ maxWidth: 900, margin: '0 auto 24px', animation: 'fadeInUp 0.35s ease' }}>

      {/* ── STATUS BAR ── */}
      {hasBreachData && (
        <div style={{
          marginBottom: 16,
          padding: '14px 20px',
          borderRadius: 14,
          background: breached ? 'rgba(239,68,68,0.05)' : 'rgba(34,197,94,0.05)',
          border: `1px solid ${breached ? '#ef444430' : '#22c55e30'}`,
          display: 'flex',
          alignItems: 'center',
          gap: 12,
        }}>
          {breached
            ? <ShieldAlert size={18} color="#ef4444" strokeWidth={2} />
            : <Shield size={18} color={theme.success} strokeWidth={2} />
          }
          <span style={{ fontSize: 14, fontWeight: 700, color: '#fff', flex: 1 }}>
            {breached ? `${breach.breach_count} veri sızıntısı tespit edildi` : 'Kayıtlı sızıntı bulunamadı'}
          </span>
          {breach?.domain_risk && (
            <span style={{
              padding: '3px 10px', borderRadius: 20, fontSize: 11, fontWeight: 700,
              background: breach.domain_risk.is_suspicious ? 'rgba(239,68,68,0.12)' : 'rgba(34,197,94,0.12)',
              color: breach.domain_risk.is_suspicious ? '#ef4444' : theme.success,
              border: `1px solid ${breach.domain_risk.is_suspicious ? '#ef444430' : '#22c55e30'}`,
            }}>
              {breach.domain_risk.domain} — {breach.domain_risk.is_suspicious ? `Risk ${breach.domain_risk.risk_score}/100` : 'Güvenli'}
            </span>
          )}
          <span style={{ fontSize: 11, color: theme.textSubtle, fontFamily: theme.mono }}>{email}</span>
        </div>
      )}

      {/* ── SECTION 1: BREACH LIST ── */}
      {breached && breach.breaches?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <SLabel>Veri İhlali Kaynakları — {breach.breaches.length} platform</SLabel>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {breach.breaches.map((b, i) => {
              const h = cardHover(theme.border)
              return (
                <div
                  key={i}
                  style={{
                    padding: '14px 18px',
                    borderRadius: 14,
                    background: 'linear-gradient(180deg, #0e1320 0%, #0a0f1a 100%)',
                    border: `1px solid ${theme.border}`,
                    boxShadow: '0 4px 16px rgba(0,0,0,0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 14,
                    transition: 'border-color 220ms ease, box-shadow 220ms ease',
                  }}
                  onMouseEnter={e => {
                    e.currentTarget.style.borderColor = `${theme.primary}55`
                    e.currentTarget.style.boxShadow = `0 8px 24px rgba(0,0,0,0.4), 0 0 16px rgba(0,212,255,0.07)`
                  }}
                  onMouseLeave={e => {
                    e.currentTarget.style.borderColor = theme.border
                    e.currentTarget.style.boxShadow = '0 4px 16px rgba(0,0,0,0.3)'
                  }}
                >
                  {/* Favicon */}
                  <div style={{ width: 38, height: 38, borderRadius: 10, background: theme.surface2, border: `1px solid ${theme.border}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0, overflow: 'hidden', position: 'relative' }}>
                    {b.domain ? (
                      <>
                        <img
                          src={`https://www.google.com/s2/favicons?domain=${b.domain}&sz=64`}
                          alt=""
                          width={24} height={24}
                          style={{ position: 'absolute' }}
                          onError={e => { e.currentTarget.style.display = 'none' }}
                        />
                        <Lock size={14} color={theme.textSubtle} />
                      </>
                    ) : (
                      <Lock size={14} color={theme.textSubtle} />
                    )}
                  </div>

                  {/* Info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 5 }}>
                      <span style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>{b.title || b.name || 'Bilinmeyen Platform'}</span>
                      {b.domain && <span style={{ fontSize: 11, color: theme.textSubtle, fontFamily: theme.mono }}>{b.domain}</span>}
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(b.data_classes || []).slice(0, 6).map((dc, di) => (
                        <span key={di} style={{ padding: '2px 8px', borderRadius: 6, fontSize: 11, fontWeight: 600, background: 'rgba(0,212,255,0.07)', color: theme.primary, border: '1px solid rgba(0,212,255,0.14)' }}>{dc}</span>
                      ))}
                      {(b.data_classes || []).length > 6 && (
                        <span style={{ padding: '2px 8px', borderRadius: 6, fontSize: 11, color: theme.textSubtle }}>+{b.data_classes.length - 6}</span>
                      )}
                    </div>
                  </div>

                  {/* Date */}
                  {b.breach_date && (
                    <span style={{ fontSize: 11, color: theme.textSubtle, flexShrink: 0, fontFamily: theme.mono }}>
                      {new Date(b.breach_date).toLocaleDateString('tr-TR', { year: 'numeric', month: 'short' })}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── SECTION 2: MODULE CONTEXT ── */}
      {(risk || riskLoading) && (
        <div style={{ marginBottom: 16 }}>
          <SLabel>Tehdit İstihbaratı Bağlamı</SLabel>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
            {[
              {
                key: 'phishing_detector',
                color: theme.accent,
                icon: <Globe size={13} color={theme.accent} strokeWidth={2} />,
                label: 'Phishing Tehdidi',
                getValue: (mod) => ({ big: mod?.detail?.ioc_count ?? 0, unit: 'IOC', sub: mod?.detail?.domain || email.split('@')[1] || '—' }),
              },
              {
                key: 'victim_atlas',
                color: theme.violet,
                icon: <TrendingUp size={13} color={theme.violet} strokeWidth={2} />,
                label: 'Bölgesel Vakalar',
                getValue: (mod) => {
                  const top = mod?.detail?.top_attack_methods?.[0]
                  return { big: mod?.detail?.total_recent_cases ?? 0, unit: '/ 30 gün', sub: top ? `${top.attack_method_tr} — %${top.pct}` : 'Veri yok' }
                },
              },
              {
                key: 'honeypot',
                color: theme.success,
                icon: <Activity size={13} color={theme.success} strokeWidth={2} />,
                label: 'Aktif IOC',
                getValue: (mod) => ({ big: (mod?.detail?.iocs_last_24h ?? 0).toLocaleString('tr-TR'), unit: '/ 24 saat', sub: 'Canlı tehdit akışı' }),
              },
            ].map(({ key, color, icon, label, getValue }) => {
              const mod = risk?.modules?.find(m => m.module === key)
              const { big, unit, sub } = riskLoading && !mod ? { big: '—', unit: '', sub: '…' } : getValue(mod)
              const h = cardHover(color)
              return (
                <div key={key} style={cardStyle(color)} onMouseEnter={h.enter} onMouseLeave={h.leave}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 14 }}>
                    {icon}
                    <span style={{ fontSize: 10, fontWeight: 700, color, textTransform: 'uppercase', letterSpacing: '1.4px' }}>{label}</span>
                  </div>
                  <p style={{ fontSize: 28, fontWeight: 800, color: '#fff', lineHeight: 1, marginBottom: 6 }}>
                    {big}
                    <span style={{ fontSize: 12, fontWeight: 400, color: theme.textMuted, marginLeft: 6 }}>{unit}</span>
                  </p>
                  <p style={{ fontSize: 11, color: theme.textSubtle, lineHeight: 1.4 }}>{sub}</p>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── SECTION 3: KVKK ── */}
      {breached && (
        <KVKKPDFButton email={email} breachCount={breach?.breaches?.length || 0} />
      )}

      {/* ── CLEAN STATE ── */}
      {hasBreachData && !breached && (
        <div style={{
          padding: '40px 32px', borderRadius: 20, textAlign: 'center',
          background: 'linear-gradient(180deg, #0e1320 0%, #0a0f1a 100%)',
          border: `1px solid ${theme.success}33`,
        }}>
          <div style={{ width: 52, height: 52, borderRadius: 14, background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.25)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 14px' }}>
            <Shield size={26} color={theme.success} strokeWidth={1.5} />
          </div>
          <p style={{ fontSize: 17, fontWeight: 800, color: theme.success, letterSpacing: '-0.5px', marginBottom: 6 }}>Sızıntı Bulunamadı</p>
          <p style={{ fontSize: 13, color: theme.textMuted }}>{email} adresi bilinen veri ihlallerinde yer almıyor.</p>
        </div>
      )}
    </div>
  )
}

function KVKKPDFButton({ email, breachCount = 0 }) {
  const [loading, setLoading] = useState(false)
  const [done, setDone] = useState(false)
  const [error, setError] = useState(null)

  async function handleDownload() {
    setLoading(true); setError(null)
    try {
      const res = await fetch(`${API}/breach/generate-kvkk-pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      })
      const data = await res.json()
      if (!data.pdf_base64) throw new Error('PDF alınamadı')
      const byteChars = atob(data.pdf_base64)
      const bytes = new Uint8Array(byteChars.length)
      for (let i = 0; i < byteChars.length; i++) bytes[i] = byteChars.charCodeAt(i)
      const blob = new Blob([bytes], { type: data.method === 'reportlab' ? 'application/pdf' : 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a'); a.href = url; a.download = data.filename; a.click()
      URL.revokeObjectURL(url)
      setDone(true); setTimeout(() => setDone(false), 5000)
    } catch (e) {
      setError(e.message)
    } finally { setLoading(false) }
  }

  return (
    <motion.div
      initial={{ opacity:0, y:8 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.4 }}
      style={{
        background: done ? 'rgba(34,197,94,0.07)' : 'rgba(0,212,255,0.05)',
        border: `1.5px solid ${done ? theme.success+'55' : theme.primary+'33'}`,
        borderRadius: theme.radius.md,
        padding: '14px 20px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 16,
        marginTop: 16,
      }}
    >
      <div style={{ display:'flex', alignItems:'center', gap:12 }}>
        <div style={{ width:40, height:40, borderRadius:10, background: done ? 'rgba(34,197,94,0.15)' : theme.primaryDim, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
          <span style={{ fontSize:20 }}>{done ? '✅' : '📄'}</span>
        </div>
        <div>
          <p style={{ fontSize:13, fontWeight:700, color:theme.text, margin:0 }}>KVKK 6698 — Resmi Başvuru Belgesi</p>
          <p style={{ fontSize:11, color:theme.textMuted, marginTop:3, margin:0 }}>
            {breachCount > 0 ? `${breachCount} ihlal dahil • ` : ''}PDF veya metin formatında indir
          </p>
          {error && <p style={{ fontSize:11, color:theme.danger, marginTop:3 }}>⚠️ {error}</p>}
        </div>
      </div>
      <motion.button
        onClick={handleDownload}
        disabled={loading || done}
        whileHover={!loading && !done ? { scale:1.04 } : undefined}
        whileTap={!loading && !done ? { scale:0.96 } : undefined}
        style={{
          padding:'9px 18px',
          borderRadius: theme.radius.sm,
          border: 'none',
          background: done ? 'rgba(34,197,94,0.2)' : 'linear-gradient(135deg, #00d4ff, #0099cc)',
          color: done ? theme.success : '#000',
          fontSize:13, fontWeight:800,
          cursor: loading || done ? 'not-allowed' : 'pointer',
          display:'flex', alignItems:'center', gap:7,
          whiteSpace:'nowrap',
          opacity: loading ? 0.7 : 1,
          boxShadow: done || loading ? 'none' : '0 4px 14px rgba(0,212,255,0.3)'
        }}
      >
        {loading ? <Spinner size={12} /> : <Download size={13} />}
        {loading ? 'Oluşturuluyor...' : done ? 'İndirildi!' : 'PDF İndir'}
      </motion.button>
    </motion.div>
  )
}

function BreachIntelMaintenance() {
  return (
    <section style={{ maxWidth:720, margin:'40px auto', padding:'48px 32px', textAlign:'center', background:theme.surface, border:`1px solid ${theme.border}`, borderRadius:16 }}>
      <div style={{ width:64, height:64, margin:'0 auto 20px', display:'grid', placeItems:'center', borderRadius:'50%', background:'rgba(245,158,11,0.12)', border:'1px solid rgba(245,158,11,0.3)' }}>
        <AlertTriangle size={28} color='#f59e0b' />
      </div>
      <h2 style={{ fontSize:24, fontWeight:800, color:'#fff', marginBottom:10, letterSpacing:'-0.5px' }}>Sızıntı Modülü Bakımda</h2>
      <p style={{ fontSize:14, color:theme.textMuted, lineHeight:1.7, maxWidth:520, margin:'0 auto 24px' }}>
        Bu modül dış API bağımlılıkları (HaveIBeenPwned vb.) nedeniyle geçici olarak bakıma alınmıştır.
        Diğer modüller (Phishing, IOC, Şifre Kalkanı, Atlas) çalışmaktadır.
      </p>
      <span style={{ display:'inline-block', padding:'6px 14px', background:'rgba(245,158,11,0.1)', border:'1px solid rgba(245,158,11,0.25)', borderRadius:999, fontSize:11, fontWeight:700, color:'#f59e0b', letterSpacing:'1.5px', textTransform:'uppercase' }}>Yakında geri dönecek</span>
    </section>
  )
}

function BreachIntel() {
  const [email, setEmail] = useState('')
  const [region, setRegion] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [riskResult, setRiskResult] = useState(null)
  const [riskLoading, setRiskLoading] = useState(false)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  async function fetchRisk(addr, reg) {
    setRiskLoading(true); setRiskResult(null)
    try {
      const r = await fetch(`${API}/risk-dashboard/aggregate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: addr, region: reg||undefined }),
      })
      const d = await r.json()
      if (r.ok) setRiskResult(d)
    } catch(_) {}
    setRiskLoading(false)
  }

  async function handleCheck() {
    if(!email||!email.includes('@')){showToast('Geçerli bir e-posta adresi girin','error');return}
    setChecking(true); setResult(null); setRiskResult(null)
    fetchRisk(email, region)
    try{
      const r=await fetch(`${API}/breach/check-email`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})})
      if(!r.ok){const e=await r.json();throw new Error(e.message||e.detail||'Sorgu hatası')}
      const d=await r.json();setResult(d)
    }catch(e){showToast('Sorgu hatası: '+e.message,'error')}
    setChecking(false)
  }

  function showToast(msg,t='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(t=>({...t,visible:false})),3000)}

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>
    <div style={{ textAlign:'center', marginBottom:48 }}>
      <span style={{ display:'inline-block', padding:'8px 20px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'24px', fontSize:12, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'2px', marginBottom:20 }}>Sızıntı İstihbaratı</span>
      <h1 style={{ fontSize:48, fontWeight:800, color:'#fff', marginBottom:16, letterSpacing:'-1px', background:'linear-gradient(135deg, #fff 0%, #00d4ff 100%)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>Veri İhlali & Dark Web Taraması</h1>
      <p style={{ color:theme.textMuted, fontSize:18, maxWidth:700, margin:'0 auto', lineHeight:1.7 }}>E-posta adresinizin sızdırılıp sızdırılmadığını kontrol edin. HIBP, dark web ve sızıntı veritabanlarında anlık tarama yapın.</p>
    </div>

    {/* Main Check Section - Full Width */}
    <div style={{ maxWidth:900, margin:'0 auto 48px' }}>
      <Card style={{ padding:40, background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`, border:`2px solid ${theme.primary}22` }}>
        <div style={{ display:'flex', alignItems:'center', gap:16, marginBottom:24 }}>
          <div style={{ width:64, height:64, borderRadius:'16px', background:theme.primaryDim, display:'flex', alignItems:'center', justifyContent:'center' }}>
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke={theme.primary} strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              <path d="M12 8v4"/><path d="M12 16h.01"/>
            </svg>
          </div>
          <div>
            <h2 style={{ fontSize:24, fontWeight:700, color:'#fff', marginBottom:4 }}>E-posta Sızıntı Kontrolü</h2>
            <p style={{ color:theme.textMuted, fontSize:14 }}>HIBP API ile gerçek zamanlı sızıntı taraması</p>
          </div>
        </div>
        
        <div style={{ display:'flex', gap:12, marginBottom:12 }}>
          <input 
            value={email} 
            onChange={e=>setEmail(e.target.value)} 
            placeholder="ornek@email.com" 
            style={{ 
              flex:1, 
              padding:'18px 24px', 
              borderRadius:theme.radius, 
              background:theme.bg, 
              border:`2px solid ${theme.border}`, 
              color:'#fff', 
              fontSize:16, 
              outline:'none',
              transition:'all 0.3s ease',
              fontFamily:theme.mono
            }} 
            onKeyDown={e=>e.key==='Enter'&&handleCheck()}
            onFocus={e=>e.currentTarget.style.borderColor=theme.primary}
            onBlur={e=>e.currentTarget.style.borderColor=theme.border}
          />
        </div>
        <div style={{ display:'flex', gap:12, marginBottom:16 }}>
          <input
            value={region}
            onChange={e=>setRegion(e.target.value)}
            placeholder="Şehir / Bölge (opsiyonel — örn: İstanbul)"
            style={{
              flex:1,
              padding:'14px 24px',
              borderRadius:theme.radius,
              background:theme.bg,
              border:`1px solid ${theme.border}`,
              color:'#fff',
              fontSize:14,
              outline:'none',
              transition:'all 0.3s ease',
            }}
            onFocus={e=>e.currentTarget.style.borderColor=theme.primary}
            onBlur={e=>e.currentTarget.style.borderColor=theme.border}
          />
          <button 
            onClick={handleCheck} 
            disabled={!email||!email.includes('@')||checking}
            style={{
              padding:'14px 40px',
              borderRadius:theme.radius,
              cursor:checking?'not-allowed':'pointer',
              fontSize:16,
              fontWeight:700,
              background:checking?'#444':'linear-gradient(135deg, #00d4ff, #0099cc)',
              color:'#000',
              border:'none',
              transition:'all 0.3s ease',
              display:'inline-flex',
              alignItems:'center',
              gap:12,
              opacity:checking||!email||!email.includes('@')?0.5:1,
              boxShadow:checking?'none':'0 4px 20px rgba(0,212,255,0.3)'
            }}
          >
            {checking?<span style={{display:'inline-block',width:20,height:20,border:'2px solid rgba(0,0,0,0.3)',borderTop:'2px solid #000',borderRadius:'50%',animation:'spin 0.8s linear infinite'}}/>:'🔍'}
            {checking?'Taranıyor...':'Analiz Et'}
          </button>
        </div>
        {result&&result.status==='error'&&<div style={{ animation:'scaleIn 0.4s ease', marginTop:32 }}>
          <div style={{ textAlign:'center', padding:32, background:theme.bg, borderRadius:theme.radius, border:`1px solid ${theme.border}` }}>
            <span style={{ fontSize:64, display:'block', marginBottom:16 }}>⚠️</span>
            <p style={{ color:theme.warning, fontSize:18, fontWeight:700, marginBottom:8 }}>{result.message}</p>
            <p style={{ color:theme.textMuted, fontSize:14 }}>{result.hint}</p>
          </div>
        </div>}
      </Card>
    </div>

    {(result || riskResult || riskLoading) && (
      <UnifiedBreachResult
        breach={result}
        risk={riskResult}
        riskLoading={riskLoading}
        email={email}
        region={region}
      />
    )}

    {/* Post-Breach Intervention - Only section below */}
    <div style={{ maxWidth:900, margin:'0 auto 48px' }}>
      <Card style={{ padding:40, background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})` }}>
        <div style={{ display:'flex', alignItems:'center', gap:16, marginBottom:24 }}>
          <div style={{ width:64, height:64, borderRadius:'16px', background:theme.warning+'22', display:'flex', alignItems:'center', justifyContent:'center' }}>
            <IkAlert size={32} color={theme.warning}/>
          </div>
          <div>
            <h2 style={{ fontSize:24, fontWeight:700, color:'#fff', marginBottom:4 }}>Sızıntı Sonrası Müdahale</h2>
            <p style={{ color:theme.textMuted, fontSize:14 }}>Adım adım eylem planı</p>
          </div>
        </div>
        
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:16 }}>
          {[
            {step:'01',Icon:IkCheck2,title:'Panik Yapmayın',desc:'Sakin olun ve adım adım ilerleyin'},
            {step:'02',Icon:IkScope,title:'Şifrenizi Hemen Değiştirin',desc:'Sızdırılan platformdaki şifrenizi yenileyin'},
            {step:'03',Icon:IkArrow,title:'Tüm Platformları Güncelleyin',desc:'Aynı şifreyi kullandığınız yerleri değiştirin'},
            {step:'04',Icon:IkShieldDoc,title:'2FA Aktifleştirin',desc:'Tüm kritik hesaplarda 2FA açın'},
            {step:'05',Icon:IkSearch,title:'Hesap Aktivitesini Kontrol Edin',desc:'Şüpheli girişleri inceleyin'},
            {step:'06',Icon:IkRadar,title:'İzlemeye Devam Edin',desc:'Bu modül ile düzenli kontrol yapın'}
          ].map((item,i)=><div key={i} style={{ padding:20, background:theme.bg, borderRadius:theme.radius, border:`1px solid ${theme.border}`, transition:'all 0.3s ease' }} onMouseEnter={e=>e.currentTarget.style.borderColor=theme.warning} onMouseLeave={e=>e.currentTarget.style.borderColor=theme.border}>
            <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:12 }}>
              <div style={{ width:40, height:40, borderRadius:'12px', background:theme.warning+'22', display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
                <item.Icon size={20} color={theme.warning}/>
              </div>
              <span style={{ width:32, height:32, borderRadius:'50%', background:theme.warning+'22', color:theme.warning, display:'flex', alignItems:'center', justifyContent:'center', fontSize:13, fontWeight:700, flexShrink:0 }}>{item.step}</span>
            </div>
            <p style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:6 }}>{item.title}</p>
            <p style={{ fontSize:14, color:theme.textMuted, lineHeight:1.5 }}>{item.desc}</p>
          </div>)}
        </div>
      </Card>
    </div>
  </div>
}

/* ===============================================
   PASSWORD SHIELD (KRİPTOGRAFİK KALKAN)
   =============================================== */
function PasswordShield() {
  const [activeTab, setActiveTab] = useState('generate')
  const [genOpts, setGenOpts] = useState({ length: 20, uppercase: true, lowercase: true, digits: true, symbols: true })
  const [genLoading, setGenLoading] = useState(false)
  const [genResult, setGenResult] = useState(null)
  const [checkPwd, setCheckPwd] = useState('')
  const [checkLoading, setCheckLoading] = useState(false)
  const [checkResult, setCheckResult] = useState(null)
  const [copied, setCopied] = useState(null)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  function showToast(msg, t='success') { setToast({message:msg,type:t,visible:true}); setTimeout(()=>setToast(t=>({...t,visible:false})),3000) }

  async function handleGenerate() {
    setGenLoading(true); setGenResult(null)
    try {
      const res = await fetch(`${API}/shield/generate`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify(genOpts)
      })
      const d = await res.json(); setGenResult(d)
    } catch(e) { showToast('Üretim hatası: '+e.message,'error') }
    setGenLoading(false)
  }

  async function handleCheckFull() {
    if (!checkPwd) { showToast('Şifre girin','error'); return }
    setCheckLoading(true); setCheckResult(null)
    try {
      const res = await fetch(`${API}/shield/check-strength-full`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ password: checkPwd })
      })
      const d = await res.json(); setCheckResult(d)
    } catch(e) { showToast('Kontrol hatası: '+e.message,'error') }
    setCheckLoading(false)
  }

  function copyText(text, key) {
    navigator.clipboard.writeText(text).then(() => { setCopied(key); setTimeout(()=>setCopied(null),2000) })
  }

  function strengthColor(level='') {
    const l = level.toLowerCase()
    if (l.includes('weak') || l.includes('zayıf')) return '#ef4444'
    if (l.includes('moderate') || l.includes('orta')) return '#f59e0b'
    if (l.includes('strong') || l.includes('güçlü')) return '#22c55e'
    return theme.primary
  }

  return (
    <div style={{ paddingBottom:80 }}>
      <Toast {...toast} />
      <SectionHeader
        badge="04 · Kriptografik Kalkan"
        title="Şifre Kalkanı"
        subtitle="Güvenli şifre üret, güçlülük analizi yap ve HIBP sızıntı veritabanında kontrol et."
      />

      {/* Tabs */}
      <div style={{ maxWidth:800, margin:'0 auto 32px', display:'flex', gap:4, background:theme.surface, borderRadius:theme.radiusSm, padding:4 }}>
        {[{id:'generate',label:'Şifre Üret',Icon:IkBolt},{id:'check',label:'Analiz & Kontrol',Icon:IkSearch}].map(t=>(
          <button key={t.id} onClick={()=>{setActiveTab(t.id);setGenResult(null);setCheckResult(null)}}
            style={{ flex:1, padding:'10px 20px', borderRadius:'6px', border:'none', cursor:'pointer', fontSize:14, fontWeight:600, fontFamily:theme.navFont, background:activeTab===t.id?theme.primary:'transparent', color:activeTab===t.id?'#000':theme.textMuted, transition:'all 0.2s', display:'flex', alignItems:'center', justifyContent:'center', gap:7 }}>
            <t.Icon size={14} color={activeTab===t.id?'#000':theme.textMuted}/>{t.label}
          </button>
        ))}
      </div>

      {/* Generate Tab */}
      {activeTab === 'generate' && (
        <div style={{ maxWidth:800, margin:'0 auto' }}>
          <Card style={{ padding:32, marginBottom:24 }}>
            <p style={{ fontSize:14, fontWeight:700, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'1px', marginBottom:20 }}>Şifre Seçenekleri</p>
            <div style={{ display:'flex', alignItems:'center', gap:16, marginBottom:24 }}>
              <label style={{ fontSize:14, color:theme.text }}>Uzunluk:</label>
              <input type="range" min={8} max={64} value={genOpts.length} onChange={e=>setGenOpts(o=>({...o,length:+e.target.value}))}
                style={{ flex:1, accentColor:theme.primary }} />
              <span style={{ fontSize:18, fontWeight:800, color:theme.primary, fontFamily:theme.mono, minWidth:28 }}>{genOpts.length}</span>
            </div>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))', gap:12, marginBottom:24 }}>
              {[['uppercase','ABC','Büyük Harf'],['lowercase','abc','Küçük Harf'],['digits','123','Rakam'],['symbols','@#!','Sembol']].map(([key,ex,label])=>(
                <label key={key} style={{ display:'flex', alignItems:'center', gap:10, padding:'12px 16px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${genOpts[key]?theme.primary+'44':theme.border}`, cursor:'pointer', transition:'all 0.2s' }}>
                  <input type="checkbox" checked={genOpts[key]} onChange={e=>setGenOpts(o=>({...o,[key]:e.target.checked}))} style={{ accentColor:theme.primary }} />
                  <span style={{ fontFamily:theme.mono, color:theme.primary, fontSize:13 }}>{ex}</span>
                  <span style={{ fontSize:13, color:theme.text }}>{label}</span>
                </label>
              ))}
            </div>
            <GlowButton onClick={handleGenerate} loading={genLoading}>🎲 Şifre Üret</GlowButton>
          </Card>

          {genResult && (
            <AnimatePresence>
              <motion.div key="gen" initial={{opacity:0,y:16}} animate={{opacity:1,y:0}} transition={{duration:0.35}}>
                {(genResult.passwords || genResult.generated_passwords || [genResult.password]).filter(Boolean).map((pwd, i) => (
                  <Card key={i} style={{ padding:20, marginBottom:12 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:12 }}>
                      <code style={{ flex:1, fontSize:15, fontFamily:theme.mono, color:theme.primary, wordBreak:'break-all', padding:'10px 14px', background:theme.bg, borderRadius:theme.radiusSm }}>
                        {pwd}
                      </code>
                      <button onClick={()=>copyText(pwd,i)} style={{ padding:'10px 14px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:'transparent', color:copied===i?theme.success:theme.textMuted, cursor:'pointer', fontSize:13, transition:'all 0.2s', whiteSpace:'nowrap' }}>
                        {copied===i ? '✅ Kopyalandı' : '📋 Kopyala'}
                      </button>
                    </div>
                  </Card>
                ))}
                {genResult.security_notes && (
                  <Card style={{ padding:20, marginTop:8, background:'rgba(0,212,255,0.05)', border:`1px solid ${theme.primary}22` }}>
                    <p style={{ fontSize:12, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'1px', marginBottom:8 }}>Güvenlik Notu</p>
                    <p style={{ fontSize:13, color:theme.textMuted, lineHeight:1.6 }}>{genResult.security_notes}</p>
                  </Card>
                )}
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      )}

      {/* Check Tab */}
      {activeTab === 'check' && (
        <div style={{ maxWidth:800, margin:'0 auto' }}>
          <Card style={{ padding:32, marginBottom:24 }}>
            <p style={{ fontSize:14, fontWeight:700, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'1px', marginBottom:16 }}>Şifre Analizi + HIBP Kontrolü</p>
            <p style={{ fontSize:13, color:theme.textMuted, marginBottom:16, lineHeight:1.5 }}>
              Şifreniz k-Anonymity ile kontrol edilir — asla dışarıya gönderilmez, yalnızca SHA-1 hash'inin ilk 5 karakteri kullanılır.
            </p>
            <div style={{ display:'flex', gap:12 }}>
              <input
                type="password"
                value={checkPwd}
                onChange={e=>setCheckPwd(e.target.value)}
                onKeyDown={e=>e.key==='Enter'&&handleCheckFull()}
                placeholder="Kontrol etmek istediğiniz şifreyi girin..."
                style={{ flex:1, padding:'14px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.bg, color:theme.text, fontSize:15, fontFamily:theme.mono, outline:'none', transition:'border-color 0.2s' }}
                onFocus={e=>e.target.style.borderColor=theme.primary}
                onBlur={e=>e.target.style.borderColor=theme.border}
              />
              <GlowButton onClick={handleCheckFull} loading={checkLoading} disabled={!checkPwd}>Analiz Et</GlowButton>
            </div>
          </Card>

          {checkResult && (
            <AnimatePresence>
              <motion.div key="check" initial={{opacity:0,y:16}} animate={{opacity:1,y:0}} transition={{duration:0.35}}>
                {/* Overall Safe Badge */}
                <div style={{ padding:20, borderRadius:theme.radius, marginBottom:16, background: checkResult.overall_safe ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)', border:`1px solid ${checkResult.overall_safe ? '#22c55e44' : '#ef444444'}`, display:'flex', alignItems:'center', gap:14 }}>
                  <span style={{ display:'inline-flex', alignItems:'center', justifyContent:'center', width:44, height:44, borderRadius:'50%', background: checkResult.overall_safe ? 'rgba(34,197,94,0.2)' : 'rgba(239,68,68,0.2)' }}>{checkResult.overall_safe ? <CheckCircle size={24} color={theme.success}/> : <AlertTriangle size={24} color={theme.danger}/>}</span>
                  <div>
                    <p style={{ fontSize:16, fontWeight:700, color: checkResult.overall_safe ? theme.success : '#ef4444' }}>
                      {checkResult.overall_safe ? 'Şifre Güvenli' : 'Dikkat Gerekiyor'}
                    </p>
                    <p style={{ fontSize:13, color:theme.textMuted }}>{(checkResult.combined_recommendation||[]).join(' ')}</p>
                  </div>
                </div>

                <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
                  {/* Strength Card */}
                  {checkResult.strength_analysis && (
                    <Card style={{ padding:24 }}>
                      <p style={{ fontSize:12, fontWeight:700, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'1px', marginBottom:16 }}>💪 Güçlülük Analizi</p>
                      <p style={{ fontSize:22, fontWeight:800, color: strengthColor(checkResult.strength_analysis.security_level||''), marginBottom:8 }}>
                        {checkResult.strength_analysis.security_level || '-'}
                      </p>
                      {Number.isFinite(checkResult.strength_analysis.strength_score) && (
                        <div style={{ marginBottom:12 }}>
                          <div style={{ display:'flex', justifyContent:'space-between', fontSize:12, color:theme.textMuted, marginBottom:4 }}>
                            <span>Güç Skoru</span><span>{checkResult.strength_analysis.strength_score}/100</span>
                          </div>
                          <div style={{ height:6, borderRadius:3, background:theme.border, overflow:'hidden' }}>
                            <motion.div initial={{width:0}} animate={{width:`${checkResult.strength_analysis.strength_score}%`}}
                              transition={{duration:0.7}} style={{ height:'100%', borderRadius:3, background:strengthColor(checkResult.strength_analysis.security_level||'') }} />
                          </div>
                        </div>
                      )}
                      {checkResult.strength_analysis.length_info && (
                        <p style={{ fontSize:12, color:theme.textMuted }}>{checkResult.strength_analysis.length_info}</p>
                      )}
                    </Card>
                  )}

                  {/* Pwned Card */}
                  {checkResult.pwned_check && (
                    <Card style={{ padding:24 }}>
                      <p style={{ fontSize:12, fontWeight:700, color:theme.textMuted, textTransform:'uppercase', letterSpacing:'1px', marginBottom:16 }}>🔍 Sızıntı Kontrolü (HIBP)</p>
                      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
                        <span style={{ fontSize:28 }}>{checkResult.pwned_check.pwned ? '🚨' : '✅'}</span>
                        <div>
                          <p style={{ fontSize:15, fontWeight:700, color: checkResult.pwned_check.pwned ? '#ef4444' : theme.success }}>
                            {checkResult.pwned_check.pwned ? 'Sızıntıda Görüldü!' : 'Temiz'}
                          </p>
                          {checkResult.pwned_check.times_seen > 0 && (
                            <p style={{ fontSize:12, color:theme.textMuted }}>{checkResult.pwned_check.times_seen.toLocaleString('tr-TR')} kez</p>
                          )}
                        </div>
                        <div style={{ marginLeft:'auto', padding:'4px 12px', borderRadius:'20px', fontSize:12, fontWeight:700, background: checkResult.pwned_check.pwned ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.2)', color: checkResult.pwned_check.pwned ? '#ef4444' : theme.success }}>
                          {(checkResult.pwned_check.risk_level||'').toUpperCase()}
                        </div>
                      </div>
                      <p style={{ fontSize:12, color:theme.textMuted, lineHeight:1.5 }}>{checkResult.pwned_check.warning}</p>
                      <p style={{ fontSize:10, color:theme.textSubtle, marginTop:8 }}>🔒 k-Anonymity: SHA-1 prefix gönderildi, şifreniz paylaşılmadı</p>
                    </Card>
                  )}
                </div>
              </motion.div>
            </AnimatePresence>
          )}
        </div>
      )}
    </div>
  )
}

/* ===============================================
   RISK DASHBOARD
   =============================================== */
function RiskDashboard() {
  const [email, setEmail] = useState('')
  const [region, setRegion] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  function showToast(message, type='success') {
    setToast({ message, type, visible:true })
    setTimeout(() => setToast(t => ({ ...t, visible:false })), 3000)
  }

  async function handleAnalyze() {
    if (!email.trim()) { showToast('E-posta adresi girin', 'error'); return }
    setLoading(true); setError(null); setResult(null)
    try {
      const res = await fetch(`${API}/risk-dashboard/aggregate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), region: region.trim() || undefined }),
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.detail || data.message || 'Analiz başarısız')
      setResult(data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  function scoreColor(s) {
    if (s >= 80) return '#ef4444'
    if (s >= 60) return '#f97316'
    if (s >= 35) return '#eab308'
    return '#22c55e'
  }

  function scoreLabel(s) {
    if (s >= 80) return 'KRİTİK'
    if (s >= 60) return 'YÜKSEK'
    if (s >= 35) return 'ORTA'
    return 'DÜŞÜK'
  }

  const moduleIcons = {
    breach_intel: 'Sızıntı',
    phishing_detector: 'Phishing',
    victim_atlas: 'Atlas',
    honeypot: 'IOC',
  }

  return (
    <div style={{ paddingBottom: 80 }}>
      <Toast message={toast.message} type={toast.type} visible={toast.visible} />

      <SectionHeader
        badge="08 · Risk Dashboard"
        title="Birleşik Dijital Risk Paneli"
        subtitle="Tüm modüllerden gelen verilerle kişisel dijital risk skorunu tek ekranda görüntüle."
      />

      {/* Input Section */}
      <div style={{ maxWidth: 700, margin: '0 auto 40px' }}>
        <Card style={{ padding: 32 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 700, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 8 }}>E-posta Adresi *</label>
              <input
                value={email}
                onChange={e => setEmail(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
                placeholder="ornek@domain.com"
                style={{ width: '100%', padding: '14px 16px', borderRadius: theme.radiusSm, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 15, fontFamily: theme.mono, outline: 'none', boxSizing: 'border-box', transition: 'border-color 0.2s' }}
                onFocus={e => e.target.style.borderColor = theme.primary}
                onBlur={e => e.target.style.borderColor = theme.border}
              />
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 700, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 8 }}>Şehir (opsiyonel)</label>
              <input
                value={region}
                onChange={e => setRegion(e.target.value)}
                placeholder="İstanbul, Ankara..."
                style={{ width: '100%', padding: '12px 16px', borderRadius: theme.radiusSm, border: `1px solid ${theme.border}`, background: theme.bg, color: theme.text, fontSize: 14, outline: 'none', boxSizing: 'border-box', transition: 'border-color 0.2s' }}
                onFocus={e => e.target.style.borderColor = theme.primary}
                onBlur={e => e.target.style.borderColor = theme.border}
              />
            </div>
            <GlowButton onClick={handleAnalyze} loading={loading} disabled={!email.trim()}>
              🛡️ Risk Analizi Başlat
            </GlowButton>
          </div>
        </Card>
      </div>

      {error && (
        <div style={{ maxWidth: 700, margin: '0 auto 32px', padding: 20, borderRadius: theme.radiusSm, background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444', fontSize: 14 }}>
          ❌ {error}
        </div>
      )}

      {result && (
        <AnimatePresence mode="wait">
          <motion.div key="dashboard-result" initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.45, ease: theme.ease.out }}>

            {/* Composite Score Hero */}
            <div style={{ maxWidth: 700, margin: '0 auto 32px' }}>
              <Card style={{ padding: 40, textAlign: 'center', background: `linear-gradient(145deg, ${theme.surface}, ${theme.surface2})` }}>
                <p style={{ fontSize: 11, fontWeight: 800, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '2px', marginBottom: 16 }}>Birleşik Risk Skoru</p>
                <div style={{ position: 'relative', display: 'inline-block', marginBottom: 16 }}>
                  <svg width="160" height="160" viewBox="0 0 160 160">
                    <circle cx="80" cy="80" r="68" fill="none" stroke={theme.surface2} strokeWidth="12"/>
                    <circle
                      cx="80" cy="80" r="68"
                      fill="none"
                      stroke={scoreColor(result.composite_score)}
                      strokeWidth="12"
                      strokeLinecap="round"
                      strokeDasharray={`${2 * Math.PI * 68}`}
                      strokeDashoffset={`${2 * Math.PI * 68 * (1 - result.composite_score / 100)}`}
                      transform="rotate(-90 80 80)"
                      style={{ transition: 'stroke-dashoffset 1s ease, stroke 0.5s' }}
                    />
                  </svg>
                  <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: 40, fontWeight: 900, color: scoreColor(result.composite_score), fontFamily: theme.mono, lineHeight: 1 }}>{result.composite_score}</span>
                    <span style={{ fontSize: 11, color: theme.textMuted, marginTop: 4 }}>/100</span>
                  </div>
                </div>
                <div style={{ display: 'inline-block', padding: '6px 24px', borderRadius: '20px', background: `${scoreColor(result.composite_score)}22`, border: `1px solid ${scoreColor(result.composite_score)}55`, color: scoreColor(result.composite_score), fontSize: 16, fontWeight: 800, letterSpacing: '1px', marginBottom: 16 }}>
                  {result.risk_label}
                </div>
                <p style={{ color: theme.textMuted, fontSize: 15, lineHeight: 1.6, maxWidth: 500, margin: '0 auto' }}>{result.summary}</p>
              </Card>
            </div>

            {/* Module Scores */}
            <div style={{ maxWidth: 900, margin: '0 auto 32px' }}>
              <p style={{ fontSize: 13, fontWeight: 700, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 16 }}>Modül Katkıları</p>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
                {(result.modules || []).map((mod, i) => (
                  <Card key={i} style={{ padding: 20, cursor: 'default' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
                      <span style={{ display:'inline-flex', alignItems:'center', justifyContent:'center', padding:'4px 8px', borderRadius:6, background:theme.primaryDim, color:theme.primary, fontSize:10, fontWeight:800, letterSpacing:'0.5px' }}>{moduleIcons[mod.module] || 'MOD'}</span>
                      <div>
                        <p style={{ fontSize: 13, fontWeight: 700, color: '#fff' }}>{mod.label}</p>
                        <p style={{ fontSize: 11, color: theme.textMuted }}>Ağırlık: %{mod.weight_pct}</p>
                      </div>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{ flex: 1, height: 6, borderRadius: 3, background: theme.border, overflow: 'hidden' }}>
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${mod.score}%` }}
                          transition={{ duration: 0.8, delay: i * 0.1, ease: theme.ease.out }}
                          style={{ height: '100%', borderRadius: 3, background: scoreColor(mod.score) }}
                        />
                      </div>
                      <span style={{ fontSize: 18, fontWeight: 800, color: scoreColor(mod.score), fontFamily: theme.mono, minWidth: 32, textAlign: 'right' }}>{Math.round(mod.score)}</span>
                    </div>
                    {mod.detail?.available === false && (
                      <p style={{ fontSize: 11, color: theme.textMuted, marginTop: 8 }}>⚠️ Modül verisi alınamadı</p>
                    )}
                    {mod.module === 'breach_intel' && mod.detail?.breach_count > 0 && (
                      <p style={{ fontSize: 11, color: '#ef4444', marginTop: 8 }}>🔴 {mod.detail.breach_count} sızıntı tespit edildi</p>
                    )}
                    {mod.module === 'phishing_detector' && mod.detail?.ioc_count > 0 && (
                      <p style={{ fontSize: 11, color: '#f97316', marginTop: 8 }}>⚠️ {mod.detail.ioc_count} IOC kaydı</p>
                    )}
                    {mod.module === 'victim_atlas' && mod.detail?.total_recent_cases > 0 && (
                      <p style={{ fontSize: 11, color: '#eab308', marginTop: 8 }}>📊 Son 30 günde {mod.detail.total_recent_cases} vaka</p>
                    )}
                    {mod.module === 'honeypot' && mod.detail?.iocs_last_24h >= 0 && (
                      <p style={{ fontSize: 11, color: theme.textMuted, marginTop: 8 }}>Son 24s: {mod.detail.iocs_last_24h} IOC</p>
                    )}
                  </Card>
                ))}
              </div>
            </div>

            {/* Recommendations */}
            {(result.recommendations || []).length > 0 && (
              <div style={{ maxWidth: 900, margin: '0 auto 32px' }}>
                <Card style={{ padding: 32 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
                    <div style={{ width: 44, height: 44, borderRadius: '12px', background: theme.warning+'22', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <span style={{ fontSize: 22 }}>💡</span>
                    </div>
                    <div>
                      <p style={{ fontSize: 16, fontWeight: 700, color: '#fff' }}>Öneriler</p>
                      <p style={{ fontSize: 13, color: theme.textMuted }}>Kişiselleştirilmiş güvenlik önerileri</p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {result.recommendations.map((rec, i) => (
                      <motion.div key={i} initial={{ opacity: 0, x: -12 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.07, duration: 0.35 }}
                        style={{ padding: '14px 18px', borderRadius: theme.radiusSm, background: theme.bg, border: `1px solid ${theme.border}`, fontSize: 14, color: theme.text, lineHeight: 1.6 }}>
                        {rec}
                      </motion.div>
                    ))}
                  </div>
                </Card>
              </div>
            )}

            {/* Victim Atlas Trend */}
            {result.modules?.find(m => m.module === 'victim_atlas')?.detail?.top_attack_methods?.length > 0 && (
              <div style={{ maxWidth: 900, margin: '0 auto 32px' }}>
                <Card style={{ padding: 32 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20 }}>
                    <span style={{ fontSize: 24 }}>📊</span>
                    <div>
                      <p style={{ fontSize: 16, fontWeight: 700, color: '#fff' }}>Bölgesel Saldırı Trendleri</p>
                      <p style={{ fontSize: 13, color: theme.textMuted }}>Son 30 günde en çok kullanılan yöntemler</p>
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {result.modules.find(m => m.module === 'victim_atlas').detail.top_attack_methods.map((t, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                        <span style={{ fontSize: 13, fontWeight: 700, color: theme.textMuted, width: 20, textAlign: 'right' }}>#{t.rank}</span>
                        <span style={{ fontSize: 14, color: '#fff', minWidth: 180 }}>{t.attack_method_tr}</span>
                        <div style={{ flex: 1, height: 8, borderRadius: 4, background: theme.border, overflow: 'hidden' }}>
                          <motion.div
                            initial={{ width: 0 }} animate={{ width: `${t.pct}%` }}
                            transition={{ duration: 0.7, delay: i * 0.1, ease: theme.ease.out }}
                            style={{ height: '100%', borderRadius: 4, background: theme.primary }}
                          />
                        </div>
                        <span style={{ fontSize: 12, color: theme.textMuted, minWidth: 50, textAlign: 'right' }}>{t.count} vaka ({t.pct}%)</span>
                      </div>
                    ))}
                  </div>
                </Card>
              </div>
            )}

          </motion.div>
        </AnimatePresence>
      )}
    </div>
  )
}
