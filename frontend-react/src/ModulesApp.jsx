import { Component, useState, useEffect, useRef, useCallback } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'
import { Shield, ShieldAlert, AlertTriangle, Activity, Globe, Search, Copy, Check, Wifi, Database, TrendingUp, Zap, Bug, Mail, Server, Hash, Radio, Eye, ChevronRight, BarChart3, Lock, Download } from 'lucide-react'
import TurkeyHeatmapSection from './components/TurkeyHeatmapSection.jsx'
import ScoringPipelineDiagram from './components/ScoringPipelineDiagram.jsx'

const API = import.meta.env.VITE_API_BASE_URL || '/api/v2'

function normalizeStatus(status) {
  const s = String(status || '').toLowerCase()
  return s === 'active' || s === 'online'
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
  return <div style={{ position:'fixed', bottom:30, right:30, zIndex:9999, padding:'14px 24px', borderRadius:theme.radiusSm, background:type==='success'?'#22c55e':'#ef4444', color:'#fff', fontWeight:600, fontSize:14, boxShadow:'0 10px 40px rgba(0,0,0,0.4)', animation:'fadeInUp 0.3s ease' }}>{type==='success'?'✅ ':'❌ '}{message}</div>
}

function RiskBadge({ level, size='sm' }) {
  const colors = { critical:{bg:'rgba(239,68,68,0.2)',text:'#ef4444'}, high:{bg:'rgba(255,107,53,0.2)',text:'#ff6b35'}, medium:{bg:'rgba(245,158,11,0.2)',text:'#f59e0b'}, low:{bg:'rgba(34,197,94,0.2)',text:'#22c55e'}, safe:{bg:'rgba(0,212,255,0.2)',text:'#00d4ff'} }
  const c = colors[level] || {bg:'rgba(100,116,139,0.2)',text:'#64748b'}
  const labels = { critical:'🔴 Kritik', high:'🟠 Yuksek', medium:'🟡 Orta', low:'🟢 Dusuk', safe:'🔵 Guvenli' }
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

export default function ModulesApp() {
  const [page, setPage] = useState('ai-analyzer')
  const [scrolled, setScrolled] = useState(false)
  const reducedMotion = useReducedMotion() ?? false
  useEffect(()=>{const onScroll=()=>setScrolled(window.scrollY>20);window.addEventListener('scroll',onScroll,{passive:true});return()=>window.removeEventListener('scroll',onScroll)},[])

  const tabs = [
    {id:'ai-analyzer',label:'AI Analiz',icon:'🤖'},
    {id:'phishing-detector',label:'Phishing',icon:'🎣'},
    {id:'victim-atlas',label:'Magduriyet Atlasi',icon:'🧭'},
    {id:'honeypot',label:'IOC / Tuzak',icon:'🕸️'},
    {id:'breach-intel',label:'Sizinti',icon:'🔓'},
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
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <svg width="32" height="32" viewBox="0 0 36 36" fill="none">
            <path d="M18 4L6 11V18C6 23.5 10 28.5 18 30C26 28.5 30 23.5 30 18V11L18 4Z" stroke={theme.primary} strokeWidth="2" fill="none"/>
            <path d="M14 18L17 21L23 15" stroke={theme.primary} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span style={{ fontSize:20, fontWeight:700, color:'#fff', letterSpacing:'-0.5px' }}>Aegis<span style={{ color:theme.primary }}>Nexus</span></span>
          <span style={{ fontSize:11, color:theme.textMuted, marginLeft:4 }}>Modüller</span>
        </div>
        <div style={{ display:'flex', gap:4, background:theme.surface, borderRadius:theme.radiusSm, padding:3 }}>
          {tabs.map(t => <motion.button key={t.id} onClick={()=>setPage(t.id)} initial={false} whileHover={reducedMotion ? undefined : { scale:1.02 }} whileTap={reducedMotion ? undefined : { scale:0.98 }} style={{ padding:'8px 18px', borderRadius:'6px', border:'none', cursor:'pointer', fontSize:13, fontWeight:600, fontFamily:theme.navFont, background:page===t.id?theme.primary:'transparent', color:page===t.id?'#000':theme.textMuted, transition:'all 0.2s ease', display:'flex', alignItems:'center', gap:6, position:'relative' }}>
            <span>{t.icon}</span><span>{t.label}</span>
            {page===t.id && <motion.span initial={{scaleX:0}} animate={{scaleX:1}} transition={{duration:0.3}} style={{ position:'absolute', bottom:0, left:0, right:0, height:2, background:theme.primary, borderRadius:1 }} />}
          </motion.button>)}
        </div>
        <motion.a href="https://aegisnexus.dev" style={{ fontSize:13, color:theme.textMuted, textDecoration:'none', padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, transition:'all 0.2s' }}
          whileHover={{ scale:1.02, borderColor:theme.primary+'44', color:theme.primary }}
          whileTap={{ scale:0.98 }}>← Ana Sayfa</motion.a>
      </div>
    </nav>

    <motion.main initial={{ opacity:0, y:20 }} animate={{ opacity:1, y:0 }} transition={{ duration:0.5, ease:theme.ease.out }} style={{ paddingTop:86, maxWidth:1400, margin:'0 auto', padding:'86px 24px 0' }}>
      {page==='ai-analyzer' && <AIAnalyzer onGoVictimAtlas={()=>setPage('victim-atlas')} />}
      {page==='phishing-detector' && <PhishingDetector />}
      {page==='victim-atlas' && <VictimAtlas onOpenAIAnalyzer={()=>setPage('ai-analyzer')} />}
      {page==='honeypot' && <ModuleErrorBoundary><HoneypotIOC /></ModuleErrorBoundary>}
      {page==='breach-intel' && <BreachIntel />}
    </motion.main>
    <footer style={{ borderTop:`1px solid ${theme.border}`, padding:'24px', textAlign:'center', color:theme.textMuted, fontSize:13, marginTop:80 }}>
      <div style={{ maxWidth:1400, margin:'0 auto' }}>
        <p>AegisNexus Modüller &copy; 2026</p>
        <div style={{ display:'flex', gap:24, justifyContent:'center', marginTop:12 }}>
          <a href={API+'/docs'} style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">API Docs</a>
          <a href="https://aegisnexus.dev" style={{ color:theme.primary, textDecoration:'none' }} target="_blank">Ana Sayfa</a>
          <a href="https://github.com/garmoths/AegisNexus" style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">GitHub</a>
        </div>
      </div>
    </footer>
  </div>
}

/* ===============================================
   AI ANALYZER
   =============================================== */
function AIAnalyzer({ onGoVictimAtlas }) {
  const [message, setMessage] = useState('')
  const [context, setContext] = useState('email')
  const [analyzing, setAnalyzing] = useState(false)
  const [result, setResult] = useState(null)
  const [history, setHistory] = useState([])
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })
  const resultRef = useRef(null)

  useEffect(() => { loadHistory() }, [])

  async function loadHistory() {
    try { const r = await fetch(`${API}/ai-analyzer/history?limit=10`); const d = await r.json(); setHistory(d.data || []) } catch { setHistory([]) }
  }

  async function handleAnalyze() {
    if (!message || message.length < 10) { showToast('En az 10 karakter girin', 'error'); return }
    setAnalyzing(true); setResult(null)
    try {
      const r = await fetch(`${API}/ai-analyzer/analyze`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ message, context }),
      })
      if (!r.ok) { const e=await r.json(); throw new Error(e.detail||'Analiz hatasi') }
      const d = await r.json(); setResult(d); loadHistory()
      setTimeout(()=>resultRef.current?.scrollIntoView({behavior:'smooth',block:'start'}),200)
    } catch(e) { showToast('Analiz hatasi: '+e.message, 'error') }
    setAnalyzing(false)
  }

  function showToast(msg, type='success') { setToast({message:msg,type,visible:true}); setTimeout(()=>setToast(t=>({...t,visible:false})),3000) }

  const examples = [
    { text:'Sayin musterimiz, hesabiniz askiya alinmistir. Hemen tiklayin: http://bit.ly/3xK...', label:'Phishing Email' },
    { text:'Tebrikler! 100.000 TL kazandiniz. Hemen arayin: 0555 123 45 67', label:'SMS Dolandiriciligi' },
    { text:'Merhaba, fatura ekteki gibidir. Acil odeme yapiniz. Saygilar, Mali Isler', label:'Fatura Dolandiriciligi' },
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
          <span style={{ display:'inline-block', padding:'10px 24px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'30px', fontSize:13, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'3px', marginBottom:24 }}>AI Analiz Modulu</span>
          <h1 style={{ fontSize:56, fontWeight:800, color:'#fff', marginBottom:20, letterSpacing:'-2px', lineHeight:1.1 }}>Yapay Zeka ile Guvenlik Analizi</h1>
          <p style={{ color:theme.textMuted, fontSize:18, maxWidth:700, margin:'0 auto', lineHeight:1.6 }}>Mesaj, e-posta veya metinlerinizi AI ile analiz edin. Phishing, sosyal muhendislik ve kotu amacli icerikleri tespit edin.</p>
          <div style={{ marginTop:20 }}>
            <GlowButton variant="secondary" onClick={onGoVictimAtlas}>🧭 Magduriyet Atlasina gec</GlowButton>
          </div>
        </motion.div>
      </div>
    </motion.div>

    {/* Main Content - Glassmorphism Cards */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.4, duration:0.6, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}
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
          <span>📝</span> Analiz Edilecek Metin
        </motion.h3>
        
        <motion.div 
          initial={{ opacity:0, y:10 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.6, duration:0.4 }}
          style={{ display:'flex', gap:10, marginBottom:20, flexWrap:'wrap' }}
        >
          {[{id:'email',label:'📧 E-posta',icon:'📧'},{id:'sms',label:'💬 SMS',icon:'💬'},{id:'whatsapp',label:'📱 WhatsApp',icon:'📱'},{id:'social_media',label:'🌐 Sosyal Medya',icon:'🌐'}].map((c,i)=>
            <motion.button 
              key={c.id} 
              onClick={()=>setContext(c.id)} 
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
                background:context===c.id?theme.primary:'rgba(255,255,255,0.05)', 
                borderColor:context===c.id?theme.primary:theme.border, 
                color:context===c.id?'#000':theme.textMuted,
                transition:'all 0.3s ease'
              }}
            >
              {c.icon} {c.label.replace(/^[^ ]+ /, '')}
            </motion.button>
          )}
        </motion.div>
        
        <motion.textarea 
          initial={{ opacity:0 }}
          animate={{ opacity:1 }}
          transition={{ delay:0.8, duration:0.4 }}
          value={message} 
          onChange={e=>setMessage(e.target.value)} 
          placeholder="Analiz edilecek metni buraya yapistirin veya yazin..." 
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
            {analyzing?'Analiz Ediliyor...':'🔍 Analiz Et'}
          </motion.button>
        </motion.div>
        
        <motion.div 
          initial={{ opacity:0, y:10 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:1.0, duration:0.4 }}
          style={{ marginTop:28 }}
        >
          <p style={{ fontSize:12, color:theme.textMuted, fontWeight:700, marginBottom:12, textTransform:'uppercase', letterSpacing:'2px' }}>Ornek Metinler</p>
          {examples.map((ex,i)=>
            <motion.button 
              key={i} 
              onClick={()=>setMessage(ex.text)} 
              initial={{ opacity:0, x:-10 }}
              animate={{ opacity:1, x:0 }}
              transition={{ delay:1.1 + i*0.1, duration:0.3 }}
              whileHover={{ background:'rgba(0,212,255,0.1)', borderColor:theme.primary, x:4 }}
              style={{ 
                padding:'14px 18px', 
                borderRadius:theme.radius.md, 
                border:`1px solid ${theme.border}`, 
                background:'rgba(255,255,255,0.03)', 
                cursor:'pointer', 
                textAlign:'left', 
                fontSize:13, 
                color:theme.textMuted, 
                lineHeight:1.5, 
                transition:'all 0.3s ease', 
                display:'block', 
                width:'100%', 
                marginBottom:10 
              }}
            >
              <span style={{ color:theme.primary, fontWeight:700, fontSize:12, display:'block', marginBottom:4 }}>{ex.label}</span>
              {ex.text.substring(0,80)}...
            </motion.button>
          )}
        </motion.div>
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
          <span>📊</span> Analiz Sonuclari
        </motion.h3>
        
        {!result&&!analyzing&&
          <motion.div 
            initial={{ opacity:0, scale:0.9 }}
            animate={{ opacity:1, scale:1 }}
            transition={{ delay:0.6, duration:0.4 }}
            style={{ textAlign:'center', padding:'80px 20px', color:theme.textMuted }}
          >
            <span style={{ fontSize:64, display:'block', marginBottom:20, opacity:0.5 }}>🔍</span>
            <p style={{ fontSize:16, marginBottom:8 }}>Henuz analiz yapilmadi</p>
            <p style={{ fontSize:14, opacity:0.7 }}>Sol taraftaki metni girin ve "Analiz Et" butonuna tiklayin</p>
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
        
        {result&&<ResultContent score={score} threatLevel={sa.threat_level||'medium'} isPhishing={isPhishing} isScam={isScam} sa={sa} da={da} recs={recs} beliefs={beliefs} threats={threats} suspects={suspects} result={result} />}
      </Card>
    </motion.div>
    
    {/* History Section */}
    <motion.div
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.8, duration:0.6, ease:theme.ease.out }}
    >
      <Card style={{ 
        background:'rgba(255,255,255,0.03)',
        backdropFilter:'blur(10px)',
        WebkitBackdropFilter:'blur(10px)',
        border:`1px solid ${theme.border}`,
        padding:32,
        marginBottom:48
      }}>
        <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:20, display:'flex', gap:10, alignItems:'center' }}>
          <span>📜</span> Son Analizler
        </h3>
        {history.length===0?
          <p style={{ color:theme.textMuted, fontSize:14, textAlign:'center', padding:40 }}>Henuz analiz yapilmadi</p>:
          <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
            {history.map((h,i)=>
              <motion.div 
                key={h.id} 
                initial={{ opacity:0, y:10 }}
                animate={{ opacity:1, y:0 }}
                transition={{ delay:0.9 + i*0.05, duration:0.3 }}
                whileHover={{ background:'rgba(255,255,255,0.05)' }}
                style={{ 
                  display:'flex', 
                  justifyContent:'space-between', 
                  alignItems:'center', 
                  padding:'14px 18px', 
                  background:'rgba(255,255,255,0.03)', 
                  borderRadius:theme.radius.md, 
                  border:`1px solid ${theme.border}`,
                  transition:'all 0.3s ease',
                  cursor:'pointer'
                }}
              >
                <div style={{ flex:1, overflow:'hidden' }}>
                  <p style={{ fontSize:14, color:'#fff', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis', fontFamily:theme.mono }}>{h.url||h.message||h.text}</p>
                  <p style={{ fontSize:12, color:theme.textMuted, marginTop:4 }}>{h.created_at?new Date(h.created_at).toLocaleString('tr-TR'):''}</p>
                </div>
                <RiskBadge level={h.risk_level||h.threat_level||'safe'} />
              </motion.div>
            )}
          </div>
        }
      </Card>
    </motion.div>
  </div>
}

function ResultContent({ score, threatLevel, isPhishing, isScam, sa, da, recs, beliefs, threats, suspects, result }) {
  // Use new algorithm's confidence from security_assessment (0-1 range), not old ML confidence
  const confidence = sa?.confidence || da?.advanced_breakdown?.confidence || 0
  const confidencePercentage = Math.round(confidence * 100)
  const confidenceColor = confidence > 0.75 ? theme.danger : confidence > 0.50 ? theme.warning : confidence > 0.25 ? theme.primary : theme.success
  
  const hardOverride = da?.hard_override || false

  return <motion.div 
    initial={{ opacity:0, scale:0.95 }}
    animate={{ opacity:1, scale:1 }}
    transition={{ duration:0.5, ease:theme.ease.out }}
  >
    {/* Hero Result Card */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.1, duration:0.4 }}
      style={{ 
        display:'flex', 
        gap:32, 
        alignItems:'stretch', 
        marginBottom:28, 
        flexWrap:'wrap',
        background: 'linear-gradient(135deg, rgba(0,212,255,0.1) 0%, rgba(255,0,128,0.05) 100%)',
        borderRadius: theme.radius.lg,
        padding: '24px 28px',
        border: `1px solid ${theme.border}`,
        backdropFilter: 'blur(10px)'
      }}
    >
      {/* Left: Big Gauge */}
      <div style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', minWidth:140 }}>
        <RiskGauge score={score} label="Risk Skoru" size="lg" />
        {hardOverride && (
          <span style={{ 
            marginTop:12, 
            padding:'6px 14px', 
            borderRadius:20, 
            fontSize:11, 
            fontWeight:800, 
            background: theme.accentDim,
            color: theme.accent,
            textTransform: 'uppercase',
            letterSpacing: 0.5
          }}>
            🚨 HARD OVERRIDE
          </span>
        )}
      </div>
      
      {/* Right: Details */}
      <div style={{ flex:1, minWidth:280, display:'flex', flexDirection:'column', gap:16 }}>
        {/* Badges */}
        <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
          <RiskBadge level={threatLevel} size="lg" />
          <span style={{ 
            padding:'10px 20px', 
            borderRadius:'28px', 
            fontSize:15, 
            fontWeight:800, 
            background: isPhishing ? 'linear-gradient(135deg, #ff4444, #ff6b6b)' : 'linear-gradient(135deg, #00d4ff, #0099cc)',
            color: '#fff',
            boxShadow: isPhishing ? '0 4px 15px rgba(255,68,68,0.3)' : '0 4px 15px rgba(0,212,255,0.3)'
          }}>
            {isPhishing ? '⚠️ TEHLİKELİ' : '✅ GÜVENLİ'}
          </span>
          {isScam && <span style={{ 
            padding:'10px 20px', 
            borderRadius:'28px', 
            fontSize:15, 
            fontWeight:800, 
            background: 'linear-gradient(135deg, #ff8c00, #ffa500)', 
            color: '#fff',
            boxShadow: '0 4px 15px rgba(255,140,0,0.3)'
          }}>🛑 SCAM</span>}
        </div>
        
        {/* Status Line */}
        <div style={{ 
          padding: '14px 18px', 
          background: 'rgba(0,0,0,0.2)', 
          borderRadius: theme.radius.md,
          border: `1px solid ${theme.border}`
        }}>
          <p style={{ fontSize:15, color:theme.text, margin:0 }}>
            <span style={{ color: theme.textMuted }}>Güvenlik Durumu:</span>{' '}
            <strong style={{ 
              color: score > 70 ? theme.danger : score > 40 ? theme.warning : theme.success,
              fontSize: 16
            }}>
              {sa.safety_status || 'Bilinmiyor'}
            </strong>
          </p>
          <p style={{ fontSize:15, color:theme.text, margin:'8px 0 0 0' }}>
            <span style={{ color: theme.textMuted }}>Gerekli Aksiyon:</span>{' '}
            <strong style={{ color: theme.primary }}>{sa.action_required || 'YOK'}</strong>
          </p>
        </div>
        
        {/* Confidence Bar */}
        <div style={{ 
          padding: '16px 18px', 
          background: 'rgba(255,255,255,0.03)', 
          borderRadius: theme.radius.md, 
          border: `1px solid ${theme.border}` 
        }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
            <span style={{ fontSize:14, fontWeight:700, color:theme.textMuted }}>🤖 AI Güvenilirlik Skoru</span>
            <span style={{ fontSize:18, fontWeight:800, color:confidenceColor }}>{confidencePercentage}%</span>
          </div>
          <div style={{ width:'100%', height:12, background:'rgba(255,255,255,0.08)', borderRadius:6, overflow:'hidden' }}>
            <motion.div 
              initial={{ width:0 }}
              animate={{ width:`${confidencePercentage}%` }}
              transition={{ delay:0.3, duration:0.8, ease:'easeOut' }}
              style={{ 
                height:'100%', 
                background: `linear-gradient(90deg, ${confidenceColor}, ${confidenceColor}aa)`, 
                borderRadius:6,
                boxShadow: `0 0 10px ${confidenceColor}50`
              }} 
            />
          </div>
          <p style={{ fontSize:13, color:theme.textMuted, marginTop:10, lineHeight:1.5 }}>
            Bu analiz %{confidencePercentage} güvenilirlikle tamamlandı. 
            {confidence < 0.5 ? 'Düşük güven - sonuçları dikkatle değerlendirin.' : 'Yüksek güven - sonuçlar güvenilir.'}
          </p>
        </div>
      </div>
    </motion.div>
    
    {result.summary&&
      <motion.div
        initial={{ opacity:0, y:10 }}
        animate={{ opacity:1, y:0 }}
        transition={{ delay:0.2, duration:0.4 }}
      >
        <Card style={{ 
          padding:20, 
          marginBottom:20, 
          maxHeight:140, 
          overflowY:'auto',
          background:'rgba(255,255,255,0.03)',
          border:`1px solid ${theme.border}`
        }}>
          <p style={{ fontSize:14, lineHeight:1.7, color:theme.text, whiteSpace:'pre-wrap' }}>{result.summary}</p>
        </Card>
      </motion.div>
    }
    
    {/* Analysis Sections Grid */}
    <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:16, marginBottom:28 }}>
      {[
        { 
          title:'🚨 Tespit Edilen Tehditler', 
          items:threats, 
          color:theme.accent, 
          bg:'rgba(255,0,64,0.08)',
          icon: '⚠️',
          emptyMsg: 'Tehdit tespit edilmedi'
        },
        { 
          title:'🧠 Psikolojik Tetikleyiciler', 
          items:beliefs, 
          color:theme.warning, 
          bg:'rgba(255,193,7,0.08)',
          icon: '🎯',
          emptyMsg: 'Tetikleyici tespit edilmedi'
        },
        { 
          title:'🔍 Şüpheli Öğeler', 
          items:suspects, 
          color:theme.primary, 
          bg:'rgba(0,212,255,0.08)',
          icon: '🔎',
          emptyMsg: 'Şüpheli öğe yok'
        },
        { 
          title:'🔗 URL Analizi', 
          items:da?.url_analysis||[], 
          color:theme.primary, 
          bg:'rgba(0,212,255,0.05)',
          icon: '🌐',
          isUrl:true,
          emptyMsg: 'URL bulunamadı'
        }
      ].map((section,i)=> (
        <motion.div
          key={i}
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.3 + i*0.08, duration:0.4 }}
        >
          <Card style={{ 
            padding:20, 
            maxHeight:260, 
            overflowY:'auto',
            background: `linear-gradient(135deg, ${section.bg} 0%, rgba(255,255,255,0.02) 100%)`,
            border: `1px solid ${section.color}30`,
            borderRadius: theme.radius.lg
          }}>
            {/* Section Header */}
            <div style={{ 
              display:'flex', 
              alignItems:'center', 
              gap:10, 
              marginBottom:16,
              paddingBottom:12,
              borderBottom: `1px solid ${section.color}30`
            }}>
              <span style={{ fontSize:20 }}>{section.icon}</span>
              <p style={{ fontSize:14, fontWeight:800, color:section.color, margin:0, letterSpacing:0.5 }}>
                {section.title}
              </p>
              <span style={{ 
                marginLeft:'auto', 
                padding:'4px 10px', 
                borderRadius:12, 
                fontSize:11, 
                fontWeight:700,
                background: section.color + '20',
                color: section.color
              }}>
                {section.items.length}
              </span>
            </div>
            
            {/* Items */}
            {section.items.length > 0 ? (
              <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
                {section.items.map((item,j)=> (
                  <motion.div 
                    key={j}
                    initial={{ opacity:0, x:-15 }}
                    animate={{ opacity:1, x:0 }}
                    transition={{ delay:0.4 + i*0.08 + j*0.05, duration:0.3 }}
                    style={{ 
                      padding:'12px 14px', 
                      background: 'rgba(0,0,0,0.2)', 
                      borderRadius:10, 
                      borderLeft:`4px solid ${section.color}`, 
                      fontSize:13, 
                      color:theme.text,
                      lineHeight:1.6,
                      boxShadow: '0 2px 8px rgba(0,0,0,0.1)'
                    }}
                  >
                    {section.isUrl ? (
                      <div>
                        <p style={{ 
                          wordBreak:'break-all', 
                          fontFamily:theme.mono, 
                          fontSize:12,
                          color: theme.primary,
                          marginBottom:6
                        }}>
                          🔗 {item.url || item}
                        </p>
                        <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
                          <span style={{ 
                            fontSize:10, 
                            padding:'3px 8px', 
                            borderRadius:6,
                            background: item.risk_score > 50 ? theme.accentDim : theme.successDim,
                            color: item.risk_score > 50 ? theme.accent : theme.success
                          }}>
                            Risk: {item.risk_score || 'N/A'}/100
                          </span>
                          {item.is_suspicious && (
                            <span style={{ 
                              fontSize:10, 
                              padding:'3px 8px', 
                              borderRadius:6,
                              background: theme.warningDim,
                              color: theme.warning
                            }}>
                              ⚠️ Şüpheli
                            </span>
                          )}
                        </div>
                        {item.reason && (
                          <p style={{ fontSize:11, color:theme.textMuted, marginTop:8, fontStyle:'italic' }}>
                            {item.reason}
                          </p>
                        )}
                      </div>
                    ) : (
                      <div style={{ display:'flex', alignItems:'flex-start', gap:8 }}>
                        <span style={{ color: section.color, fontSize:14 }}>
                          {section.title.includes('Psikolojik') ? '⚡' : (section.title.includes('Şüpheli') ? '•' : '⚠️')}
                        </span>
                        <span>{item}</span>
                      </div>
                    )}
                  </motion.div>
                ))}
              </div>
            ) : (
              <motion.div
                initial={{ opacity:0 }}
                animate={{ opacity:1 }}
                transition={{ delay:0.5 }}
                style={{ 
                  textAlign:'center', 
                  padding:30,
                  color:theme.textMuted 
                }}
              >
                <span style={{ fontSize:32, display:'block', marginBottom:10, opacity:0.5 }}>✓</span>
                <p style={{ fontSize:13, margin:0 }}>{section.emptyMsg}</p>
              </motion.div>
            )}
          </Card>
        </motion.div>
      ))}
    </div>
    
    {/* Recommendations Section */}
    {recs.length > 0 &&
      <motion.div 
        initial={{ opacity:0, y:20 }}
        animate={{ opacity:1, y:0 }}
        transition={{ delay:0.6, duration:0.4 }}
        style={{ marginBottom:16 }}
      >
        <div style={{ 
          display:'flex', 
          alignItems:'center', 
          gap:12, 
          marginBottom:18,
          paddingBottom:12,
          borderBottom: `1px solid ${theme.border}`
        }}>
          <span style={{ fontSize:22 }}>💡</span>
          <p style={{ fontSize:16, fontWeight:800, color:'#fff', margin:0, letterSpacing:0.5 }}>
            ÖNERİLER
          </p>
          <span style={{ 
            marginLeft:'auto', 
            padding:'5px 12px', 
            borderRadius:14, 
            fontSize:11, 
            fontWeight:700,
            background: theme.primaryDim,
            color: theme.primary
          }}>
            {recs.length} adet
          </span>
        </div>
        
        <div style={{ display:'flex', flexDirection:'column', gap:12, maxHeight:350, overflowY:'auto' }}>
          {recs.map((rec,i)=> {
            const isCritical = rec.priority === 'CRITICAL' || rec.priority === 'HIGH'
            const recText = rec.description || rec.message || (typeof rec === 'string' ? rec : JSON.stringify(rec))
            
            return (
              <motion.div 
                key={i}
                initial={{ opacity:0, x:-20 }}
                animate={{ opacity:1, x:0 }}
                transition={{ delay:0.7 + i*0.06, duration:0.3 }}
                style={{ 
                  padding:'16px 20px', 
                  background: isCritical ? 'rgba(255,0,64,0.08)' : 'rgba(0,212,255,0.06)', 
                  borderRadius:theme.radius.lg, 
                  borderLeft:`4px solid ${isCritical ? theme.accent : theme.primary}`, 
                  fontSize:14, 
                  lineHeight:1.7,
                  color:theme.text,
                  boxShadow: '0 4px 12px rgba(0,0,0,0.15)'
                }}
              >
                <div style={{ display:'flex', alignItems:'flex-start', gap:12 }}>
                  <span style={{ 
                    fontSize:18, 
                    filter: isCritical ? 'drop-shadow(0 0 8px rgba(255,0,64,0.5))' : 'none'
                  }}>
                    {isCritical ? '🚨' : '💡'}
                  </span>
                  <div style={{ flex:1 }}>
                    {rec.priority && (
                      <span style={{ 
                        display:'inline-block',
                        marginBottom:6,
                        padding:'3px 10px', 
                        borderRadius:8, 
                        fontSize:10, 
                        fontWeight:800,
                        textTransform:'uppercase',
                        letterSpacing:0.5,
                        background: isCritical ? theme.accentDim : theme.primaryDim,
                        color: isCritical ? theme.accent : theme.primary
                      }}>
                        {rec.priority}
                      </span>
                    )}
                    <p style={{ margin:0, fontSize:14 }}>{recText}</p>
                    {rec.action && (
                      <p style={{ 
                        margin:'8px 0 0 0', 
                        fontSize:12, 
                        color:theme.primary,
                        fontWeight:700
                      }}>
                        → {rec.action}
                      </p>
                    )}
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>
      </motion.div>
    }
  </motion.div>
}

function RiskGauge({ score, label, showPercentage = false, size = 'md', safetyMode = false }) {
  const sizeMap = {
    sm: { width: 80, height: 80, radius: 32, stroke: 6, fontSize: 16 },
    md: { width: 120, height: 120, radius: 40, stroke: 8, fontSize: 22 },
    lg: { width: 160, height: 160, radius: 56, stroke: 10, fontSize: 28 }
  }
  const { width, height, radius, stroke, fontSize } = sizeMap[size] || sizeMap.md
  
  const c = 2 * Math.PI * radius
  const o = c - (Math.min(score, 100) / 100) * c
  const color = safetyMode
    ? (score > 75 ? theme.success : score > 50 ? theme.primary : score > 25 ? theme.warning : theme.danger)
    : (score > 75 ? theme.danger : score > 50 ? theme.warning : score > 25 ? theme.primary : theme.success)
  const percentage = Math.round(score)
  const center = width / 2
  
  return <div style={{ display:'inline-flex', flexDirection:'column', alignItems:'center' }}>
    <svg width={width} height={height} viewBox={`0 0 ${width} ${height}`}>
      {/* Background circle */}
      <circle 
        cx={center} 
        cy={center} 
        r={radius} 
        fill="none" 
        stroke={theme.border} 
        strokeWidth={stroke}
      />
      {/* Progress circle with glow */}
      <circle 
        cx={center} 
        cy={center} 
        r={radius} 
        fill="none" 
        stroke={color} 
        strokeWidth={stroke} 
        strokeDasharray={c} 
        strokeDashoffset={o} 
        transform={`rotate(-90 ${center} ${center})`} 
        style={{ 
          transition: 'stroke-dashoffset 1s ease',
          filter: `drop-shadow(0 0 8px ${color}50)`
        }} 
        strokeLinecap="round"
      />
      {/* Score text */}
      <text 
        x={center} 
        y={center} 
        textAnchor="middle" 
        dominantBaseline="central" 
        fill="#fff" 
        fontSize={fontSize} 
        fontWeight="800" 
        fontFamily="Inter, sans-serif"
        style={{ textShadow: `0 0 20px ${color}30` }}
      >
        {showPercentage ? `${percentage}%` : score}
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
    { key:'urlhaus', icon:'🔗', name:'URLhaus', data:urlhaus, isBad:urlhaus.listed===true, isClean:urlhaus.listed===false, badLabel:'LISTED', cleanLabel:'CLEAN', detail:urlhaus.listed?`Tehdit: ${urlhaus.threat_type||'unknown'}`:'Kara listede değil', penalty:40 },
    { key:'spamhaus_domain', icon:'🛡️', name:'Spamhaus Domain', data:shDomain, isBad:shDomain.listed===true, isClean:shDomain.listed===false&&shDomain.available, badLabel:'LISTED', cleanLabel:'CLEAN', detail:shDomain.listed?`Listeler: ${(shDomain.lists||[]).join(', ')||'-'}`:shDomain.zrd?'Sıfır itibar (ZRD)':'Temiz', penalty:35 },
    { key:'spamhaus_ip', icon:'🌐', name:'Spamhaus IP', data:shIp, isBad:shIp.listed===true, isClean:shIp.listed===false&&shIp.available, badLabel:'LISTED', cleanLabel:'CLEAN', detail:shIp.listed?`Listeler: ${(shIp.lists||[]).join(', ')||'-'}`:'Temiz', penalty:30 },
    { key:'threatfox', icon:'🦊', name:'ThreatFox', data:tf, isBad:tf.found===true, isClean:tf.found===false&&tf.available, badLabel:'FOUND', cleanLabel:'NOT FOUND', detail:tf.found?`${tf.malware_family||'unknown'} (conf: ${tf.confidence||0}%)`:'IOC bulunamadı', penalty:25 },
    { key:'virustotal', icon:'🛡️', name:'VirusTotal', data:vt, isBad:(vt.malicious||0)>=1, isClean:vt.available&&(vt.malicious||0)===0, badLabel:`${vt.malicious||0} MAL`, cleanLabel:'CLEAN', detail:vt.available?(vt.source==='whitelist'?'Whitelist domain (güvenilir)':`${vt.malicious||0} motor tehlikeli`):'Sonuç yok', penalty:40 },
    { key:'gsb', icon:'🔍', name:'Google Safe Browsing', data:gsb, isBad:gsb.threat===true, isClean:gsb.available&&!gsb.threat, badLabel:'THREAT', cleanLabel:'SAFE', detail:gsb.threat?gsb.threat_type||'Tehdit':'Güvenli', penalty:50 },
    { key:'abuseipdb', icon:'📊', name:'AbuseIPDB (Local)', data:aipdb, isBad:(aipdb.abuse_score||0)>=30, isClean:aipdb.available&&(aipdb.abuse_score||0)<30, badLabel:`${aipdb.abuse_score||0}%`, cleanLabel:'CLEAN', detail:aipdb.available?`Suistimal: %${aipdb.abuse_score||0}`:'Sonuç yok', penalty:25 },
    { key:'screenshot', icon:'📸', name:'Screenshot Analyzer', data:sa, isBad:(sa.risk_score||0)>50, isClean:sa.available&&(sa.risk_score||0)<=30, badLabel:sa.risk_level||'HIGH', cleanLabel:'SAFE', detail:(!sa.available&&screenshotB64)?'Screenshot alındı (AI analizi devre dışı)':(sa.verdict||'Analiz yok'), penalty:sa.available?Math.round((sa.risk_score||50)*0.6):0, hasDataOverride: !!screenshotB64 || !!sa.verdict, badgeOverride: (!sa.available&&screenshotB64)?'CAPTURED':null },
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
              <span style={{position:'absolute',bottom:6,right:6,padding:'3px 8px',borderRadius:6,fontSize:9,fontWeight:700,background:'rgba(0,0,0,0.7)',color:theme.primary,letterSpacing:0.5}}>🔍 BÜYÜT</span>
            </motion.div>
          )}
        </div>
        {/* Right: Details */}
        <div style={{flex:1,minWidth:300}}>
          <p style={{fontSize:14,color:theme.textMuted,wordBreak:'break-all',marginBottom:16,fontFamily:theme.mono,lineHeight:1.6}}>{url}</p>
          {result.details&&Array.isArray(result.details)&&result.details.length>0&&(
            <div style={{marginBottom:16}}>
              <p style={{fontSize:12,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'1.5px',marginBottom:10}}>🔍 Tespitler</p>
              <div style={{display:'flex',flexDirection:'column',gap:6,maxHeight:200,overflowY:'auto'}}>
                {result.details.slice(0,10).map((d,i)=>{
                  const isDanger=d.includes('🚨')||d.includes('❌')
                  const isWarn=d.includes('⚠️')
                  return <motion.div key={i} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.1+i*0.03,duration:0.3}} style={{padding:'8px 14px',background:isDanger?'rgba(255,0,64,0.08)':isWarn?'rgba(255,193,7,0.08)':theme.primaryDim,borderRadius:10,fontSize:13,color:theme.text,lineHeight:1.5,borderLeft:isDanger?`3px solid ${theme.accent}`:isWarn?`3px solid ${theme.warning}`:`3px solid ${theme.primary}`}}>{d}</motion.div>
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
      <p style={{fontSize:13,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'2px',marginBottom:16}}>📡 Tehdit İstihbaratı Kaynakları</p>
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
                <span style={{fontSize:14,fontWeight:700,color:'#fff',display:'flex',alignItems:'center',gap:6}}><span>{src.icon}</span> {src.name}</span>
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
        <p style={{fontSize:13,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'2px',marginBottom:16}}>🧩 Görsel Tehdit İndikatörleri</p>
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill, minmax(280px, 1fr))',gap:10}}>
          {indicators.map((ind,j)=>{
            const t=ind.type||'visual'
            const ic=t==='url'?'🔗':t==='domain'?'🌐':t==='ip'?'🖥️':'👁️'
            return (
              <motion.div key={j} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.6+j*0.05,duration:0.3}} style={{padding:'12px 16px',background:'rgba(255,107,53,0.06)',border:`1px solid ${theme.accent}30`,borderRadius:theme.radius.md,borderLeft:`3px solid ${theme.accent}`}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <span style={{fontSize:14}}>{ic}</span>
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
        <p style={{fontSize:13,fontWeight:700,color:theme.textMuted,textTransform:'uppercase',letterSpacing:'2px',marginBottom:16}}>📋 Taranan Kaynaklar</p>
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
function PhishingDetector() {
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
  const [showScoringDiagram, setShowScoringDiagram] = useState(false)

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
      const r = await fetch(`${API}/phishing/scan-history?limit=20&page=${p}`)
      if(!r.ok) throw new Error('Tarama gecmisi alınamadı')
      const d = await r.json()
      const items = d.data || d.history || []
      setScanHistory(items.filter(item => item?.url))
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

  async function handleCheck(forceFreshOrEvent = false) {
    // Event handler olarak kullanıldığında (onClick), React event object gelir - ignore et
    const forceFresh = typeof forceFreshOrEvent === 'boolean' ? forceFreshOrEvent : false
    if(!url){showToast('Lutfen bir URL girin','error');return}
    setChecking(true);setResult(null);setJobId(null);setAnalyzing(false);setPollCount(0);setShowRetryButton(false)
    try{
      const normalizedInput = /^https?:\/\//i.test(url) ? url : `https://${url}`
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
        padding:'120px 24px 80px',
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
          <span style={{ display:'inline-block', padding:'10px 24px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'30px', fontSize:13, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'3px', marginBottom:24 }}>Phishing Dedektoru</span>
          <h1 style={{ fontSize:56, fontWeight:800, color:'#fff', marginBottom:20, letterSpacing:'-2px', lineHeight:1.1 }}>URL Guvenlik Tarama Motoru</h1>
          <p style={{ color:theme.textMuted, fontSize:18, maxWidth:700, margin:'0 auto', lineHeight:1.6 }}>{totalUrls.toLocaleString('tr-TR')}+ phishing URL veritabani ile anlik guvenlik kontrolu. Aninda sonuc, detayli rapor.</p>
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
            <div style={{ display:'flex', gap:12 }}>
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
                {checking?'Taranıyor...':'🔍 Tara'}
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
              margin:'48px auto 0',
              background:'rgba(255,255,255,0.03)',
              backdropFilter:'blur(10px)',
              WebkitBackdropFilter:'blur(10px)',
              borderRadius:theme.radius.lg,
              padding:24,
              border:`1px solid ${theme.border}`
            }}
          >
            <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>📋 Son Taranan URL'ler</h3>
            <div style={{ display:'flex', flexWrap:'wrap', gap:10 }}>
              {scanHistory.slice(0, 8).map((item, i) => (
                <motion.button
                  key={i}
                  initial={{ opacity:0, scale:0.9 }}
                  animate={{ opacity:1, scale:1 }}
                  transition={{ delay:0.7 + i * 0.05, duration:0.3 }}
                  onClick={() => {
                    setUrl(item.url)
                    setTimeout(() => handleCheck(), 100)
                  }}
                  style={{ 
                    padding:'8px 16px', 
                    borderRadius:'20px', 
                    border:`1px solid ${theme.border}`, 
                    background:'rgba(255,255,255,0.05)', 
                    cursor:'pointer', 
                    fontSize:12, 
                    color:theme.primary, 
                    fontFamily:theme.mono,
                    maxWidth:220,
                    overflow:'hidden',
                    textOverflow:'ellipsis',
                    whiteSpace:'nowrap',
                    transition:'all 0.3s ease'
                  }}
                  whileHover={{ background:'rgba(0,212,255,0.15)', borderColor:theme.primary, transform:'translateY(-2px)' }}
                >
                  {item.url}
                </motion.button>
              ))}
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>

    {/* C1: Derin Analiz Progress Bar */}
    <AnimatePresence>
      {analyzing && (
        <motion.div
          initial={{ opacity:0, y:-10 }}
          animate={{ opacity:1, y:0 }}
          exit={{ opacity:0, y:-10 }}
          transition={{ duration:0.3, ease:theme.ease.out }}
          style={{
            maxWidth:900,
            margin:'0 auto 24px',
            padding:'16px 24px',
            background:'rgba(0,212,255,0.06)',
            border:`1px solid ${theme.primary}40`,
            borderRadius:theme.radius.md,
            display:'flex',
            alignItems:'center',
            gap:16
          }}
        >
          <motion.span
            animate={{ rotate:360 }}
            transition={{ repeat:Infinity, duration:1.5, ease:'linear' }}
            style={{ fontSize:22, flexShrink:0 }}
          >🔍</motion.span>
          <div style={{ flex:1, minWidth:0 }}>
            <p style={{ margin:'0 0 4px', fontSize:14, fontWeight:700, color:theme.primary }}>
              Derin Analiz Devam Ediyor...
            </p>
            <p style={{ margin:'0 0 10px', fontSize:12, color:theme.textMuted }}>
              Playwright screenshot + AI analizi ({Math.round(pollCount * 3)}s)
            </p>
            <div style={{ height:4, background:theme.border, borderRadius:2, overflow:'hidden' }}>
              <motion.div
                animate={{ width:`${Math.min((pollCount/MAX_POLLS)*100, 95)}%` }}
                transition={{ duration:0.5 }}
                style={{ height:'100%', background:theme.gradientPrimary, borderRadius:2 }}
              />
            </div>
          </div>
        </motion.div>
      )}
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
    {/* Scoring Pipeline Diagram */}
    <motion.div
      initial={{ opacity:0, y:16 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.65, duration:0.5 }}
      style={{ marginBottom:32 }}
    >
      <button
        onClick={() => setShowScoringDiagram(v => !v)}
        style={{
          width:'100%', padding:'12px 20px',
          background: showScoringDiagram ? theme.primaryDim : theme.surface,
          border:`1px solid ${showScoringDiagram ? theme.primary+'55' : theme.border}`,
          borderRadius:12, cursor:'pointer', display:'flex', alignItems:'center', gap:12,
          transition:'all 0.2s', marginBottom: showScoringDiagram ? 12 : 0,
        }}
      >
        <Activity size={16} color={theme.primary} />
        <span style={{ fontSize:13, fontWeight:700, color: showScoringDiagram ? theme.primary : theme.textMuted }}>Puanlama Motoru — Nasıl Çalışır?</span>
        <span style={{ marginLeft:'auto', fontSize:11, color:theme.textMuted }}>{showScoringDiagram ? '▲ Kapat' : '▼ Göster'}</span>
      </button>
      <AnimatePresence>
        {showScoringDiagram && (
          <motion.div
            initial={{ opacity:0, height:0 }}
            animate={{ opacity:1, height:'auto' }}
            exit={{ opacity:0, height:0 }}
            transition={{ duration:0.3 }}
            style={{ overflow:'hidden' }}
          >
            <ScoringPipelineDiagram />
          </motion.div>
        )}
      </AnimatePresence>
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
  phishing: '🎣',
  smishing: '📱',
  vishing: '📞',
  social_engineering: '🎭',
  malware_assisted: '🦠',
  sahte_mobil_uygulama: '📲',
  banka_taklit: '🏦',
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
  bank_account: '🏧',
  social_media: '📸',
  ecommerce: '📦',
  corporate_account: '🏢',
  crypto_wallet: '₿',
  device_compromise: '💻',
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

  useEffect(() => {
    document.body.style.overflow = 'hidden'
    fetch(`${API}/victim-atlas/cases/${c.id}`).then(r=>r.json()).then(d=>setDetail(d.data||null)).catch(()=>{})
    return () => { document.body.style.overflow = '' }
  }, [c.id])

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
    { id:'ozet', label:'📋 Özet' },
    { id:'korunma', label:'🛡️ Korunma' },
    { id:'yorumlar', label:'💬 Yorumlar' },
    { id:'benzer', label:'🔗 Benzer' },
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
              <button key={t.id} onClick={()=>setTab(t.id)} style={{ padding:'10px 18px', background:'none', border:'none', cursor:'pointer', fontSize:13, fontWeight:600, color: tab===t.id?theme.primary:theme.textMuted, borderBottom: tab===t.id?`2px solid ${theme.primary}`:'2px solid transparent', transition:'all 0.2s' }}>{t.label}</button>
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
                <span style={{ fontSize:20 }}>⚠️</span>
                <p style={{ color:theme.warning, fontWeight:600, fontSize:14, margin:0, lineHeight:1.6 }}>{c.critical_warning}</p>
              </div>
              {/* Güven & Platform */}
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12, marginBottom:20 }}>
                {[
                  { label:'Güven Skoru', value:`${c.confidence_score}%`, color:theme.primary },
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

function VictimAtlas() {
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
              <div style={{ fontSize:28, lineHeight:1 }}>{ATTACK_ICONS[c.attack_method] || '⚠️'}</div>
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
                <span style={{ fontSize:11, color:theme.textMuted }}>Güven: {c.confidence_score}%</span>
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

function HoneypotIOC() {
  const [iocStats, setIocStats] = useState(null)
  const [iocList, setIocList] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searching, setSearching] = useState(false)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })
  const [showDropdown, setShowDropdown] = useState(false)
  const [exportingSTIX, setExportingSTIX] = useState(false)
  const searchTimeoutRef = useRef(null)

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
function BreachIntel() {
  const [email, setEmail] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  async function handleCheck() {
    if(!email||!email.includes('@')){showToast('Geçerli bir e-posta adresi girin','error');return}
    setChecking(true);setResult(null)
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
        
        <div style={{ display:'flex', gap:12, marginBottom:8 }}>
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
          <button 
            onClick={handleCheck} 
            disabled={!email||!email.includes('@')||checking}
            style={{
              padding:'18px 40px',
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
            {checking?'Taranıyor...':'Sorgula'}
          </button>
        </div>
        {result&&<div style={{ animation:'scaleIn 0.4s ease', marginTop:32 }}>
          {result.status==='error'?<div style={{ textAlign:'center', padding:32, background:theme.bg, borderRadius:theme.radius, border:`1px solid ${theme.border}` }}>
            <span style={{ fontSize:64, display:'block', marginBottom:16 }}>⚠️</span>
            <p style={{ color:theme.warning, fontSize:18, fontWeight:700, marginBottom:8 }}>{result.message}</p>
            <p style={{ color:theme.textMuted, fontSize:14 }}>{result.hint}</p>
          </div>
          :result.breached?<>
            <div style={{ textAlign:'center', marginBottom:24 }}>
              <span style={{ fontSize:64 }}>🚨</span>
              <p style={{ color:theme.danger, fontSize:28, fontWeight:800, marginTop:16 }}>Sızıntı Tespit Edildi!</p>
              <p style={{ color:theme.textMuted, fontSize:16, marginTop:8 }}>{result.breach_count} olayda verileriniz sızdırılmış</p>
            </div>
            
            {result.turkish_summary&&<div style={{ padding:20, background:theme.warning+'22', borderRadius:theme.radius, marginBottom:24, borderLeft:`4px solid ${theme.warning}` }}>
              <p style={{ fontSize:16, lineHeight:1.8, color:theme.text, fontWeight:500 }}>{result.turkish_summary}</p>
            </div>}
            
            {result.shantaj_risk_analysis&&<div style={{ padding:24, background:theme.accentDim, borderRadius:theme.radius, marginBottom:24, border:`1px solid ${theme.accent}33` }}>
              <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:16 }}>
                <span style={{ fontSize:32 }}>⚡</span>
                <div>
                  <p style={{ fontSize:18, fontWeight:700, color:'#fff' }}>Şantaj Risk Analizi</p>
                  <p style={{ fontSize:14, color:theme.textMuted }}>AI destekli risk değerlendirmesi</p>
                </div>
                <div style={{ marginLeft:'auto', textAlign:'right' }}>
                  <p style={{ fontSize:36, fontWeight:800, color:theme.danger }}>{result.shantaj_risk_analysis.shantaj_risk_score}</p>
                  <p style={{ fontSize:12, color:theme.textMuted, textTransform:'uppercase' }}>/100</p>
                </div>
              </div>
              <div style={{ display:'flex', gap:8, marginBottom:16 }}>
                <span style={{ padding:'6px 16px', borderRadius:'20px', fontSize:13, fontWeight:700, background:theme.danger, color:'#fff' }}>{result.shantaj_risk_analysis.risk_level}</span>
              </div>
              {result.shantaj_risk_analysis.risk_factors&&<div>
                <p style={{ fontSize:13, fontWeight:600, color:theme.textMuted, marginBottom:12, textTransform:'uppercase', letterSpacing:'1px' }}>Risk Faktörleri</p>
                <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:8 }}>
                  {result.shantaj_risk_analysis.risk_factors.slice(0,4).map((rf,i)=><div key={i} style={{ padding:'12px 16px', background:theme.bg, borderRadius:theme.radiusSm, display:'flex', gap:8, alignItems:'center' }}>
                    <span style={{ fontSize:18 }}>⚠️</span>
                    <p style={{ fontSize:14, color:theme.text }}>{rf}</p>
                  </div>)}
                </div>
              </div>}
            </div>}
            
            <div style={{ marginBottom:24 }}>
              <p style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', alignItems:'center', gap:8 }}><span style={{ fontSize:24 }}>📊</span> Sızıntı Detayları</p>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(300px, 1fr))', gap:16 }}>
                {(result.breaches||[]).map((b,i)=><div key={i} style={{ padding:20, background:theme.surface2, borderRadius:theme.radius, border:`1px solid ${theme.border}`, transition:'all 0.3s ease' }} onMouseEnter={e=>e.currentTarget.style.borderColor=theme.accent} onMouseLeave={e=>e.currentTarget.style.borderColor=theme.border}>
                  <div style={{ display:'flex', alignItems:'flex-start', gap:12, marginBottom:12 }}>
                    <div style={{ width:48, height:48, borderRadius:'12px', background:theme.bg, display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0, overflow:'hidden' }}>
                      {b.domain ? (
                        <img 
                          src={`https://www.google.com/s2/favicons?domain=${b.domain}&sz=64`} 
                          alt={b.domain}
                          style={{ width:32, height:32 }}
                          onError={e=>e.currentTarget.style.display='none'}
                        />
                      ) : (
                        <span style={{ fontSize:24 }}>🔓</span>
                      )}
                    </div>
                    <div style={{ flex:1 }}>
                      <p style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:4 }}>{b.title||b.name||'Bilinmeyen'}</p>
                      <p style={{ fontSize:13, color:theme.textMuted }}>{b.breach_date?new Date(b.breach_date).toLocaleDateString('tr-TR'):''}</p>
                      {b.domain && <p style={{ fontSize:11, color:theme.primary, marginTop:2 }}>{b.domain}</p>}
                    </div>
                  </div>
                  <div style={{ padding:12, background:theme.bg, borderRadius:theme.radiusSm }}>
                    <p style={{ fontSize:12, fontWeight:600, color:theme.textMuted, marginBottom:8, textTransform:'uppercase', letterSpacing:'0.5px' }}>Sızan Veriler</p>
                    <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
                      {(b.data_classes||[]).map((dc,di)=><span key={di} style={{ padding:'4px 12px', borderRadius:'12px', fontSize:12, background:theme.primaryDim, color:theme.primary }}>{dc}</span>)}
                    </div>
                  </div>
                </div>)}
              </div>
            </div>
            
            {result.kvkk_report&&<div style={{ padding:24, background:theme.primaryDim, borderRadius:theme.radius, border:`1px solid ${theme.primary}33` }}>
              <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:16 }}>
                <div style={{ width:48, height:48, borderRadius:'12px', background:theme.primary+'33', display:'flex', alignItems:'center', justifyContent:'center' }}>
                  <span style={{ fontSize:24 }}>📄</span>
                </div>
                <div>
                  <p style={{ fontSize:18, fontWeight:700, color:'#fff' }}>KVKK Başvuru Raporu</p>
                  <p style={{ fontSize:14, color:theme.textMuted }}>Otomatik oluşturulmuş başvuru belgesi</p>
                </div>
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(200px, 1fr))', gap:16 }}>
                <div style={{ padding:16, background:theme.bg, borderRadius:theme.radiusSm }}>
                  <p style={{ fontSize:12, color:theme.textMuted, marginBottom:4 }}>Rapor ID</p>
                  <p style={{ fontSize:16, fontWeight:700, color:'#fff', fontFamily:theme.mono }}>{result.kvkk_report.report_id}</p>
                </div>
                <div style={{ padding:16, background:theme.bg, borderRadius:theme.radiusSm }}>
                  <p style={{ fontSize:12, color:theme.textMuted, marginBottom:4 }}>Başvuru</p>
                  <a href="https://www.kvkk.gov.tr" target="_blank" style={{ fontSize:16, fontWeight:700, color:theme.primary, textDecoration:'none' }}>kvkk.gov.tr</a>
                </div>
              </div>
            </div>}
          </>
          :<div style={{ textAlign:'center', padding:48, background:theme.bg, borderRadius:theme.radius, border:`1px solid ${theme.border}` }}>
            <span style={{ fontSize:80 }}>✅</span>
            <p style={{ color:theme.success, fontSize:28, fontWeight:800, marginTop:20 }}>Sızıntı Bulunamadı</p>
            <p style={{ color:theme.textMuted, fontSize:16, marginTop:8 }}>{email} adresi bilinen sızıntılarda yok</p>
          </div>}
        </div>}
      </Card>
    </div>

    {/* Post-Breach Intervention - Only section below */}
    <div style={{ maxWidth:900, margin:'0 auto 48px' }}>
      <Card style={{ padding:40, background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})` }}>
        <div style={{ display:'flex', alignItems:'center', gap:16, marginBottom:24 }}>
          <div style={{ width:64, height:64, borderRadius:'16px', background:theme.warning+'22', display:'flex', alignItems:'center', justifyContent:'center' }}>
            <span style={{ fontSize:32 }}>🚨</span>
          </div>
          <div>
            <h2 style={{ fontSize:24, fontWeight:700, color:'#fff', marginBottom:4 }}>Sızıntı Sonrası Müdahale</h2>
            <p style={{ color:theme.textMuted, fontSize:14 }}>Adım adım eylem planı</p>
          </div>
        </div>
        
        <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:16 }}>
          {[
            {step:'01',icon:'😌',title:'Panik Yapmayın',desc:'Sakin olun ve adım adım ilerleyin'},
            {step:'02',icon:'🔑',title:'Şifrenizi Hemen Değiştirin',desc:'Sızdırılan platformdaki şifrenizi yenileyin'},
            {step:'03',icon:'🔄',title:'Tüm Platformları Güncelleyin',desc:'Aynı şifreyi kullandığınız yerleri değiştirin'},
            {step:'04',icon:'🔐',title:'2FA Aktifleştirin',desc:'Tüm kritik hesaplarda 2FA açın'},
            {step:'05',icon:'🔍',title:'Hesap Aktivitesini Kontrol Edin',desc:'Şüpheli girişleri inceleyin'},
            {step:'06',icon:'📊',title:'İzlemeye Devam Edin',desc:'Bu modül ile düzenli kontrol yapın'}
          ].map((item,i)=><div key={i} style={{ padding:20, background:theme.bg, borderRadius:theme.radius, border:`1px solid ${theme.border}`, transition:'all 0.3s ease' }} onMouseEnter={e=>e.currentTarget.style.borderColor=theme.warning} onMouseLeave={e=>e.currentTarget.style.borderColor=theme.border}>
            <div style={{ display:'flex', alignItems:'center', gap:12, marginBottom:12 }}>
              <div style={{ width:40, height:40, borderRadius:'12px', background:theme.warning+'22', display:'flex', alignItems:'center', justifyContent:'center', flexShrink:0 }}>
                <span style={{ fontSize:20 }}>{item.icon}</span>
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
