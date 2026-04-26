import { useState, useEffect, useRef, useCallback } from 'react'
import { motion, useReducedMotion, AnimatePresence } from 'framer-motion'

const API = import.meta.env.VITE_API_BASE_URL || '/api/v2'

function normalizeStatus(status) {
  const s = String(status || '').toLowerCase()
  return s === 'active' || s === 'online'
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
      {page==='ai-analyzer' && <AIAnalyzer />}
      {page==='phishing-detector' && <PhishingDetector />}
      {page==='victim-atlas' && <VictimAtlas />}
      {page==='honeypot' && <HoneypotIOC />}
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
function AIAnalyzer() {
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

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast} />
    <SectionHeader badge="AI Analiz Modulu" title="Yapay Zeka ile Guvenlik Analizi" subtitle="Mesaj, e-posta veya metinlerinizi AI ile analiz edin. Phishing, sosyal muhendislik ve kotu amacli icerikleri tespit edin." />
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}>
      <Card style={{ animation:'slideInLeft 0.5s ease' }}>
        <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📝</span> Analiz Edilecek Metin</h3>
        <div style={{ display:'flex', gap:8, marginBottom:16, flexWrap:'wrap' }}>
          {[{id:'email',label:'📧 E-posta'},{id:'sms',label:'💬 SMS'},{id:'whatsapp',label:'📱 WhatsApp'},{id:'social_media',label:'🌐 Sosyal Medya'}].map(c=>
            <button key={c.id} onClick={()=>setContext(c.id)} style={{ padding:'6px 14px', borderRadius:'20px', border:'1px solid', cursor:'pointer', fontSize:12, fontWeight:600, background:context===c.id?theme.primary:'transparent', borderColor:context===c.id?theme.primary:theme.border, color:context===c.id?'#000':theme.textMuted, transition:'all 0.2s' }}>{c.label}</button>
          )}
        </div>
        <textarea value={message} onChange={e=>setMessage(e.target.value)} placeholder="Analiz edilecek metni buraya yapistirin veya yazin..." rows={8} style={{ width:'100%', padding:16, borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:theme.text, fontSize:14, resize:'vertical', outline:'none', lineHeight:1.6 }} />
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:12 }}>
          <span style={{ fontSize:12, color:theme.textMuted }}>{message.length} karakter</span>
          <GlowButton onClick={handleAnalyze} loading={analyzing} disabled={message.length<10}>{analyzing?'Analiz Ediliyor...':'🔍 Analiz Et'}</GlowButton>
        </div>
        <div style={{ marginTop:24 }}>
          <p style={{ fontSize:12, color:theme.textMuted, fontWeight:600, marginBottom:8, textTransform:'uppercase', letterSpacing:'1px' }}>Ornek Metinler</p>
          {examples.map((ex,i)=><button key={i} onClick={()=>setMessage(ex.text)} style={{ padding:'10px 14px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, cursor:'pointer', textAlign:'left', fontSize:12, color:theme.textMuted, lineHeight:1.4, transition:'all 0.2s', display:'block', width:'100%', marginBottom:8 }}
            onMouseEnter={e=>{e.currentTarget.style.borderColor=theme.primary+'44';e.currentTarget.style.background=theme.surface2}}
            onMouseLeave={e=>{e.currentTarget.style.borderColor=theme.border;e.currentTarget.style.background=theme.surface}}>
            <span style={{ color:theme.primary, fontWeight:600, fontSize:11 }}>{ex.label}</span><br/>{ex.text.substring(0,70)}...
          </button>)}
        </div>
      </Card>
      <Card ref={resultRef} style={{ animation:'slideInRight 0.5s ease' }}>
        <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📊</span> Analiz Sonuclari</h3>
        {!result&&!analyzing&&<div style={{ textAlign:'center', padding:'60px 20px', color:theme.textMuted }}><span style={{ fontSize:48, display:'block', marginBottom:16 }}>🔍</span><p style={{ fontSize:14 }}>Henuz analiz yapilmadi</p><p style={{ fontSize:12, marginTop:8 }}>Sol taraftaki metni girin ve "Analiz Et" butonuna tiklayin</p></div>}
        {analyzing&&<div style={{ textAlign:'center', padding:'60px 20px' }}><Spinner size={40}/><p style={{ marginTop:16, color:theme.textMuted, fontSize:14 }}>AI analiz ediyor...</p></div>}
        {result&&<ResultContent score={score} threatLevel={sa.threat_level||'medium'} isPhishing={isPhishing} isScam={isScam} sa={sa} da={da} recs={recs} beliefs={beliefs} threats={threats} suspects={suspects} result={result} />}
      </Card>
    </div>
    <Card style={{ marginBottom:48 }}>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📜</span> Son Analizler</h3>
      {history.length===0?<p style={{ color:theme.textMuted, fontSize:13, textAlign:'center', padding:20 }}>Henuz analiz yapilmadi</p>:
      <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
        {history.map(h=><div key={h.id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'12px 16px', background:theme.surface, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
          <div style={{ flex:1, overflow:'hidden' }}><p style={{ fontSize:13, color:'#fff', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>{h.url||h.message||h.text}</p><p style={{ fontSize:11, color:theme.textMuted, marginTop:2 }}>{h.created_at?new Date(h.created_at).toLocaleString('tr-TR'):''}</p></div>
          <RiskBadge level={h.risk_level||h.threat_level||'safe'} />
        </div>)}
      </div>}
    </Card>
  </div>
}

function ResultContent({ score, threatLevel, isPhishing, isScam, sa, da, recs, beliefs, threats, suspects, result }) {
  const confidence = da?.ai_analysis?.confidence_score || 0
  const confidencePercentage = Math.round(confidence)
  const confidenceColor = confidence > 75 ? theme.danger : confidence > 50 ? theme.warning : confidence > 25 ? theme.primary : theme.success

  return <div style={{ animation:'scaleIn 0.3s ease' }}>
    <div style={{ display:'flex', gap:24, alignItems:'center', marginBottom:20, flexWrap:'wrap' }}>
      <RiskGauge score={score} label="Risk Skoru" />
      <div style={{ flex:1 }}>
        <div style={{ display:'flex', gap:12, flexWrap:'wrap', marginBottom:12 }}>
          <RiskBadge level={threatLevel} size="md" />
          <span style={{ padding:'6px 16px', borderRadius:'20px', fontSize:13, fontWeight:700, background:isPhishing?theme.accentDim:theme.primaryDim, color:isPhishing?theme.accent:theme.primary }}>{isPhishing?'⚠️ Phishing':'✅ Guvenli'}</span>
          {isScam&&<span style={{ padding:'6px 16px', borderRadius:'20px', fontSize:13, fontWeight:700, background:theme.accentDim, color:theme.accent }}>🛑 Scam</span>}
        </div>
        <p style={{ fontSize:13, color:theme.textMuted }}>Guvenlik Durumu: <strong style={{ color:score>70?'#ef4444':score>40?'#f59e0b':'#22c55e' }}>{sa.safety_status||'Bilinmiyor'}</strong> • Aksiyon: {sa.action_required||'YOK'}</p>
        <div style={{ marginTop:12, padding:12, background:theme.surface, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
            <span style={{ fontSize:12, fontWeight:700, color:theme.textMuted }}>🤖 AI Guvenilirlik Skoru</span>
            <span style={{ fontSize:14, fontWeight:800, color:confidenceColor }}>{confidencePercentage}%</span>
          </div>
          <div style={{ width:'100%', height:8, background:theme.bg, borderRadius:4, overflow:'hidden' }}>
            <div style={{ width:`${confidencePercentage}%`, height:'100%', background:confidenceColor, borderRadius:4, transition:'width 0.5s ease' }} />
          </div>
          <p style={{ fontSize:11, color:theme.textMuted, marginTop:6 }}>Yapay zeka modeli bu analizi %{confidencePercentage} guvenilirlik ile tamamladi.</p>
        </div>
      </div>
    </div>
    {result.summary&&<Card style={{ padding:16, marginBottom:16, maxHeight:120, overflowY:'auto' }}><p style={{ fontSize:13, lineHeight:1.6, color:theme.textDim, whiteSpace:'pre-wrap' }}>{result.summary}</p></Card>}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginBottom:20 }}>
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}><p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🚨 Tespit Edilen Tehditler</p>
        {threats.length>0?threats.map((t,i)=><div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.accentDim, borderRadius:6, borderLeft:`3px solid ${theme.accent}`, fontSize:12, color:theme.text }}>{t}</div>):<p style={{ fontSize:12, color:theme.textMuted }}>Tehdit tespit edilmedi</p>}
      </Card>
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}><p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🧠 Psikolojik Tetikleyiciler</p>
        {beliefs.length>0?beliefs.map((b,i)=><div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.warning+'22', borderRadius:6, borderLeft:`3px solid ${theme.warning}`, fontSize:12, color:theme.text }}>⚠️ {b}</div>):<p style={{ fontSize:12, color:theme.textMuted }}>Tetikleyici tespit edilmedi</p>}
      </Card>
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}><p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🔍 Supheli Ogeler</p>
        {suspects.length>0?suspects.map((s,i)=><div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.primaryDim, borderRadius:6, borderLeft:`3px solid ${theme.primary}`, fontSize:12, color:theme.text }}>• {s}</div>):<p style={{ fontSize:12, color:theme.textMuted }}>Supheli oge yok</p>}
      </Card>
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}><p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🔗 URL Analizi</p>
        {da?.url_analysis?.length>0?da.url_analysis.map((u,i)=><div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.primaryDim, borderRadius:6, fontSize:12, color:theme.text }}><p style={{ wordBreak:'break-all' }}>{u.url||u}</p><span style={{ fontSize:11, color:theme.textMuted }}>Risk: {u.risk_score||'N/A'}</span></div>):<p style={{ fontSize:12, color:theme.textMuted }}>URL bulunamadi</p>}
      </Card>
    </div>
    {recs.length>0&&<div style={{ marginBottom:16 }}><p style={{ fontSize:14, fontWeight:700, color:'#fff', marginBottom:12 }}>💡 Oneriler</p>
      <div style={{ display:'flex', flexDirection:'column', gap:8, maxHeight:300, overflowY:'auto' }}>
        {recs.map((rec,i)=><div key={i} style={{ padding:'12px 14px', background:theme.primaryDim, borderRadius:theme.radiusSm, borderLeft:`3px solid ${theme.primary}`, fontSize:13, lineHeight:1.5 }}>{rec.description||rec.message||(typeof rec==='string'?rec:JSON.stringify(rec))}</div>)}
      </div>
    </div>}
  </div>
}

function RiskGauge({ score, label, showPercentage = false }) {
  const c=2*Math.PI*40;const o=c-(Math.min(score,100)/100)*c
  const color=score>75?theme.danger:score>50?theme.warning:score>25?theme.primary:theme.success
  const percentage = Math.round(score)
  return <div style={{ display:'inline-flex', flexDirection:'column', alignItems:'center' }}>
    <svg width="120" height="120" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="none" stroke={theme.border} strokeWidth="8"/><circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8" strokeDasharray={c} strokeDashoffset={o} transform="rotate(-90 50 50)" style={{ transition:'stroke-dashoffset 1s ease' }} strokeLinecap="round"/><text x="50" y="50" textAnchor="middle" dominantBaseline="central" fill="#fff" fontSize="22" fontWeight="800" fontFamily="Inter, sans-serif">{showPercentage?`${percentage}%`:score}</text></svg>
    <p style={{ fontSize:12, color:theme.textMuted, marginTop:8, fontWeight:600 }}>{label}</p>
  </div>
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
    if (url.length < 3) {
      setSearchResults([])
      setShowDropdown(false)
      return
    }
    
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
      } catch (e) {
        setSearchResults([])
        setShowDropdown(false)
      }
    }, 300)
    
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [url])

  async function handleCheck() {
    if(!url){showToast('Lutfen bir URL girin','error');return}
    setChecking(true);setResult(null)
    try{
      const normalizedInput = /^https?:\/\//i.test(url) ? url : `https://${url}`
      new URL(normalizedInput)
      const r=await fetch(`${API}/phishing/check-url`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url: normalizedInput})})
      if(!r.ok)throw new Error(`URL kontrol hatasi (${r.status})`)
      const d=await r.json();setResult(d)
      loadScanHistory(1)
    }catch(e){showToast('URL kontrol hatasi: '+e.message,'error')}
    setChecking(false)
  }

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
          <span style={{ display:'inline-block', padding:'10px 24px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'30px', fontSize:13, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'3px', marginBottom:24 }}>Phishing Dedektoru</span>
          <h1 style={{ fontSize:56, fontWeight:800, color:'#fff', marginBottom:20, letterSpacing:'-2px', lineHeight:1.1 }}>URL Guvenlik Tarama Motoru</h1>
          <p style={{ color:theme.textMuted, fontSize:18, maxWidth:700, margin:'0 auto', lineHeight:1.6 }}>{totalUrls.toLocaleString('tr-TR')}+ phishing URL veritabani ile anlik guvenlik kontrolu. Aninda sonuc, detayli rapor.</p>
        </motion.div>

        {/* Search Section - Glassmorphism */}
        <motion.div 
          initial={{ opacity:0, y:30 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.4, duration:0.6, ease:theme.ease.out }}
          style={{ maxWidth:800, margin:'0 auto', position:'relative' }}
        >
          <div style={{ 
            background:'rgba(255,255,255,0.05)', 
            backdropFilter:'blur(20px)', 
            WebkitBackdropFilter:'blur(20px)',
            border:`1px solid ${theme.primary}33`,
            borderRadius:theme.radius.lg,
            padding:8,
            boxShadow:'0 8px 32px rgba(0,0,0,0.3)'
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
            
            {/* Autocomplete Dropdown */}
            <AnimatePresence>
              {showDropdown && searchResults.length > 0 && (
                <motion.div
                  initial={{ opacity:0, y:-10 }}
                  animate={{ opacity:1, y:0 }}
                  exit={{ opacity:0, y:-10 }}
                  transition={{ duration:0.2, ease:theme.ease.out }}
                  style={{
                    position:'absolute',
                    top:'100%',
                    left:0,
                    right:0,
                    marginTop:12,
                    background:'rgba(8,12,20,0.95)',
                    backdropFilter:'blur(20px)',
                    WebkitBackdropFilter:'blur(20px)',
                    borderRadius:theme.radius.md,
                    border:`1px solid ${theme.border}`,
                    maxHeight:350,
                    overflowY:'auto',
                    zIndex:100,
                    boxShadow:'0 8px 32px rgba(0,0,0,0.4)'
                  }}
                >
                  {searchResults.slice(0, 10).map((item, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity:0, x:-10 }}
                      animate={{ opacity:1, x:0 }}
                      transition={{ delay:i * 0.05, duration:0.2 }}
                      onClick={() => {
                        setUrl(item.url || '')
                        setShowDropdown(false)
                        setTimeout(() => handleCheck(), 100)
                      }}
                      style={{
                        padding:'14px 20px',
                        borderBottom:`1px solid ${theme.border}`,
                        cursor:'pointer',
                        transition:'background 0.2s ease'
                      }}
                      whileHover={{ background:'rgba(0,212,255,0.1)' }}
                    >
                      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                        <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:13, wordBreak:'break-all' }}>{item.url||'-'}</span>
                        <span style={{ padding:'6px 12px', borderRadius:'12px', fontSize:11, background:(item.risk_score||0)>50?theme.accentDim:theme.primaryDim, color:(item.risk_score||0)>50?theme.accent:theme.primary }}>{item.risk_level||'Bilinmiyor'}</span>
                      </div>
                      <div style={{ display:'flex', gap:20, fontSize:12, color:theme.textMuted }}>
                        <span>Risk: <span style={{ color:(item.risk_score||0)>50?theme.accent:theme.primary, fontWeight:600 }}>{item.risk_score||'-'}</span></span>
                        <span>Domain: {item.domain||'-'}</span>
                      </div>
                    </motion.div>
                  ))}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
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

    {/* Result Display */}
    {result && (
      <motion.div
        initial={{ opacity:0, y:30 }}
        animate={{ opacity:1, y:0 }}
        transition={{ duration:0.6, ease:theme.ease.out }}
        style={{ marginBottom:48 }}
      >
        <Card style={{ 
          background:'rgba(255,255,255,0.03)',
          backdropFilter:'blur(10px)',
          WebkitBackdropFilter:'blur(10px)',
          border:`1px solid ${theme.border}`
        }}>
          <div style={{ display:'flex', gap:32, alignItems:'flex-start', flexWrap:'wrap' }}>
            <RiskGauge score={result.score||0} label="Risk Skoru"/>
            <div style={{ flex:1, minWidth:300 }}>
              <div style={{ display:'flex', gap:12, flexWrap:'wrap', marginBottom:16 }}>
                <span style={{ padding:'8px 20px', borderRadius:'24px', fontSize:14, fontWeight:700, background:result.score>50?theme.accentDim:theme.primaryDim, color:result.score>50?theme.accent:theme.primary }}>{result.risk_level||'Bilinmiyor'}</span>
              </div>
              <p style={{ fontSize:14, color:theme.textMuted, wordBreak:'break-all', marginBottom:16, fontFamily:theme.mono, lineHeight:1.6 }}>{url}</p>
              {result.details&&Array.isArray(result.details)&&result.details.map((d,i)=><div key={i} style={{ padding:'10px 16px', marginBottom:8, background:theme.primaryDim, borderRadius:12, fontSize:14, color:theme.text, lineHeight:1.5 }}>• {d}</div>)}
              {result.sources&&Array.isArray(result.sources)&&result.sources.map((s,i)=><div key={i} style={{ padding:'10px 16px', marginBottom:8, background:theme.surface, borderRadius:12, fontSize:14, display:'flex', gap:10, alignItems:'center' }}><span style={{ color:theme.textMuted }}>Kaynak:</span><span style={{ color:'#fff', fontWeight:600 }}>{s.name}</span><span style={{ marginLeft:'auto', color:s.status?.includes('Başarısız')?theme.danger:theme.success }}>{s.status}</span></div>)}
            </div>
          </div>
        </Card>
      </motion.div>
    )}

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
   VICTIM ATLAS
   =============================================== */
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
  const [expanded, setExpanded] = useState({})
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
    return theme.primary
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
    }
    return labels[value] || value || 'Genel'
  }

  const methodDist = stats?.attack_method_distribution || {}
  const topMethods = Object.entries(methodDist).sort((a,b)=>b[1]-a[1]).slice(0,5)

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>
    <SectionHeader
      badge="Magduriyet Atlasi"
      title="Siber Magduriyet Arsivi"
      subtitle="Turkiye odakli dolandiricilik vakalarini modern kartvizitlerle incele. Karti cevirerek adim adim korunma planina gec."
    />

    <div style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:16, marginBottom:24 }}>
      <Card style={{ textAlign:'center', padding:'18px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', marginBottom:8 }}>Toplam Vaka</p><p style={{ fontSize:30, fontWeight:800, color:theme.primary }}><CountUp end={stats?.total_cases||0}/></p></Card>
      <Card style={{ textAlign:'center', padding:'18px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', marginBottom:8 }}>Hot Set</p><p style={{ fontSize:30, fontWeight:800, color:theme.accent }}><CountUp end={stats?.hot_cases||0}/></p></Card>
      <Card style={{ textAlign:'center', padding:'18px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', marginBottom:8 }}>Yuksek Guven</p><p style={{ fontSize:30, fontWeight:800, color:theme.success }}><CountUp end={stats?.high_confidence_cases||0}/></p></Card>
      <Card style={{ textAlign:'center', padding:'18px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', marginBottom:8 }}>Listelenen</p><p style={{ fontSize:30, fontWeight:800, color:theme.warning }}><CountUp end={total||0}/></p></Card>
    </div>

    {topMethods.length>0 && <Card style={{ marginBottom:20, padding:'14px 16px' }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', flexWrap:'wrap', gap:10 }}>
        <p style={{ fontSize:12, color:theme.textMuted, fontWeight:700, margin:0 }}>En sik gorulen dolandiricilik yontemleri</p>
        <div style={{ display:'flex', gap:8, flexWrap:'wrap' }}>
          {topMethods.map(([name,count])=><span key={name} style={{ padding:'6px 10px', borderRadius:'16px', fontSize:11, background:theme.primaryDim, border:`1px solid ${theme.primary}33`, color:theme.primary }}>{methodLabel(name)} • {count}</span>)}
        </div>
      </div>
    </Card>}

    <Card style={{ marginBottom:24, padding:16 }}>
      <div style={{ display:'flex', gap:8, flexWrap:'wrap', marginBottom:12 }}>
        {[
          { label:'Banka taklidi', method:'banka_taklit', loss:'bank_account' },
          { label:'Sahte mobil app', method:'sahte_mobil_uygulama', loss:'bank_account' },
          { label:'Sosyal medya ele gecirme', method:'phishing', loss:'social_media' },
          { label:'SMS oltalamasi', method:'smishing', loss:'' },
        ].map((preset)=>(
          <button
            key={preset.label}
            onClick={()=>{ setAttackMethod(preset.method); setLossType(preset.loss); setTimeout(()=>loadCases(1), 0) }}
            style={{ padding:'6px 12px', borderRadius:'20px', border:`1px solid ${theme.border}`, background:theme.surface, color:theme.text, fontSize:11, cursor:'pointer' }}
          >
            {preset.label}
          </button>
        ))}
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'2fr 1fr 1fr auto', gap:10 }}>
        <input value={query} onChange={e=>setQuery(e.target.value)} placeholder="Orn: sahte banka uygulamasi, kargo mesaji, hesap kapatildi..." style={{ padding:'12px 14px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', outline:'none' }} onKeyDown={e=>e.key==='Enter'&&loadCases(1)} />
        <select value={attackMethod} onChange={e=>setAttackMethod(e.target.value)} style={{ padding:'12px 10px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff' }}>
          <option value="">Tum yontemler</option>
          <option value="banka_taklit">Banka taklit senaryosu</option>
          <option value="sahte_mobil_uygulama">Sahte mobil uygulama</option>
          <option value="phishing">Phishing (oltalama)</option>
          <option value="smishing">Smishing (SMS)</option>
          <option value="vishing">Vishing (telefon)</option>
          <option value="social_engineering">Sosyal muhendislik</option>
          <option value="malware_assisted">Zararli yazilim destekli</option>
        </select>
        <select value={lossType} onChange={e=>setLossType(e.target.value)} style={{ padding:'12px 10px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff' }}>
          <option value="">Tum kayip tipleri</option>
          <option value="bank_account">Banka hesabi</option>
          <option value="social_media">Sosyal medya hesabi</option>
          <option value="ecommerce">E-ticaret</option>
          <option value="corporate_account">Kurumsal hesap</option>
          <option value="crypto_wallet">Kripto cuzdan</option>
          <option value="device_compromise">Cihaz ele gecirme</option>
        </select>
        <GlowButton onClick={()=>loadCases(1)} loading={loading}>Vakaları getir</GlowButton>
      </div>
    </Card>

    <div style={{ display:'grid', gridTemplateColumns:'repeat(3, minmax(0,1fr))', gap:20 }}>
      {cases.length===0 && <Card style={{ gridColumn:'1 / -1', textAlign:'center', color:theme.textMuted }}>{loading?'Vaka verileri yukleniyor...':'Filtreye uygun vaka bulunamadi'}</Card>}
      {cases.map((c, idx)=> {
        const isFlipped = expanded[c.id] === true
        return <div key={c.id} style={{ perspective:'2000px', minHeight:480 }}>
          <div style={{
            position:'relative',
            width:'100%',
            minHeight:480,
            transformStyle:'preserve-3d',
            transition:'transform 0.8s cubic-bezier(0.4, 0, 0.2, 1)',
            transform:isFlipped ? 'rotateY(180deg)' : 'rotateY(0deg)',
          }}>
            <div style={{
              position:'absolute',
              inset:0,
              backfaceVisibility:'hidden',
              background:`linear-gradient(145deg, ${theme.surface}, ${theme.surface2})`,
              border:`1px solid ${riskColor(c.severity_score)}66`,
              borderRadius:theme.radius,
              padding:24,
              boxShadow:isFlipped ? theme.cardShadowHover : theme.cardShadow,
              transition:'box-shadow 0.4s ease',
            }}>
              <div style={{ height:6, borderRadius:99, background:`linear-gradient(90deg, ${riskColor(c.severity_score)}, ${theme.primary})`, marginBottom:16, animation:'floatPulse 3s ease-in-out infinite' }} />
              <div style={{ display:'flex', justifyContent:'space-between', gap:8, marginBottom:12 }}>
                <span style={{ fontSize:12, color:theme.textMuted, fontWeight:600, textTransform:'uppercase', letterSpacing:'0.5px' }}>{methodLabel(c.attack_method)}</span>
                <span style={{ fontSize:12, color:riskColor(c.severity_score), fontWeight:800, padding:'4px 12px', background:riskColor(c.severity_score)+'22', borderRadius:'20px' }}>Risk {c.severity_score}/100</span>
              </div>
              <h4 style={{ fontSize:18, color:'#fff', marginBottom:10, lineHeight:1.4, fontWeight:700 }}>{c.case_title}</h4>
              <p style={{ fontSize:13, color:theme.textMuted, marginBottom:16 }}>{lossTypeLabel(c.loss_type)} • {platformLabel(c.target_platform)}</p>
              <div style={{ marginBottom:16 }}>
                <div style={{ display:'flex', justifyContent:'space-between', marginBottom:8 }}>
                  <span style={{ fontSize:12, color:theme.textMuted, fontWeight:600 }}>Güven Skoru</span>
                  <span style={{ fontSize:12, color:'#fff', fontWeight:800 }}>{c.confidence_score}%</span>
                </div>
                <div style={{ width:'100%', height:8, borderRadius:99, overflow:'hidden', background:theme.bg }}>
                  <div style={{ width:`${Math.max(4, Math.min(100, c.confidence_score||0))}%`, height:'100%', background:riskColor(c.confidence_score), borderRadius:99, transition:'width 1s ease' }} />
                </div>
              </div>
              <div style={{ padding:'14px 16px', borderRadius:theme.radiusSm, background:theme.surface, border:`1px solid ${theme.border}`, marginBottom:16 }}>
                <p style={{ fontSize:13, color:theme.warning, margin:0, fontWeight:700, marginBottom:6 }}>⚠️ Kritik Uyarı</p>
                <p style={{ fontSize:13, color:theme.text, margin:0, lineHeight:1.5 }}>{c.critical_warning}</p>
              </div>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:16 }}>
                <span style={{ fontSize:12, color:theme.textMuted }}>Kartı çevir ve korunma planını gör</span>
                <button onClick={()=>setExpanded(v=>({...v,[c.id]:true}))} style={{ padding:'12px 20px', borderRadius:theme.radiusSm, cursor:'pointer', border:`1px solid ${theme.primary}44`, background:theme.primaryDim, color:theme.primary, fontWeight:700, fontSize:13, transition:'all 0.3s ease' }} onMouseEnter={e=>{e.currentTarget.style.background=theme.primary+'33';e.currentTarget.style.transform='translateY(-2px)'}} onMouseLeave={e=>{e.currentTarget.style.background=theme.primaryDim;e.currentTarget.style.transform='none'}}>
                  Kartı Çevir →
                </button>
              </div>
            </div>
            <div style={{
              position:'absolute',
              inset:0,
              backfaceVisibility:'hidden',
              transform:'rotateY(180deg)',
              background:`linear-gradient(145deg, ${theme.surface2}, ${theme.surface})`,
              border:`1px solid ${theme.primary}66`,
              borderRadius:theme.radius,
              padding:24,
              boxShadow:theme.cardShadowHover,
              overflow:'auto',
            }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
                <p style={{ fontSize:14, color:theme.primary, fontWeight:700, margin:0 }}>🛡️ Korunma Planı</p>
                <button onClick={()=>setExpanded(v=>({...v,[c.id]:false}))} style={{ padding:'10px 16px', borderRadius:theme.radiusSm, cursor:'pointer', border:`1px solid ${theme.border}`, background:theme.bg, color:theme.text, fontWeight:600, fontSize:12, transition:'all 0.3s ease' }} onMouseEnter={e=>{e.currentTarget.style.borderColor=theme.primary+'44';e.currentTarget.style.color=theme.primary}} onMouseLeave={e=>{e.currentTarget.style.borderColor=theme.border;e.currentTarget.style.color=theme.text}}>
                  ← Ön Yüze Dön
                </button>
              </div>
              <VictimAtlasDefense caseId={c.id} compact />
            </div>
          </div>
        </div>
      })}
    </div>

    {totalPages>1 && <div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:20 }}>
      <button onClick={()=>loadCases(page-1)} disabled={page<=1||loading} style={{ padding:'8px 14px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:page<=1?theme.textMuted:'#fff', cursor:page<=1?'not-allowed':'pointer' }}>← Onceki</button>
      <span style={{ padding:'8px 14px', color:theme.textMuted }}>Sayfa {page} / {totalPages}</span>
      <button onClick={()=>loadCases(page+1)} disabled={page>=totalPages||loading} style={{ padding:'8px 14px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:page>=totalPages?theme.textMuted:'#fff', cursor:page>=totalPages?'not-allowed':'pointer' }}>Sonraki →</button>
    </div>}
  </div>
}

function VictimAtlasDefense({ caseId, compact = false }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)

  useEffect(()=>{
    let mounted = true
    async function load() {
      try {
        setLoading(true)
        const r = await fetch(`${API}/victim-atlas/cases/${caseId}`)
        if(!r.ok) throw new Error('detail failed')
        const d = await r.json()
        if(mounted) setData(d.data || null)
      } catch {
        if(mounted) setData(null)
      } finally {
        if(mounted) setLoading(false)
      }
    }
    load()
    return ()=>{ mounted = false }
  },[caseId])

  if (loading) return <div style={{ display:'flex', alignItems:'center', gap:8, padding:16, background:theme.bg, borderRadius:theme.radiusSm }}><Spinner size={16}/><span style={{ fontSize:12, color:theme.textMuted }}>Detay yükleniyor...</span></div>
  if (!data) return <p style={{ marginTop:10, fontSize:12, color:theme.textMuted }}>Detay bulunamadi.</p>

  return <div style={{ marginTop:compact ? 0 : 0 }}>
    <div style={{ padding:'16px 18px', background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, marginBottom:16 }}>
      <p style={{ fontSize:13, color:theme.text, marginBottom:12, lineHeight:1.6, fontWeight:500 }}>{data.narrative_summary}</p>
    </div>
    
    <p style={{ fontSize:13, color:theme.primary, fontWeight:700, marginBottom:12, display:'flex', alignItems:'center', gap:6 }}>📋 Adım Adım Korunma Rehberi</p>
    <div style={{ display:'flex', flexDirection:'column', gap:10, marginBottom:16 }}>
      {(data.defense_steps||[]).map((step, idx)=><div key={idx} style={{ display:'flex', gap:12, alignItems:'flex-start', padding:'14px 16px', borderRadius:theme.radiusSm, background:theme.surface, border:`1px solid ${theme.border}`, transition:'all 0.3s ease' }} onMouseEnter={e=>{e.currentTarget.style.borderColor=theme.primary+'44';e.currentTarget.style.transform='translateX(4px)'}} onMouseLeave={e=>{e.currentTarget.style.borderColor=theme.border;e.currentTarget.style.transform='none'}}>
        <div style={{ minWidth:28, height:28, borderRadius:'50%', background:theme.primaryDim, border:`1px solid ${theme.primary}44`, display:'flex', alignItems:'center', justifyContent:'center', color:theme.primary, fontWeight:800, fontSize:13 }}>{idx+1}</div>
        <div style={{ flex:1 }}>
          <p style={{ fontSize:13, color:'#fff', lineHeight:1.6, margin:0, fontWeight:500 }}>{step}</p>
        </div>
      </div>)}
    </div>
    
    {Array.isArray(data.evidence) && data.evidence.length>0 && <div style={{ padding:'14px 16px', background:theme.surface, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
      <p style={{ fontSize:12, color:theme.textMuted, marginBottom:10, fontWeight:600, textTransform:'uppercase', letterSpacing:'0.5px' }}>🔗 Kaynak Bağlantıları</p>
      {data.evidence.slice(0,3).map((ev, idx)=><a key={idx} href={ev.url} target="_blank" rel="noreferrer" style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 12px', background:theme.bg, borderRadius:6, fontSize:12, color:theme.primary, textDecoration:'none', marginBottom:6, transition:'all 0.2s ease' }} onMouseEnter={e=>{e.currentTarget.style.background=theme.primary+'22';e.currentTarget.style.transform='translateX(4px)'}} onMouseLeave={e=>{e.currentTarget.style.background=theme.bg;e.currentTarget.style.transform='none'}}>
        <span>📄</span>
        <span style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{ev.title || ev.url}</span>
      </a>)}
    </div>}
  </div>
}

/* ===============================================
   HONEYPOT / IOC
   =============================================== */
function HoneypotIOC() {
  const [iocStats, setIocStats] = useState(null)
  const [iocList, setIocList] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searching, setSearching] = useState(false)
  const [activeTab, setActiveTab] = useState('dashboard')
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })
  const [currentSlide, setCurrentSlide] = useState(0)
  const [showDropdown, setShowDropdown] = useState(false)
  const searchTimeoutRef = useRef(null)

  async function loadIoCStats(){
    try{
      const r=await fetch(`${API}/honeypot/ioc/stats`);
      const d=await r.json();
      setIocStats(d)
    }catch{
      try{
        const r=await fetch(`${API}/honeypot/ioc/stats`);
        const d=await r.json();
        setIocStats(d)
      }catch{
        setIocStats(null)
      }
    }
  }
  async function loadIoCList(){
    try{
      const levels=['critical','high','medium','low'];
      let allIocs=[];
      for(const level of levels){
        try{
          const r=await fetch(`${API}/honeypot/ioc/by-risk-score?level=${level}&limit=8`);
          const d=await r.json();
          if(d.iocs) allIocs=[...allIocs,...d.iocs];
        }catch{
          continue
        }
      }
      setIocList(allIocs)
    }catch{
      try{
        const r=await fetch(`${API}/honeypot/ioc/list?limit=25`);
        const d=await r.json();
        setIocList(d.data||d.iocs||[])
      }catch{
        setIocList([])
      }
    }
  }
  async function handleSearch(){if(!searchQuery)return;setSearching(true);try{const r=await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`);const d=await r.json();if(d.status==='success'||d.results){setSearchResults(d.results||d.data||d.iocs||[]);setActiveTab('search-results')}else{showToast('Arama sonucu bulunamadi veya hata: '+d.message,'error')}}catch(e){showToast('Arama hatasi: '+e.message,'error')};setSearching(false)}
  function showToast(msg,t='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(v=>({...v,visible:false})),3000)}
  
  // Real-time autocomplete with debouncing
  useEffect(() => {
    if (searchQuery.length < 2) {
      setSearchResults([])
      setShowDropdown(false)
      return
    }
    
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
      } catch (e) {
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
  
  // Auto slide for latest IOCs
  useEffect(() => {
    if (iocList.length > 0) {
      const interval = setInterval(() => {
        setCurrentSlide(prev => (prev + 1) % Math.min(iocList.length, 5))
      }, 4000)
      return () => clearInterval(interval)
    }
  }, [iocList])
  
  useEffect(()=>{loadIoCStats();loadIoCList()},[])

  const statsData=iocStats?.stats||iocStats||{}
  const riskDist=statsData?.risk_distribution||iocStats?.risk_distribution||[]
  const weeklyGrowth=statsData?.weekly_growth||iocStats?.weekly_growth||[]
  const topThreats=statsData?.top_threats||iocStats?.top_threats||[]
  const sourceBreakdown=statsData?.source_breakdown||iocStats?.source_breakdown||[]
  const totalIocs=statsData?.total_iocs||iocStats?.total_iocs||iocStats?.total_records||0
  const highRisk=statsData?.high_risk_count||iocStats?.high_risk_count||0
  const mediumRisk=statsData?.medium_risk_count||iocStats?.medium_risk_count||0
  const lowRisk=statsData?.low_risk_count||iocStats?.low_risk_count||0

  return <div>
    <Toast {...toast}/>
    
    {/* Hero Section - Merged Search & Latest IOCs */}
    <motion.div 
      initial={{ opacity:0, y:30 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.6, ease:theme.ease.out }}
      style={{ 
        background:theme.gradientHero,
        borderRadius:theme.radiusLg,
        padding:48,
        marginBottom:32,
        position:'relative',
        overflow:'hidden',
        border:`1px solid ${theme.border}`
      }}
    >
      <div style={{ position:'absolute', top:0, left:0, right:0, bottom:0, opacity:0.1, backgroundImage:theme.gridPattern, backgroundSize:'40px 40px' }} />
      <div style={{ position:'relative', zIndex:1 }}>
        <motion.div 
          initial={{ opacity:0, scale:0.9 }}
          animate={{ opacity:1, scale:1 }}
          transition={{ delay:0.2, duration:0.5, ease:theme.ease.spring }}
          style={{ textAlign:'center', marginBottom:32 }}
        >
          <span style={{ display:'inline-block', padding:'8px 20px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'24px', fontSize:12, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'2px', marginBottom:16 }}>IOC / Tuzak Modulu</span>
          <h1 style={{ fontSize:42, fontWeight:800, color:'#fff', marginBottom:12, letterSpacing:'-1px' }}>Tehdit Istihbarati & IOC Analizi</h1>
          <p style={{ color:theme.textMuted, fontSize:16, maxWidth:600, margin:'0 auto' }}>{totalIocs.toLocaleString('tr-TR')}+ tehdit indikatoru. Gercek zamanli IOC taramasi, risk analizi ve kaynak dagilimi.</p>
        </motion.div>

        {/* Search Section */}
        <motion.div 
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.3, duration:0.5, ease:theme.ease.out }}
          style={{ maxWidth:700, margin:'0 auto 32px', position:'relative' }}
        >
          <div style={{ display:'flex', gap:12, background:theme.bg, padding:8, borderRadius:theme.radiusLg, border:`2px solid ${theme.border}`, boxShadow:theme.shadow.glow }}>
            <input 
              value={searchQuery} 
              onChange={e=>setSearchQuery(e.target.value)} 
              placeholder="IP, domain, URL veya hash arat..." 
              style={{ 
                flex:1, 
                padding:'16px 24px', 
                borderRadius:theme.radiusMd, 
                background:'transparent', 
                border:'none', 
                color:'#fff', 
                fontSize:16, 
                outline:'none',
                fontFamily:theme.mono
              }} 
              onKeyDown={e=>e.key==='Enter'&&handleSearch()}
            />
            <motion.button 
              onClick={handleSearch}
              disabled={searching}
              whileHover={{ scale:1.02 }}
              whileTap={{ scale:0.98 }}
              style={{
                padding:'16px 32px',
                borderRadius:theme.radiusMd,
                cursor:searching?'not-allowed':'pointer',
                fontSize:15,
                fontWeight:700,
                background:searching?'#444':theme.gradientPrimary,
                color:searching?'#888':'#000',
                border:'none',
                display:'inline-flex',
                alignItems:'center',
                gap:8,
                opacity:searching?0.5:1
              }}
            >
              {searching?'Aranıyor...':'🔎 Ara'}
            </motion.button>
          </div>
          
          {/* Autocomplete Dropdown */}
          <AnimatePresence>
            {showDropdown && searchResults.length > 0 && (
              <motion.div
                initial={{ opacity:0, y:-10 }}
                animate={{ opacity:1, y:0 }}
                exit={{ opacity:0, y:-10 }}
                transition={{ duration:0.2, ease:theme.ease.out }}
                style={{
                  position:'absolute',
                  top:'100%',
                  left:0,
                  right:0,
                  marginTop:8,
                  background:theme.bgDeep,
                  borderRadius:theme.radiusMd,
                  border:`1px solid ${theme.border}`,
                  maxHeight:300,
                  overflowY:'auto',
                  zIndex:100,
                  boxShadow:theme.shadow.glow
                }}
              >
                {searchResults.slice(0, 10).map((item, i) => (
                  <motion.div
                    key={i}
                    initial={{ opacity:0, x:-10 }}
                    animate={{ opacity:1, x:0 }}
                    transition={{ delay:i * 0.05, duration:0.2 }}
                    onClick={() => {
                      setSearchQuery(item.value || item.ioc_value || item.ioc || item.indicator || '')
                      setShowDropdown(false)
                      handleSearch()
                    }}
                    style={{
                      padding:'12px 16px',
                      borderBottom:`1px solid ${theme.border}`,
                      cursor:'pointer',
                      transition:'background 0.2s ease'
                    }}
                    whileHover={{ background:theme.surface }}
                  >
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                      <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:13, wordBreak:'break-all' }}>{item.value||item.ioc_value||item.ioc||item.indicator||'-'}</span>
                      <span style={{ padding:'4px 10px', borderRadius:'10px', fontSize:10, background:theme.primaryDim, color:theme.primary }}>{item.ioc_type||item.type||item.threat_type||'-'}</span>
                    </div>
                    <div style={{ display:'flex', gap:16, fontSize:11, color:theme.textMuted }}>
                      <span>Risk: <span style={{ color:(item.risk_score||0)>75?theme.accent:(item.risk_score||0)>40?theme.warning:theme.primary, fontWeight:600 }}>{item.risk_score||'-'}</span></span>
                      <span>Kaynak: {item.source||'-'}</span>
                    </div>
                  </motion.div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Latest IOCs Preview - Slide */}
        {iocList.length > 0 && (
          <motion.div
            initial={{ opacity:0, y:20 }}
            animate={{ opacity:1, y:0 }}
            transition={{ delay:0.4, duration:0.5, ease:theme.ease.out }}
            style={{ 
              maxWidth:900, 
              margin:'0 auto',
              background:theme.bgDeep,
              borderRadius:theme.radiusLg,
              padding:24,
              border:`1px solid ${theme.border}`
            }}
          >
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
              <h3 style={{ fontSize:14, fontWeight:700, color:'#fff' }}>📋 Son Eklenen IOC'lar</h3>
              <div style={{ display:'flex', gap:8 }}>
                {iocList.slice(0, 5).map((_, i) => (
                  <div 
                    key={i}
                    onClick={() => setCurrentSlide(i)}
                    style={{ 
                      width:8, 
                      height:8, 
                      borderRadius:'50%', 
                      background:currentSlide === i ? theme.primary : theme.border,
                      cursor:'pointer',
                      transition:'all 0.3s ease'
                    }}
                  />
                ))}
              </div>
            </div>
            <AnimatePresence mode='wait'>
              <motion.div
                key={currentSlide}
                initial={{ opacity:0, x:50 }}
                animate={{ opacity:1, x:0 }}
                exit={{ opacity:0, x:-50 }}
                transition={{ duration:0.4, ease:theme.ease.out }}
                style={{ 
                  padding:20, 
                  background:theme.surface, 
                  borderRadius:theme.radiusMd,
                  border:`1px solid ${theme.border}`
                }}
              >
                <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:12 }}>
                  <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:13, wordBreak:'break-all' }}>{iocList[currentSlide]?.value||iocList[currentSlide]?.ioc_value||iocList[currentSlide]?.ioc||iocList[currentSlide]?.indicator||'-'}</span>
                  <span style={{ padding:'4px 12px', borderRadius:'12px', fontSize:11, background:theme.primaryDim, color:theme.primary }}>{iocList[currentSlide]?.type||iocList[currentSlide]?.ioc_type||'-'}</span>
                </div>
                <div style={{ display:'flex', gap:24, fontSize:12, color:theme.textMuted }}>
                  <span>Risk: <span style={{ color:(iocList[currentSlide]?.risk_score||0)>75?theme.accent:(iocList[currentSlide]?.risk_score||0)>40?theme.warning:theme.primary, fontWeight:600 }}>{iocList[currentSlide]?.risk_score||'-'}</span></span>
                  <span>Kaynak: {iocList[currentSlide]?.source||'-'}</span>
                  <span>Tarih: {iocList[currentSlide]?.created_at?new Date(iocList[currentSlide].created_at).toLocaleDateString('tr-TR'):iocList[currentSlide]?.date?new Date(iocList[currentSlide].date).toLocaleDateString('tr-TR'):'-'}</span>
                </div>
              </motion.div>
            </AnimatePresence>
          </motion.div>
        )}
      </div>
    </motion.div>

    {/* Stats Grid */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.5, duration:0.5, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:16, marginBottom:32 }}
    >
      {[
        { label:'Toplam IOC', value:totalIocs, color:theme.primary },
        { label:'Yuksek Risk', value:highRisk, color:theme.danger },
        { label:'Orta Risk', value:mediumRisk, color:theme.warning },
        { label:'Dusuk Risk', value:lowRisk, color:theme.success },
        { label:'Kaynak', value:sourceBreakdown.length, color:theme.warning }
      ].map((stat, i) => (
        <motion.div
          key={i}
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.6 + i * 0.1, duration:0.4, ease:theme.ease.spring }}
        >
          <Card style={{ textAlign:'center', padding:'20px 12px' }}>
            <p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>{stat.label}</p>
            <p style={{ fontSize:28, fontWeight:800, color:stat.color }}><CountUp end={stat.value}/></p>
          </Card>
        </motion.div>
      ))}
    </motion.div>

    {/* Charts Section */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.8, duration:0.5, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:32 }}
    >
      {/* Risk Distribution - Donut Chart Style */}
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:20 }}>📊 Risk Dagilimi</h3>
        {riskDist.length>0?(
          <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
            {riskDist.map((item,i)=>{
              const colors=['#22c55e','#84cc16','#f59e0b','#ff6b35','#ef4444'];
              return (
                <motion.div 
                  key={i}
                  initial={{ opacity:0, x:-20 }}
                  animate={{ opacity:1, x:0 }}
                  transition={{ delay:0.9 + i * 0.1, duration:0.4, ease:theme.ease.out }}
                >
                  <div style={{ display:'flex', justifyContent:'space-between', fontSize:12, marginBottom:6 }}>
                    <span style={{ color:theme.textMuted }}>{item.range}</span>
                    <span style={{ color:'#fff', fontWeight:600 }}>{item.count} ({item.percentage?.toFixed(1)}%)</span>
                  </div>
                  <div style={{ height:12, background:theme.surface, borderRadius:6, overflow:'hidden' }}>
                    <motion.div 
                      initial={{ width:0 }}
                      animate={{ width:`${Math.min(item.percentage,100)}%` }}
                      transition={{ delay:1 + i * 0.1, duration:0.8, ease:theme.ease.out }}
                      style={{ height:'100%', background:colors[i]||theme.primary, borderRadius:6 }}
                    />
                  </div>
                </motion.div>
              )
            })}
          </div>
        ):<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}
      </Card>

      {/* Weekly Growth - Line Chart Style */}
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:20 }}>📈 Haftalik IOC Artisi</h3>
        {weeklyGrowth.length>0?(
          <div style={{ display:'flex', gap:6, alignItems:'flex-end', height:180, padding:'0 8px' }}>
            {weeklyGrowth.map((item,i)=>{
              const maxVal=Math.max(...weeklyGrowth.map(w=>w.count),1);
              const h=(item.count/maxVal)*100;
              return (
                <motion.div 
                  key={i}
                  initial={{ opacity:0, y:20 }}
                  animate={{ opacity:1, y:0 }}
                  transition={{ delay:1 + i * 0.05, duration:0.4, ease:theme.ease.spring }}
                  style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', gap:6 }}
                >
                  <span style={{ fontSize:10, color:theme.textMuted, fontWeight:600 }}>{item.count}</span>
                  <motion.div 
                    initial={{ height:0 }}
                    animate={{ height:`${h}%` }}
                    transition={{ delay:1.2 + i * 0.05, duration:0.6, ease:theme.ease.out }}
                    style={{ 
                      width:'100%', 
                      minHeight:4, 
                      background:`linear-gradient(to top, ${theme.primary}, ${theme.primary}88)`, 
                      borderRadius:'4px 4px 0 0' 
                    }}
                  />
                  <span style={{ fontSize:8, color:theme.textMuted, transform:'rotate(-45deg)', marginTop:4, whiteSpace:'nowrap' }}>{item.date?.slice(5)||''}</span>
                </motion.div>
              )
            })}
          </div>
        ):<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}
      </Card>
    </motion.div>

    {/* Source Breakdown & Top Threats */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:1.2, duration:0.5, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:32 }}
    >
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>📡 Kaynak Dagilimi</h3>
        {sourceBreakdown.length>0?sourceBreakdown.slice(0,8).map((s,i)=>(
          <motion.div 
            key={i}
            initial={{ opacity:0, x:-20 }}
            animate={{ opacity:1, x:0 }}
            transition={{ delay:1.3 + i * 0.05, duration:0.4, ease:theme.ease.out }}
            style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 0', borderBottom:`1px solid ${theme.border}` }}
          >
            <span style={{ fontSize:13, color:theme.text }}>{s.source}</span>
            <span style={{ fontSize:13, fontWeight:700, color:theme.primary }}>{(s.count||0).toLocaleString('tr-TR')}</span>
          </motion.div>
        )):<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}
      </Card>

      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>🔥 En Cok Gorulen Tehditler</h3>
        {topThreats.length>0?topThreats.slice(0,10).map((t,i)=>(
          <motion.div 
            key={i}
            initial={{ opacity:0, x:20 }}
            animate={{ opacity:1, x:0 }}
            transition={{ delay:1.3 + i * 0.05, duration:0.4, ease:theme.ease.out }}
            style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'10px 0', borderBottom:`1px solid ${theme.border}` }}
          >
            <span style={{ fontSize:12, color:'#fff' }}>{i+1}. {(t.type||t.threat_type||t.name||'').toUpperCase()}</span>
            <span style={{ fontSize:13, fontWeight:700, color:theme.danger }}>{(t.count||0).toLocaleString('tr-TR')}</span>
          </motion.div>
        )):<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}
      </Card>
    </motion.div>

    {/* Full IOC Table */}
    <motion.div
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:1.4, duration:0.5, ease:theme.ease.out }}
    >
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}>
          <span>📋</span> Tum IOC'lar
          <span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>{iocList.length} kayit</span>
        </h3>
        <div style={{ overflowX:'auto', maxHeight:500, overflowY:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}>
              <tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:10, textTransform:'uppercase', letterSpacing:'1px' }}>
                <th style={{ textAlign:'left', padding:'12px 8px' }}>Gosterge</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Tur</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Risk</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Kaynak</th>
                <th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {iocList.length===0&&<tr><td colSpan={5} style={{ textAlign:'center', padding:32, color:theme.textMuted }}>Veri yukleniyor...</td></tr>}
              {iocList.map((item,i)=>(
                <motion.tr 
                  key={item.id||i}
                  initial={{ opacity:0, y:10 }}
                  animate={{ opacity:1, y:0 }}
                  transition={{ delay:1.5 + i * 0.02, duration:0.3, ease:theme.ease.out }}
                  style={{ borderBottom:`1px solid ${theme.border}` }}
                  whileHover={{ background:theme.surface }}
                >
                  <td style={{ padding:'10px 8px' }}><span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11, wordBreak:'break-all' }}>{item.value||item.ioc_value||item.ioc||item.indicator||'-'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'4px 10px', borderRadius:'10px', fontSize:10, background:theme.primaryDim, color:theme.primary }}>{item.type||item.ioc_type||'-'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'4px 10px', borderRadius:'10px', fontSize:10, fontWeight:600, background:(item.risk_score||0)>75?theme.accentDim:(item.risk_score||0)>40?theme.warning+'22':theme.primaryDim, color:(item.risk_score||0)>75?theme.accent:(item.risk_score||0)>40?theme.warning:theme.primary }}>{item.risk_score||'-'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center', color:theme.textMuted, fontSize:11 }}>{item.source||'-'}</td>
                  <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:10 }}>{item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):item.date?new Date(item.date).toLocaleDateString('tr-TR'):'-'}</td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </motion.div>
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
