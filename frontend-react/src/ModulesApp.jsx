import { useState, useEffect, useRef } from 'react'

const API = '/api/v2'

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

function Card({ children, style, hover=true, ...props }) {
  const [h,sH]=useState(false)
  return <div onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)} style={{ background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`, border:`1px solid ${h?theme.primary+'66':theme.border}`, borderRadius:theme.radius, padding:24, transition:'all 0.3s cubic-bezier(0.175,0.885,0.32,1.275)', boxShadow:h?theme.glow:'none', transform:h?'translateY(-2px)':'none', ...style }} {...props}>{children}</div>
}

function GlowButton({ children, onClick, disabled, loading, variant='primary', style, ...props }) {
  const isPrimary=variant==='primary'
  return <button onClick={onClick} disabled={disabled||loading} style={{ padding:'14px 32px', borderRadius:theme.radiusSm, border:'none', cursor:disabled?'not-allowed':'pointer', fontSize:14, fontWeight:700, letterSpacing:'0.5px', background:isPrimary?'linear-gradient(135deg, #00d4ff, #0099cc)':'transparent', color:isPrimary?'#000':'#00d4ff', border:isPrimary?'none':'1px solid #00d4ff44', transition:'all 0.3s ease', opacity:disabled?0.5:1, display:'inline-flex', alignItems:'center', gap:8, boxShadow:isPrimary?'0 4px 20px rgba(0,212,255,0.3)':'none', ...style }} onMouseEnter={e=>{if(!disabled){e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow='0 8px 30px rgba(0,212,255,0.4)'}}} onMouseLeave={e=>{e.currentTarget.style.transform='none';e.currentTarget.style.boxShadow=isPrimary?'0 4px 20px rgba(0,212,255,0.3)':'none'}} {...props}>{loading&&<Spinner size={18}/>}{children}</button>
}

function CountUp({ end, duration=1500 }) {
  const [val,setVal]=useState(0);const ref=useRef(null)
  useEffect(()=>{const start=performance.now();const animate=(now)=>{const elapsed=now-start;const progress=Math.min(elapsed/duration,1);const eased=1-Math.pow(1-progress,3);setVal(Math.floor(eased*end));if(progress<1)ref.current=requestAnimationFrame(animate)};ref.current=requestAnimationFrame(animate);return()=>cancelAnimationFrame(ref.current)},[end,duration])
  return <>{val.toLocaleString('tr-TR')}</>
}

function SectionHeader({ badge, title, subtitle }) {
  return <div style={{ textAlign:'center', marginBottom:48 }}>
    <span style={{ display:'inline-block', padding:'6px 16px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'20px', fontSize:11, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'1.5px', marginBottom:16 }}>{badge}</span>
    <h1 style={{ fontSize:36, fontWeight:800, color:'#fff', marginBottom:12, letterSpacing:'-1px' }}>{title}</h1>
    <p style={{ color:theme.textMuted, fontSize:16, maxWidth:600, margin:'0 auto', lineHeight:1.6 }}>{subtitle}</p>
  </div>
}

export default function ModulesApp() {
  const [page, setPage] = useState('ai-analyzer')
  const [scrolled, setScrolled] = useState(false)
  useEffect(()=>{const onScroll=()=>setScrolled(window.scrollY>20);window.addEventListener('scroll',onScroll,{passive:true});return()=>window.removeEventListener('scroll',onScroll)},[])

  const tabs = [
    {id:'ai-analyzer',label:'AI Analiz',icon:'🤖'},
    {id:'phishing-detector',label:'Phishing',icon:'🎣'},
    {id:'honeypot',label:'IOC / Tuzak',icon:'🕸️'},
    {id:'breach-intel',label:'Sizinti',icon:'🔓'},
  ]

  return <div style={{ minHeight:'100vh', background:theme.bg, color:theme.text }}>
    <style>{`
      @keyframes spin { to { transform:rotate(360deg) } }
      @keyframes fadeInUp { from { opacity:0; transform:translateY(20px) } to { opacity:1; transform:translateY(0) } }
      @keyframes slideInLeft { from { opacity:0; transform:translateX(-30px) } to { opacity:1; transform:translateX(0) } }
      @keyframes slideInRight { from { opacity:0; transform:translateX(30px) } to { opacity:1; transform:translateX(0) } }
      @keyframes scaleIn { from { opacity:0; transform:scale(0.9) } to { opacity:1; transform:scale(1) } }
      * { scrollbar-width:thin; scrollbar-color:${theme.border} transparent; }
      ::-webkit-scrollbar { width:6px }
      ::-webkit-scrollbar-track { background:transparent }
      ::-webkit-scrollbar-thumb { background:${theme.border}; border-radius:3px }
    `}</style>

    <nav style={{ position:'fixed', top:0, left:0, right:0, zIndex:1000, background:scrolled?'rgba(8,12,20,0.95)':'rgba(8,12,20,0.8)', backdropFilter:'blur(20px)', borderBottom:`1px solid ${scrolled?theme.border:'transparent'}`, transition:'all 0.3s ease', padding:'0 24px' }}>
      <div style={{ maxWidth:1400, margin:'0 auto', display:'flex', alignItems:'center', justifyContent:'space-between', height:70 }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <svg width="32" height="32" viewBox="0 0 36 36" fill="none">
            <path d="M18 4L6 11V18C6 23.5 10 28.5 18 30C26 28.5 30 23.5 30 18V11L18 4Z" stroke="#00d4ff" strokeWidth="2" fill="none"/>
            <path d="M14 18L17 21L23 15" stroke="#00d4ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span style={{ fontSize:20, fontWeight:700, color:'#fff', letterSpacing:'-0.5px' }}>Aegis<span style={{ color:theme.primary }}>Nexus</span></span>
          <span style={{ fontSize:11, color:theme.textMuted, marginLeft:4 }}>Modüller</span>
        </div>
        <div style={{ display:'flex', gap:4, background:theme.surface, borderRadius:theme.radiusSm, padding:3 }}>
          {tabs.map(t => <button key={t.id} onClick={()=>setPage(t.id)} style={{ padding:'8px 18px', borderRadius:'6px', border:'none', cursor:'pointer', fontSize:13, fontWeight:600, background:page===t.id?theme.primary:'transparent', color:page===t.id?'#000':theme.textMuted, transition:'all 0.2s ease', display:'flex', alignItems:'center', gap:6 }}><span>{t.icon}</span><span>{t.label}</span></button>)}
        </div>
        <a href="https://aegisnexus.dev" style={{ fontSize:13, color:theme.textMuted, textDecoration:'none', padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, transition:'all 0.2s' }}
          onMouseEnter={e=>{e.currentTarget.style.color=theme.primary;e.currentTarget.style.borderColor=theme.primary+'44'}}
          onMouseLeave={e=>{e.currentTarget.style.color=theme.textMuted;e.currentTarget.style.borderColor=theme.border}}>← Ana Sayfa</a>
      </div>
    </nav>

    <main style={{ paddingTop:86, maxWidth:1400, margin:'0 auto', padding:'86px 24px 0' }}>
      {page==='ai-analyzer' && <AIAnalyzer />}
      {page==='phishing-detector' && <PhishingDetector />}
      {page==='honeypot' && <HoneypotIOC />}
      {page==='breach-intel' && <BreachIntel />}
    </main>
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
    try { const r = await fetch(`${API}/ai-analyzer/history?limit=10`); const d = await r.json(); setHistory(d.data || []) } catch {}
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

function RiskGauge({ score, label }) {
  const c=2*Math.PI*40;const o=c-(Math.min(score,100)/100)*c
  const color=score>75?theme.danger:score>50?theme.warning:score>25?theme.primary:theme.success
  return <div style={{ display:'inline-flex', flexDirection:'column', alignItems:'center' }}>
    <svg width="120" height="120" viewBox="0 0 100 100"><circle cx="50" cy="50" r="40" fill="none" stroke={theme.border} strokeWidth="8"/><circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8" strokeDasharray={c} strokeDashoffset={o} transform="rotate(-90 50 50)" style={{ transition:'stroke-dashoffset 1s ease' }} strokeLinecap="round"/><text x="50" y="50" textAnchor="middle" dominantBaseline="central" fill="#fff" fontSize="22" fontWeight="800" fontFamily="Inter, sans-serif">{score}</text></svg>
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
  const [latest, setLatest] = useState([])
  const [stats, setStats] = useState(null)
  const [pageNum, setPageNum] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  useEffect(()=>{loadLatest();loadStats()},[])

  async function loadLatest(p=1) {
    try{const r=await fetch(`${API}/phishing/latest?limit=20`);const d=await r.json();setLatest(d.data||d.latest||[]);setTotalPages(Math.ceil((d.total||0)/20)||1);setPageNum(p)}catch{}
  }

  async function loadStats() {
    try{const r=await fetch(`${API}/phishing/stats`);const d=await r.json();setStats(d)}catch{}
  }

  async function handleCheck() {
    if(!url)return;setChecking(true);setResult(null)
    try{
      const r=await fetch(`${API}/phishing/check-url`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})})
      if(!r.ok)throw new Error('URL kontrol hatasi')
      const d=await r.json();setResult(d)
    }catch(e){showToast('URL kontrol hatasi: '+e.message,'error')}
    setChecking(false)
  }

  function showToast(msg,t='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(t=>({...t,visible:false})),3000)}

  const totalUrls=stats?.stats?.total_urls||stats?.total_urls||0
  const phCount=stats?.stats?.phishing_count||stats?.phishing_count||0
  const safeCount=stats?.stats?.safe_count||stats?.safe_count||0

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>
    <SectionHeader badge="Phishing Dedektoru" title="URL Guvenlik Tarama Motoru" subtitle="1.2M+ phishing URL veritabani ile anlik guvenlik kontrolu. Aninda sonuc, detayli rapor."/>
    <div style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:16, marginBottom:32 }}>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Toplam URL</p><p style={{ fontSize:32, fontWeight:800, color:theme.primary }}><CountUp end={totalUrls}/></p></Card>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Phishing</p><p style={{ fontSize:32, fontWeight:800, color:theme.danger }}><CountUp end={phCount}/></p></Card>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Guvenli</p><p style={{ fontSize:32, fontWeight:800, color:theme.success }}><CountUp end={safeCount}/></p></Card>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Bugun Taranan</p><p style={{ fontSize:32, fontWeight:800, color:theme.warning }}><CountUp end={stats?.stats?.today_scans||0}/></p></Card>
    </div>
    <Card style={{ marginBottom:32 }}>
      <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>🔍</span> URL Guvenlik Kontrolu</h3>
      <div style={{ display:'flex', gap:12, marginBottom:16 }}>
        <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://ornek.com/supheli-link" style={{ flex:1, padding:'14px 18px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:14, outline:'none' }} onKeyDown={e=>e.key==='Enter'&&handleCheck()}/>
        <GlowButton onClick={handleCheck} loading={checking} disabled={!url}>{checking?'Taranıyor...':'🔍 Tara'}</GlowButton>
      </div>
      {latest.length>0&&<div style={{ marginTop:12, padding:12, background:theme.surface, borderRadius:theme.radiusSm }}>
        <p style={{ fontSize:11, color:theme.textMuted, marginBottom:8, fontWeight:600 }}>Son taranan URL'ler (tıklayarak kontrol edin):</p>
        <div style={{ display:'flex', flexWrap:'wrap', gap:6 }}>
          {latest.slice(0,10).map((item,i)=><button key={i} onClick={()=>{setUrl(item.url);setTimeout(()=>handleCheck(),100)}} style={{ padding:'5px 12px', borderRadius:'16px', border:`1px solid ${theme.border}`, background:theme.surface2, cursor:'pointer', fontSize:11, color:theme.primary, fontFamily:theme.mono, maxWidth:280, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{item.url}</button>)}
        </div>
      </div>}
      {result&&<div style={{ animation:'scaleIn 0.3s ease', padding:20, background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
        <div style={{ display:'flex', gap:24, alignItems:'flex-start', flexWrap:'wrap' }}>
          <RiskGauge score={result.score||0} label="Risk Skoru"/>
          <div style={{ flex:1, minWidth:250 }}>
            <div style={{ display:'flex', gap:12, flexWrap:'wrap', marginBottom:12 }}>
              <span style={{ padding:'4px 14px', borderRadius:'20px', fontSize:12, fontWeight:700, background:result.score>50?theme.accentDim:theme.primaryDim, color:result.score>50?theme.accent:theme.primary }}>{result.risk_level||'Bilinmiyor'}</span>
            </div>
            <p style={{ fontSize:12, color:theme.textMuted, wordBreak:'break-all', marginBottom:12, fontFamily:theme.mono }}>{url}</p>
            {result.details&&Array.isArray(result.details)&&result.details.map((d,i)=><div key={i} style={{ padding:'6px 10px', marginBottom:4, background:theme.primaryDim, borderRadius:6, fontSize:12, color:theme.text }}>• {d}</div>)}
            {result.sources&&Array.isArray(result.sources)&&result.sources.map((s,i)=><div key={i} style={{ padding:'6px 10px', marginBottom:4, background:theme.surface, borderRadius:6, fontSize:12, display:'flex', gap:8, alignItems:'center' }}><span style={{ color:theme.textMuted }}>Kaynak:</span><span style={{ color:'#fff', fontWeight:600 }}>{s.name}</span><span style={{ marginLeft:'auto', color:s.status?.includes('Başarısız')?theme.danger:theme.success }}>{s.status}</span></div>)}
          </div>
        </div>
      </div>}
    </Card>
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📋</span> Son Phishing Verileri<span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>Toplam {totalPages} sayfa</span></h3>
      <div style={{ overflowX:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:13 }}>
          <thead><tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:11, textTransform:'uppercase', letterSpacing:'1px' }}><th style={{ textAlign:'left', padding:'12px 8px' }}>URL</th><th style={{ textAlign:'left', padding:'12px 8px' }}>Domain</th><th style={{ textAlign:'center', padding:'12px 8px' }}>Hedef</th><th style={{ textAlign:'center', padding:'12px 8px' }}>Durum</th><th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th></tr></thead>
          <tbody>
            {latest.length===0&&<tr><td colSpan={5} style={{ textAlign:'center', padding:32, color:theme.textMuted }}>Veri yukleniyor...</td></tr>}
            {latest.map((item,i)=><tr key={item.id||i} style={{ borderBottom:`1px solid ${theme.border}`, cursor:'pointer' }} onClick={()=>{setUrl(item.url);setTimeout(()=>handleCheck(),100)}} onMouseEnter={e=>e.currentTarget.style.background=theme.surface} onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
              <td style={{ padding:'10px 8px', maxWidth:300, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}><span style={{ color:theme.text, fontSize:12, fontFamily:theme.mono }}>{item.url}</span></td>
              <td style={{ padding:'10px 8px' }}><span style={{ color:theme.primary, fontSize:12 }}>{item.domain||'-'}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'2px 8px', borderRadius:'10px', fontSize:11, background:theme.accentDim, color:theme.accent }}>{item.target||'Phishing'}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:4, fontSize:12 }}><StatusDot active={item.status==='active'}/>{item.status||'Bilinmiyor'}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:11 }}>{item.submission_time?new Date(item.submission_time).toLocaleDateString('tr-TR'):item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):'-'}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
      {totalPages>1&&<div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:20 }}>
        <button onClick={()=>loadLatest(pageNum-1)} disabled={pageNum<=1} style={{ padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:pageNum<=1?theme.textMuted:'#fff', cursor:pageNum<=1?'not-allowed':'pointer', fontSize:13, fontWeight:600 }}>← Onceki</button>
        <span style={{ padding:'8px 16px', color:theme.textMuted, fontSize:13 }}>Sayfa {pageNum} / {totalPages}</span>
        <button onClick={()=>loadLatest(pageNum+1)} disabled={pageNum>=totalPages} style={{ padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:pageNum>=totalPages?theme.textMuted:'#fff', cursor:pageNum>=totalPages?'not-allowed':'pointer', fontSize:13, fontWeight:600 }}>Sonraki →</button>
      </div>}
    </Card>
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

  useEffect(()=>{loadIoCStats();loadIoCList()},[])

  async function loadIoCStats(){
    try{
      const r=await fetch(`${API}/honeypot/ioc/stats`);
      const d=await r.json();
      setIocStats(d)
    }catch(e){
      try{const r=await fetch(`${API}/honeypot/ioc/stats`);const d=await r.json();setIocStats(d)}catch{}
    }
  }
  async function loadIoCList(){
    try{
      // Fetch from all risk levels to get a good mix
      const levels=['critical','high','medium','low'];
      let allIocs=[];
      for(const level of levels){
        try{
          const r=await fetch(`${API}/honeypot/ioc/by-risk-score?level=${level}&limit=8`);
          const d=await r.json();
          if(d.iocs) allIocs=[...allIocs,...d.iocs];
        }catch(e){}
      }
      setIocList(allIocs.length>0?allIocs:(d.iocs||d.data||d.results||d.indicators||[]))
    }catch(e){
      try{const r=await fetch(`${API}/honeypot/ioc/list?limit=25`);const d=await r.json();setIocList(d.data||d.iocs||[])}catch{}
    }
  }
  async function handleSearch(){if(!searchQuery)return;setSearching(true);try{const r=await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`);const d=await r.json();if(d.status==='success'||d.results){setSearchResults(d.results||d.data||d.iocs||[]);setActiveTab('search-results')}else{showToast('Arama sonucu bulunamadi veya hata: '+d.message,'error')}}catch(e){showToast('Arama hatasi: '+e.message,'error')};setSearching(false)}

  const statsData=iocStats?.stats||iocStats||{}
  const riskDist=statsData?.risk_distribution||iocStats?.risk_distribution||[]
  const weeklyGrowth=statsData?.weekly_growth||iocStats?.weekly_growth||[]
  const topThreats=statsData?.top_threats||iocStats?.top_threats||[]
  const sourceBreakdown=statsData?.source_breakdown||iocStats?.source_breakdown||[]
  const totalIocs=statsData?.total_iocs||iocStats?.total_iocs||iocStats?.total_records||0
  const highRisk=statsData?.high_risk_count||iocStats?.high_risk_count||0
  const mediumRisk=statsData?.medium_risk_count||iocStats?.medium_risk_count||0
  const lowRisk=statsData?.low_risk_count||iocStats?.low_risk_count||0

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <SectionHeader badge="IOC / Tuzak Modulu" title="Tehdit Istihbarati & IOC Analizi" subtitle={`${totalIocs.toLocaleString('tr-TR')}+ tehdit indikatoru. Gercek zamanli IOC taramasi, risk analizi ve kaynak dagilimi.`}/>
    <div style={{ display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:16, marginBottom:32 }}>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}><p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Toplam IOC</p><p style={{ fontSize:24, fontWeight:800, color:theme.primary }}><CountUp end={totalIocs}/></p></Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}><p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Yuksek Risk</p><p style={{ fontSize:24, fontWeight:800, color:theme.danger }}><CountUp end={highRisk}/></p></Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}><p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Orta Risk</p><p style={{ fontSize:24, fontWeight:800, color:theme.warning }}><CountUp end={mediumRisk}/></p></Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}><p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Dusuk Risk</p><p style={{ fontSize:24, fontWeight:800, color:theme.success }}><CountUp end={lowRisk}/></p></Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}><p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Kaynak</p><p style={{ fontSize:24, fontWeight:800, color:theme.warning }}>{sourceBreakdown.length}</p></Card>
    </div>
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:32 }}>
      <div>
        <Card style={{ marginBottom:24 }}>
          <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>📊 Risk Dagilimi</h3>
          {riskDist.length>0?<div style={{ display:'flex', flexDirection:'column', gap:10 }}>{riskDist.map((item,i)=>{const colors=['#22c55e','#84cc16','#f59e0b','#ff6b35','#ef4444'];return <div key={i}><div style={{ display:'flex', justifyContent:'space-between', fontSize:12, marginBottom:4 }}><span style={{ color:theme.textMuted }}>{item.range}</span><span style={{ color:'#fff', fontWeight:600 }}>{item.count} ({item.percentage?.toFixed(1)}%)</span></div><div style={{ height:10, background:theme.surface, borderRadius:5, overflow:'hidden' }}><div style={{ height:'100%', width:`${Math.min(item.percentage,100)}%`, background:colors[i]||theme.primary, borderRadius:5, transition:'width 1s ease' }}/></div></div>})}</div>:<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}
        </Card>
        <Card><h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:12 }}>📡 Kaynak Dagilimi</h3>{sourceBreakdown.length>0?sourceBreakdown.slice(0,8).map((s,i)=><div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${theme.border}` }}><span style={{ fontSize:13, color:theme.text }}>{s.source}</span><span style={{ fontSize:13, fontWeight:700, color:theme.primary }}>{(s.count||0).toLocaleString('tr-TR')}</span></div>):<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}</Card>
      </div>
      <div>
        <Card style={{ marginBottom:24 }}>
          <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>📈 Haftalik IOC Artisi</h3>
          {weeklyGrowth.length>0?<div style={{ display:'flex', gap:8, alignItems:'flex-end', height:160 }}>{weeklyGrowth.map((item,i)=>{const maxVal=Math.max(...weeklyGrowth.map(w=>w.count),1);const h=(item.count/maxVal)*100;return <div key={i} style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}><span style={{ fontSize:9, color:theme.textMuted }}>{item.count}</span><div style={{ width:'100%', height:`${h}%`, minHeight:4, background:`linear-gradient(to top, ${theme.primary}, ${theme.primary}88)`, borderRadius:'4px 4px 0 0', transition:'height 1s ease' }}/><span style={{ fontSize:8, color:theme.textMuted, transform:'rotate(-45deg)', marginTop:4, whiteSpace:'nowrap' }}>{item.date?.slice(5)||''}</span></div>})}</div>:<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}
        </Card>
        <Card><h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🔎</span> IOC Sorgula</h3>
          <div style={{ display:'flex', gap:8 }}><input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)} placeholder="IP, domain, URL veya hash..." style={{ flex:1, padding:'12px 16px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:13, outline:'none' }} onKeyDown={e=>e.key==='Enter'&&handleSearch()}/><GlowButton onClick={handleSearch} loading={searching}>Ara</GlowButton></div>
          {activeTab==='search-results'&&<div style={{ marginTop:16, maxHeight:300, overflowY:'auto' }}><p style={{ fontSize:12, color:theme.textMuted, marginBottom:8 }}>{searchResults.length} sonuc bulundu</p>{searchResults.length>0?searchResults.slice(0,15).map((item,i)=><div key={i} style={{ padding:'10px', marginBottom:6, background:theme.surface, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, fontSize:12 }}><div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}><span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11 }}>{item.value||item.ioc_value||item.ioc||item.indicator}</span><span style={{ padding:'2px 8px', borderRadius:'10px', fontSize:10, background:theme.accentDim, color:theme.accent }}>{item.ioc_type||item.type||item.threat_type||'unknown'}</span></div><p style={{ color:theme.textMuted, marginTop:4, fontSize:11 }}>Risk: {item.risk_score||'N/A'} • Kaynak: {item.source||'N/A'} • Tespit: {(item.detection_count||0)+'kez'}</p></div>):<p style={{ color:theme.textMuted, fontSize:13, textAlign:'center' }}>Sonuc bulunamadi</p>}</div>}
        </Card>
      </div>
    </div>
    <div style={{ display:'grid', gridTemplateColumns:'1fr 2fr', gap:24, marginBottom:48 }}>
      <Card><h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:12 }}>🔥 En Cok Gorulen Tehditler</h3>{topThreats.length>0?topThreats.slice(0,10).map((t,i)=><div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${theme.border}` }}><span style={{ fontSize:12, color:'#fff' }}>{i+1}. {(t.type||t.threat_type||t.name||'').toUpperCase()}</span><span style={{ fontSize:13, fontWeight:700, color:theme.danger }}>{(t.count||0).toLocaleString('tr-TR')}</span></div>):<p style={{ color:theme.textMuted, fontSize:13 }}>Veri yukleniyor...</p>}</Card>
      <Card><h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📋</span> Son Eklenen IOC'ler<span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>Son 25 kayit</span></h3>
        <div style={{ overflowX:'auto', maxHeight:400, overflowY:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}><tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:10, textTransform:'uppercase', letterSpacing:'1px' }}><th style={{ textAlign:'left', padding:'10px 6px' }}>Gosterge</th><th style={{ textAlign:'center', padding:'10px 6px' }}>Tur</th><th style={{ textAlign:'center', padding:'10px 6px' }}>Risk</th><th style={{ textAlign:'center', padding:'10px 6px' }}>Kaynak</th><th style={{ textAlign:'right', padding:'10px 6px' }}>Tarih</th></tr></thead>
            <tbody>{iocList.length===0&&<tr><td colSpan={5} style={{ textAlign:'center', padding:24, color:theme.textMuted }}>Veri yukleniyor...</td></tr>}
              {iocList.map((item,i)=><tr key={item.id||i} style={{ borderBottom:`1px solid ${theme.border}` }} onMouseEnter={e=>e.currentTarget.style.background=theme.surface} onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                <td style={{ padding:'8px 6px' }}><span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11, wordBreak:'break-all' }}>{item.value||item.ioc_value||item.ioc||item.indicator||'-'}</span></td>
                <td style={{ padding:'8px 6px', textAlign:'center' }}><span style={{ padding:'2px 6px', borderRadius:'8px', fontSize:10, background:theme.primaryDim, color:theme.primary }}>{item.type||item.ioc_type||'-'}</span></td>
                <td style={{ padding:'8px 6px', textAlign:'center' }}><span style={{ padding:'2px 6px', borderRadius:'8px', fontSize:10, fontWeight:600, background:(item.risk_score||0)>75?theme.accentDim:(item.risk_score||0)>40?theme.warning+'22':theme.primaryDim, color:(item.risk_score||0)>75?theme.accent:(item.risk_score||0)>40?theme.warning:theme.primary }}>{item.risk_score||item.risk_score||'-'}</span></td>
                <td style={{ padding:'8px 6px', textAlign:'center', color:theme.textMuted, fontSize:11 }}>{item.source||'-'}</td>
                <td style={{ padding:'8px 6px', textAlign:'right', color:theme.textMuted, fontSize:10 }}>{item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):item.date?new Date(item.date).toLocaleDateString('tr-TR'):'-'}</td>
              </tr>)}
            </tbody>
          </table>
        </div>
      </Card>
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
  const [stats, setStats] = useState(null)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  useEffect(()=>{loadStats()},[])
  async function loadStats(){try{const r=await fetch(`${API}/breach/stats`);const d=await r.json();setStats(d)}catch{}}

  async function handleCheck() {
    if(!email||!email.includes('@')){showToast('Gecerli bir e-posta adresi girin','error');return}
    setChecking(true);setResult(null)
    try{
      const r=await fetch(`${API}/breach/check-email`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email})})
      if(!r.ok){const e=await r.json();throw new Error(e.message||e.detail||'Sorgu hatasi')}
      const d=await r.json();setResult(d)
    }catch(e){showToast('Sorgu hatasi: '+e.message,'error')}
    setChecking(false)
  }

  function showToast(msg,t='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(t=>({...t,visible:false})),3000)}

  const riskDefs=stats?.risk_score_definitions||{}
  const socialImpact=stats?.social_impact||{}

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>
    <SectionHeader badge="Sizinti Istihbarati" title="Veri Ihlali & Dark Web Taramasi" subtitle="E-posta adresinizin sizdirilip sizdirilmadigini kontrol edin. HIBP, dark web ve sizinti veritabanlarinda arama yapin."/>
    <div style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:16, marginBottom:32 }}>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Izlenen E-posta</p><p style={{ fontSize:28, fontWeight:800, color:theme.primary }}>{stats?.monitored_emails||0}</p></Card>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Takip Edilen Ihlal</p><p style={{ fontSize:28, fontWeight:800, color:theme.danger }}>{stats?.total_tracked_breaches||0}</p></Card>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Risk Turu</p><p style={{ fontSize:28, fontWeight:800, color:theme.warning }}>{Object.keys(riskDefs).length}</p></Card>
      <Card style={{ textAlign:'center', padding:'20px' }}><p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Sosyal Etki</p><p style={{ fontSize:28, fontWeight:800, color:theme.accent }}>{socialImpact.risk_level||'N/A'}</p></Card>
    </div>
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}>
      <div>
        <Card style={{ marginBottom:24 }}><h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🔓</span> Sizinti Kontrolu Nedir?</h3>
          <p style={{ fontSize:13, color:theme.textDim, lineHeight:1.7 }}>Veri ihlalleri, hackerlarin sirket veritabanlarini ele gecirmesiyle milyonlarca kullanicinin e-posta, sifre ve kisisel bilgilerinin internete sizmasina neden olur. Bu modul, <strong style={{ color:'#fff' }}>Have I Been Pwned</strong>, <strong style={{ color:'#fff' }}>dark web forumlari</strong> ve <strong style={{ color:'#fff' }}>sizinti veritabanlarinda</strong> tarama yapar.</p>
        </Card>
        <Card><h3 style={{ fontSize:14, fontWeight:700, color:'#fff', marginBottom:12 }}>📡 Risk Skorlari</h3><div style={{ display:'flex', flexDirection:'column', gap:6 }}>{Object.entries(riskDefs).length>0?Object.entries(riskDefs).slice(0,10).map(([k,v])=><div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'6px 0', borderBottom:`1px solid ${theme.border}`, fontSize:12 }}><span style={{ color:theme.text }}>{k}</span><span style={{ fontWeight:700, color:v>70?theme.danger:v>40?theme.warning:theme.textMuted }}>{v} puan</span></div>):<p style={{ color:theme.textMuted, fontSize:13 }}>Risk tanimlari yukleniyor...</p>}</div></Card>
      </div>
      <Card><h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>🔍</span> E-posta Sizinti Kontrolu</h3>
        <p style={{ fontSize:13, color:theme.textDim, marginBottom:16 }}>E-posta adresinizi girin, veri ihlallerinde sizdirilip sizdirilmadigini kontrol edelim.</p>
        <div style={{ display:'flex', gap:8, marginBottom:16 }}>
          <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="ornek@email.com" style={{ flex:1, padding:'14px 18px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:14, outline:'none' }} onKeyDown={e=>e.key==='Enter'&&handleCheck()}/>
          <GlowButton onClick={handleCheck} loading={checking} disabled={!email||!email.includes('@')}>{checking?'Taranıyor...':'🔍 Sorgula'}</GlowButton>
        </div>
        <p style={{ fontSize:11, color:theme.textMuted }}>Not: HIBP API anahtari gerektirir. Su an demo modda calismaktadir.</p>
        {result&&<div style={{ animation:'scaleIn 0.3s ease', marginTop:24, padding:20, background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
          {result.status==='error'?<div style={{ textAlign:'center', padding:20 }}><span style={{ fontSize:48, display:'block', marginBottom:12 }}>⚠️</span><p style={{ color:theme.warning, fontSize:16, fontWeight:600 }}>{result.message}</p><p style={{ color:theme.textMuted, fontSize:12, marginTop:8 }}>{result.hint}</p></div>
          :result.compromised?<><div style={{ textAlign:'center', marginBottom:16 }}><span style={{ fontSize:48 }}>⚠️</span><p style={{ color:theme.danger, fontSize:18, fontWeight:700, marginTop:8 }}>Sizinti Tespit Edildi!</p></div>{(result.breaches||[]).map((b,i)=><div key={i} style={{ padding:'10px 14px', marginBottom:8, background:theme.accentDim, borderRadius:theme.radiusSm, borderLeft:`3px solid ${theme.accent}` }}><p style={{ fontSize:13, fontWeight:600, color:'#fff' }}>{b.name||b.source||'Bilinmeyen'}</p><p style={{ fontSize:11, color:theme.textMuted }}>{b.date?new Date(b.date).toLocaleDateString('tr-TR'):''} — {(b.data_classes||b.data||[]).join(', ')}</p></div>)}</>
          :<div style={{ textAlign:'center', padding:20 }}><span style={{ fontSize:48 }}>✅</span><p style={{ color:theme.success, fontSize:18, fontWeight:700, marginTop:8 }}>Sizinti Bulunamadi</p><p style={{ color:theme.textMuted, fontSize:13, marginTop:4 }}>{email} adresi bilinen sizintilarda yok</p></div>}
        </div>}
      </Card>
    </div>
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}>
      <Card><h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🛡️</span> Sifre Guvenlik Onerileri</h3><div style={{ display:'flex', flexDirection:'column', gap:10 }}>
        {[{icon:'🔑',title:'Essiz Sifre Kullanin',desc:'Her platform icin farkli sifre olusturun'},{icon:'📏',title:'Uzunluk Onemli',desc:'En az 12 karakter, buyuk/kucuk harf + rakam + sembol'},{icon:'🔄',title:'Duzenli Degistirin',desc:'90 gunde bir sifrelerinizi yenileyin'},{icon:'🔐',title:'2FA Acin',desc:'Iki faktorlu kimlik dogrulama kullanin'},{icon:'🕵️',title:'Parola Yoneticisi',desc:'Bitwarden, 1Password gibi araclar kullanin'}].map((item,i)=><div key={i} style={{ display:'flex', gap:12, alignItems:'flex-start', padding:'10px 14px', background:theme.surface, borderRadius:theme.radiusSm }}><span style={{ fontSize:24 }}>{item.icon}</span><div><p style={{ fontSize:13, fontWeight:600, color:'#fff' }}>{item.title}</p><p style={{ fontSize:12, color:theme.textMuted }}>{item.desc}</p></div></div>)}
      </div></Card>
      <Card><h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🚨</span> Sizinti Sonrasi Mudahale</h3><div style={{ display:'flex', flexDirection:'column', gap:10 }}>
        {[{step:'01',title:'Panik Yapmayin',desc:'Sakin olun ve adim adim ilerleyin'},{step:'02',title:'Sifrenizi Hemen Degistirin',desc:'Sizdirilan platformdaki sifrenizi yenileyin'},{step:'03',title:'Tum Platformlari Guncelleyin',desc:'Ayni sifreyi kullandiginiz yerleri degistirin'},{step:'04',title:'2FA Aktiflestirin',desc:'Tum kritik hesaplarda 2FA acin'},{step:'05',title:'Hesap Aktivitesini Kontrol Edin',desc:'Supheli girisleri inceleyin'},{step:'06',title:'Izlemeye Devam Edin',desc:'Bu modul ile duzenli kontrol yapin'}].map((item,i)=><div key={i} style={{ display:'flex', gap:12, alignItems:'flex-start' }}><span style={{ width:28, height:28, borderRadius:'50%', background:theme.primaryDim, color:theme.primary, display:'flex', alignItems:'center', justifyContent:'center', fontSize:12, fontWeight:700, flexShrink:0 }}>{item.step}</span><div><p style={{ fontSize:13, fontWeight:600, color:'#fff' }}>{item.title}</p><p style={{ fontSize:12, color:theme.textMuted }}>{item.desc}</p></div></div>)}
      </div></Card>
    </div>
    <Card><h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📋</span> Bilinen Buyuk Veri Ihlalleri</h3>
      <div style={{ overflowX:'auto' }}><table style={{ width:'100%', borderCollapse:'collapse', fontSize:13 }}>
        <thead><tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:11, textTransform:'uppercase', letterSpacing:'1px' }}><th style={{ textAlign:'left', padding:'12px 8px' }}>Ihlal</th><th style={{ textAlign:'left', padding:'12px 8px' }}>Sirket</th><th style={{ textAlign:'center', padding:'12px 8px' }}>Sizan Veri</th><th style={{ textAlign:'center', padding:'12px 8px' }}>Boyut</th><th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th></tr></thead>
        <tbody>{[
          {name:'Collection #1',company:'Multiple',data:'Email, Password',size:'773M',date:'2019-01'},
          {name:'LinkedIn',company:'LinkedIn',data:'Email, Password',size:'500M',date:'2021-06'},
          {name:'Facebook',company:'Meta',data:'Phone, Email, Name',size:'533M',date:'2021-04'},
          {name:'Twitter',company:'X Corp',data:'Email, Username',size:'235M',date:'2022-12'},
          {name:'Adobe',company:'Adobe',data:'Email, Password, CC',size:'153M',date:'2013-10'},
          {name:'Dropbox',company:'Dropbox',data:'Email, Password',size:'69M',date:'2012-07'},
          {name:'Yahoo',company:'Yahoo',data:'Email, Password, Name',size:'3B',date:'2013-08'},
          {name:'Marriott',company:'Marriott',data:'Passport, Name, Email',size:'500M',date:'2018-11'},
        ].map((b,i)=><tr key={i} style={{ borderBottom:`1px solid ${theme.border}` }} onMouseEnter={e=>e.currentTarget.style.background=theme.surface} onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
          <td style={{ padding:'10px 8px' }}><span style={{ color:'#fff', fontWeight:600 }}>{b.name}</span></td>
          <td style={{ padding:'10px 8px', color:theme.textMuted }}>{b.company}</td>
          <td style={{ padding:'10px 8px', textAlign:'center', fontSize:12 }}>{b.data}</td>
          <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'2px 8px', borderRadius:'10px', fontSize:11, background:theme.primaryDim, color:theme.primary }}>{b.size}</span></td>
          <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:11 }}>{b.date}</td>
        </tr>)}</tbody></table></div>
    </Card>
  </div>
}
