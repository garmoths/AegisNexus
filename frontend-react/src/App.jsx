import { useState, useEffect, useRef, useCallback } from 'react'

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

/* ======================================
     UTILITY COMPONENTS
  ====================================== */

function Spinner({ size = 20 }) {
  return <span style={{ display:'inline-block', width:size, height:size, border:'2px solid rgba(255,255,255,0.2)', borderTop:'2px solid #fff', borderRadius:'50%', animation:'spin 0.8s linear infinite' }} />
}

function Toast({ message, type = 'success', visible }) {
  if (!visible) return null
  return <div style={{ position:'fixed', bottom:30, right:30, zIndex:9999, padding:'14px 24px', borderRadius:theme.radiusSm, background:type==='success'?'#22c55e':'#ef4444', color:'#fff', fontWeight:600, fontSize:14, boxShadow:'0 10px 40px rgba(0,0,0,0.4)', animation:'fadeInUp 0.3s ease' }}>{type==='success'?'✅ ':'❌ '}{message}</div>
}

function RiskBadge({ level, size = 'sm' }) {
  const colors = {
    critical: { bg:'rgba(239,68,68,0.2)', text:'#ef4444' },
    high: { bg:'rgba(255,107,53,0.2)', text:'#ff6b35' },
    medium: { bg:'rgba(245,158,11,0.2)', text:'#f59e0b' },
    low: { bg:'rgba(34,197,94,0.2)', text:'#22c55e' },
    safe: { bg:'rgba(0,212,255,0.2)', text:'#00d4ff' },
  }
  const c = colors[level] || { bg:'rgba(100,116,139,0.2)', text:'#64748b' }
  const labels = { critical:'🔴 Kritik', high:'🟠 Yüksek', medium:'🟡 Orta', low:'🟢 Düşük', safe:'🔵 Güvenli' }
  return <span style={{ display:'inline-block', padding:size==='sm'?'3px 10px':'6px 16px', background:c.bg, color:c.text, borderRadius:'20px', fontSize:size==='sm'?11:13, fontWeight:700, textTransform:'uppercase', letterSpacing:'0.5px' }}>{labels[level]||level}</span>
}

function StatusDot({ active }) {
  return <span style={{ display:'inline-block', width:8, height:8, borderRadius:'50%', background:active?theme.success:theme.danger, boxShadow:`0 0 8px ${active?theme.success:theme.danger}66`, marginRight:6 }} />
}

function Spacer({ h = 24 }) { return <div style={{ height:h }} /> }

/* ======================================
     CARD
  ====================================== */
function Card({ children, style, hover = true, ...props }) {
  const [h, sH] = useState(false)
  return <div onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)} style={{ background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`, border:`1px solid ${h?theme.primary+'66':theme.border}`, borderRadius:theme.radius, padding:24, transition:'all 0.3s cubic-bezier(0.175,0.885,0.32,1.275)', boxShadow:h?theme.glow:'none', transform:h?'translateY(-2px)':'none', ...style }} {...props}>{children}</div>
}

/* ======================================
     GLOW BUTTON
  ====================================== */
function GlowButton({ children, onClick, disabled, loading, variant = 'primary', style, ...props }) {
  const isPrimary = variant === 'primary'
  return <button onClick={onClick} disabled={disabled||loading} style={{ padding:'14px 32px', borderRadius:theme.radiusSm, border:'none', cursor:disabled?'not-allowed':'pointer', fontSize:14, fontWeight:700, letterSpacing:'0.5px', background:isPrimary?`linear-gradient(135deg, ${theme.primary}, #0099cc)`:'transparent', color:isPrimary?'#000':theme.primary, border:isPrimary?'none':`1px solid ${theme.primary}44`, transition:'all 0.3s ease', opacity:disabled?0.5:1, display:'inline-flex', alignItems:'center', gap:8, boxShadow:isPrimary?'0 4px 20px rgba(0,212,255,0.3)':'none', ...style }} onMouseEnter={e=>{if(!disabled){e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow='0 8px 30px rgba(0,212,255,0.4)'}}} onMouseLeave={e=>{e.currentTarget.style.transform='none';e.currentTarget.style.boxShadow=isPrimary?'0 4px 20px rgba(0,212,255,0.3)':'none'}} {...props}>{loading&&<Spinner size={18}/>}{children}</button>
}

/* ======================================
     COUNT UP
  ====================================== */
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

/* ======================================
     RISK GAUGE
  ====================================== */
function RiskGauge({ score, label }) {
  const c = 2 * Math.PI * 40
  const o = c - (Math.min(score,100) / 100) * c
  const color = score > 75 ? theme.danger : score > 50 ? theme.warning : score > 25 ? theme.primary : theme.success
  return <div style={{ display:'inline-flex', flexDirection:'column', alignItems:'center' }}>
    <svg width="120" height="120" viewBox="0 0 100 100">
      <circle cx="50" cy="50" r="40" fill="none" stroke={theme.border} strokeWidth="8" />
      <circle cx="50" cy="50" r="40" fill="none" stroke={color} strokeWidth="8" strokeDasharray={c} strokeDashoffset={o} transform="rotate(-90 50 50)" style={{ transition:'stroke-dashoffset 1s ease' }} strokeLinecap="round" />
      <text x="50" y="50" textAnchor="middle" dominantBaseline="central" fill="#fff" fontSize="22" fontWeight="800" fontFamily="'Inter', sans-serif">{score}</text>
    </svg>
    <p style={{ fontSize:12, color:theme.textMuted, marginTop:8, fontWeight:600 }}>{label}</p>
  </div>
}

/* ======================================
     SECTION HEADER
  ====================================== */
function SectionHeader({ badge, title, subtitle }) {
  return <div style={{ textAlign:'center', marginBottom:48 }}>
    <span style={{ display:'inline-block', padding:'6px 16px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'20px', fontSize:11, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'1.5px', marginBottom:16 }}>{badge}</span>
    <h1 style={{ fontSize:36, fontWeight:800, color:'#fff', marginBottom:12, letterSpacing:'-1px' }}>{title}</h1>
    <p style={{ color:theme.textMuted, fontSize:16, maxWidth:600, margin:'0 auto', lineHeight:1.6 }}>{subtitle}</p>
  </div>
}

/* ======================================
     MAIN APP
  ====================================== */
export default function App() {
  const [page, setPage] = useState('landing')

  const tabs = [
    { id: 'landing', label: 'Ana Sayfa', icon: '🏠' },
    { id: 'ai-analyzer', label: 'AI Analiz', icon: '🤖' },
    { id: 'phishing-detector', label: 'Phishing', icon: '🎣' },
    { id: 'honeypot', label: 'IOC / Tuzak', icon: '🕸️' },
    { id: 'breach-intel', label: 'Sızıntı', icon: '🔓' },
  ]

  return <div style={{ minHeight:'100vh', background:theme.bg, color:theme.text }}>
    <style>{`
      @keyframes spin { to { transform: rotate(360deg) } }
      @keyframes fadeInUp { from { opacity:0; transform:translateY(20px) } to { opacity:1; transform:translateY(0) } }
      @keyframes slideInLeft { from { opacity:0; transform:translateX(-30px) } to { opacity:1; transform:translateX(0) } }
      @keyframes slideInRight { from { opacity:0; transform:translateX(30px) } to { opacity:1; transform:translateX(0) } }
      @keyframes scaleIn { from { opacity:0; transform:scale(0.9) } to { opacity:1; transform:scale(1) } }
      @keyframes float { 0%,100% { transform:translateY(0) } 50% { transform:translateY(-10px) } }
      * { scrollbar-width:thin; scrollbar-color:${theme.border} transparent; }
      ::-webkit-scrollbar { width:6px }
      ::-webkit-scrollbar-track { background:transparent }
      ::-webkit-scrollbar-thumb { background:${theme.border}; border-radius:3px }
      textarea, input { font-family:${theme.mono} }
    `}</style>

    {/* ===== NAVBAR ===== */}
    <Navbar page={page} setPage={setPage} tabs={tabs} />

    <main style={{ paddingTop:86, maxWidth:1400, margin:'0 auto', padding:'86px 24px 0' }}>
      {page === 'landing' && <LandingPage setPage={setPage} />}
      {page === 'ai-analyzer' && <AIAnalyzer />}
      {page === 'phishing-detector' && <PhishingDetector />}
      {page === 'honeypot' && <HoneypotIOC />}
      {page === 'breach-intel' && <BreachIntel />}
    </main>
    <Footer />
  </div>
}

/* ======================================
     NAVBAR
  ====================================== */
function Navbar({ page, setPage, tabs }) {
  const [scrolled, setScrolled] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  useEffect(() => { const onScroll = () => setScrolled(window.scrollY>20); window.addEventListener('scroll',onScroll,{passive:true}); return ()=>window.removeEventListener('scroll',onScroll) }, [])

  return <nav style={{ position:'fixed', top:0, left:0, right:0, zIndex:1000, background:scrolled?'rgba(8,12,20,0.95)':'rgba(8,12,20,0.8)', backdropFilter:'blur(20px)', borderBottom:`1px solid ${scrolled?theme.border:'transparent'}`, transition:'all 0.3s ease', padding:'0 24px' }}>
    <div style={{ maxWidth:1400, margin:'0 auto', display:'flex', alignItems:'center', justifyContent:'space-between', height:70 }}>
      <div style={{ display:'flex', alignItems:'center', gap:12, cursor:'pointer' }} onClick={()=>setPage('landing')}>
        <svg width="36" height="36" viewBox="0 0 36 36" fill="none">
          <path d="M18 4L6 11V18C6 23.5 10 28.5 18 30C26 28.5 30 23.5 30 18V11L18 4Z" stroke="#00d4ff" strokeWidth="2" fill="none"/>
          <path d="M14 18L17 21L23 15" stroke="#00d4ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
        <span style={{ fontSize:20, fontWeight:700, color:'#fff', letterSpacing:'-0.5px' }}>Aegis<span style={{ color:theme.primary }}>Nexus</span></span>
      </div>
      <div style={{ display:'flex', gap:4, background:theme.surface, borderRadius:theme.radiusSm, padding:3 }}>
        {tabs.map(t => <button key={t.id} onClick={()=>setPage(t.id)} style={{ padding:'8px 18px', borderRadius:'6px', border:'none', cursor:'pointer', fontSize:13, fontWeight:600, background:page===t.id?theme.primary:'transparent', color:page===t.id?'#000':theme.textMuted, transition:'all 0.2s ease', display:'flex', alignItems:'center', gap:6 }}><span>{t.icon}</span><span style={{ display:window.innerWidth<768?'none':'inline' }}>{t.label}</span></button>)}
      </div>
    </div>
  </nav>
}

/* ======================================
     FOOTER
  ====================================== */
function Footer() {
  return <footer style={{ borderTop:`1px solid ${theme.border}`, padding:'24px', textAlign:'center', color:theme.textMuted, fontSize:13, marginTop:80 }}>
    <div style={{ maxWidth:1400, margin:'0 auto' }}>
      <p>AegisNexus — Enterprise Cybersecurity Platform &copy; 2026</p>
      <div style={{ display:'flex', gap:24, justifyContent:'center', marginTop:12 }}>
        <a href={API+'/docs'} style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">API Docs</a>
        <a href="/api/health" style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">Health</a>
        <a href="https://github.com/garmoths/AegisNexus" style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">GitHub</a>
      </div>
    </div>
  </footer>
}

/* ======================================
     LANDING PAGE
  ====================================== */
function LandingPage({ setPage }) {
  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    {/* HERO */}
    <div style={{ textAlign:'center', padding:'80px 0 60px', position:'relative', overflow:'hidden' }}>
      {/* Background glow */}
      <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', width:600, height:600, background:'radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 70%)', pointerEvents:'none' }} />
      <div style={{ position:'relative', zIndex:1 }}>
        <span style={{ display:'inline-block', padding:'8px 20px', background:theme.primaryDim, border:`1px solid ${theme.primary}33`, borderRadius:'20px', fontSize:12, fontWeight:700, color:theme.primary, textTransform:'uppercase', letterSpacing:'2px', marginBottom:24 }}>🛡️ 5 Katmanlı Güvenlik Kalkanı</span>
        <h1 style={{ fontSize:'clamp(36px, 6vw, 64px)', fontWeight:900, color:'#fff', lineHeight:1.1, marginBottom:20, letterSpacing:'-2px' }}>
          Siber Tehditlere Karşı<br />
          <span style={{ background:`linear-gradient(135deg, ${theme.primary}, #0099cc)`, WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>Proaktif Koruma</span>
        </h1>
        <p style={{ color:theme.textMuted, fontSize:'clamp(16px, 2vw, 20px)', maxWidth:680, margin:'0 auto', lineHeight:1.7, marginBottom:40 }}>
          Bireyler ve KOBİ'ler için yapay zeka destekli, gerçek zamanlı siber güvenlik platformu. 
          Phishing, veri sızıntıları ve sosyal mühendislik saldırılarına karşı 5 katmanlı koruma.
        </p>
        <div style={{ display:'flex', gap:16, justifyContent:'center', flexWrap:'wrap' }}>
          <GlowButton onClick={()=>setPage('ai-analyzer')}>🤖 AI Analizi Dene</GlowButton>
          <GlowButton variant="outline" onClick={()=>setPage('phishing-detector')}>🎣 Phishing Tara</GlowButton>
          <GlowButton variant="outline" onClick={()=>window.open('https://modules.aegisnexus.dev','_blank')}>📦 Tüm Modüller</GlowButton>
        </div>
      </div>
    </div>

    {/* STATS BANNER */}
    <LiveStatsBanner />

    {/* MODÜLLER */}
    <div style={{ marginBottom:80 }}>
      <h2 style={{ fontSize:28, fontWeight:800, color:'#fff', textAlign:'center', marginBottom:48, letterSpacing:'-1px' }}>
        Güvenlik <span style={{ color:theme.primary }}>Modülleri</span>
      </h2>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(280px, 1fr))', gap:24 }}>
        {[
          { icon:'🤖', title:'AI Güvenlik Asistanı', desc:'DeepSeek/Groq LLM ile mesaj, e-posta ve metin analizi. Phishing, sosyal mühendislik ve psikolojik manipülasyon tespiti.', color:theme.primary, badge:'YENİ', page:'ai-analyzer' },
          { icon:'🎣', title:'Phishing Dedektörü', desc:'1.2M+ phishing URL veritabanı ile anlık URL güvenlik kontrolü. DNS, SSL ve makine öğrenimi analizi.', color:theme.accent, badge:'1.2M DB', page:'phishing-detector' },
          { icon:'🕸️', title:'IOC / Tuzak Sistemi', desc:'Saldırganlardan toplanan 9K+ IOC. IP, domain, URL ve hash analizi. Gerçek zamanlı tehdit istihbaratı.', color:theme.warning, badge:'9K IOC', page:'honeypot' },
          { icon:'🔓', title:'Veri Sızıntı Radarı', desc:'Have I Been Pwned, dark web ve sızıntı veritabanlarında e-posta taraması. KVKK uyumlu raporlama.', color:theme.danger, badge:'GELİYOR', page:'breach-intel' },
          { icon:'🔐', title:'Kriptografik Kalkan', desc:'Yüz yıllar süren şifreler oluşturun. AES-256 şifreleme ile güvenli şifre yönetimi.', color:theme.success, badge:'GELİYOR', page:'landing' },
          { icon:'⚡', title:'Tehdit Yanıtlayıcı', desc:'IOC verilerini operatörlere anlık uyar. Otomatik müdahale ve raporlama sistemi.', color:theme.primary, badge:'GELİYOR', page:'landing' },
        ].map((m,i) => <ModuleCard key={i} {...m} onClick={()=>m.page!=='landing'&&setPage(m.page)} />)}
      </div>
    </div>

    {/* İSTATİSTİKLER */}
    <div style={{ marginBottom:80 }}>
      <h2 style={{ fontSize:28, fontWeight:800, color:'#fff', textAlign:'center', marginBottom:48, letterSpacing:'-1px' }}>
        Platform <span style={{ color:theme.primary }}>İstatistikleri</span>
      </h2>
      <PlatformStats />
    </div>

    {/* NEDEN AEGIS NEXUS */}
    <div style={{ marginBottom:80 }}>
      <h2 style={{ fontSize:28, fontWeight:800, color:'#fff', textAlign:'center', marginBottom:48, letterSpacing:'-1px' }}>
        Neden <span style={{ color:theme.primary }}>AegisNexus</span>?
      </h2>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(300px, 1fr))', gap:24 }}>
        {[
          { icon:'🧠', title:'Yapay Zeka Destekli', desc:'DeepSeek ve Groq AI modelleri ile gerçek zamanlı tehdit analizi. Saniyeler içinde phishing ve sosyal mühendislik tespiti.' },
          { icon:'🌐', title:'Gerçek Zamanlı İstihbarat', desc:'1.2M+ phishing URL, 9K+ IOC, AbuseIPDB, URLhaus, AlienVault OTX gibi 10+ kaynaktan beslenen tehdit istihbaratı.' },
          { icon:'🛡️', title:'5 Katmanlı Koruma', desc:'AI Analiz → Phishing Tarama → IOC Tespit → Sızıntı Kontrolü → Kriptografik Koruma. Her açıdan güvende olun.' },
          { icon:'🇹🇷', title:'Turkce ve KVKK Uyumlu', desc:'Tamamen Turkce arayuz. KVKK ve GDPR uyumlu veri isleme. Turkiyedeki siber tehditlere ozel analiz.', color:theme.success, badge:'GELIYOR', page:'landing' },
          { icon:'🔒', title:'Gizlilik Odaklı', desc:'Hiçbir veriniz üçüncü taraflarla paylaşılmaz. Şifreleriniz sadece sizin bilgisayarınızda oluşturulur.' },
          { icon:'📊', title:'Detaylı Raporlama', desc:'Her analiz için kapsamlı raporlar. PDF export, e-posta bildirimleri ve dashboard ile takip.' },
        ].map((item,i) => <Card key={i} style={{ textAlign:'center', padding:'32px 24px' }}>
          <span style={{ fontSize:48, display:'block', marginBottom:16, animation:'float 3s ease-in-out infinite', animationDelay:`${i*0.3}s` }}>{item.icon}</span>
          <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:12 }}>{item.title}</h3>
          <p style={{ fontSize:14, color:theme.textMuted, lineHeight:1.7 }}>{item.desc}</p>
        </Card>)}
      </div>
    </div>

    {/* İLETİŞİM / CTA */}
    <div style={{ textAlign:'center', padding:'60px 0 40px', borderTop:`1px solid ${theme.border}` }}>
      <h2 style={{ fontSize:28, fontWeight:800, color:'#fff', marginBottom:16 }}>Hemen Kullanmaya Başla</h2>
      <p style={{ color:theme.textMuted, fontSize:16, marginBottom:32, maxWidth:500, margin:'0 auto 32px' }}>Ücretsiz hesap oluşturun, 5 katmanlı güvenlik kalkanı ile dijital dünyada güvende olun.</p>
      <div style={{ display:'flex', gap:16, justifyContent:'center', flexWrap:'wrap' }}>
        <GlowButton onClick={()=>setPage('ai-analyzer')}>🚀 Hemen Dene</GlowButton>
        <GlowButton variant="outline" onClick={()=>window.open('https://github.com/garmoths/AegisNexus','_blank')}>💻 GitHub</GlowButton>
      </div>
    </div>
  </div>
}

/* ======================================
     MODULE CARD
  ====================================== */
function ModuleCard({ icon, title, desc, color, badge, onClick }) {
  const [h, sH] = useState(false)
  return <div onClick={onClick} onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)} style={{ background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`, border:`1px solid ${h?color+'66':theme.border}`, borderRadius:theme.radius, padding:'32px 24px', cursor:onClick?'pointer':'default', transition:'all 0.3s cubic-bezier(0.175,0.885,0.32,1.275)', boxShadow:h?`0 0 40px ${color}11`:'none', transform:h?'translateY(-4px)':'none', position:'relative', overflow:'hidden' }}>
    <div style={{ position:'absolute', top:0, right:0, width:150, height:150, background:`radial-gradient(circle, ${color}11 0%, transparent 70%)`, pointerEvents:'none' }} />
    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:16 }}>
      <span style={{ fontSize:40 }}>{icon}</span>
      {badge && <span style={{ padding:'3px 10px', borderRadius:'12px', fontSize:10, fontWeight:700, background:color+'22', color:color }}>{badge}</span>}
    </div>
    <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:10, letterSpacing:'-0.5px' }}>{title}</h3>
    <p style={{ fontSize:13, color:theme.textMuted, lineHeight:1.7 }}>{desc}</p>
  </div>
}

/* ======================================
     LIVE STATS BANNER
  ====================================== */
function LiveStatsBanner() {
  const [stats, setStats] = useState(null)
  const [iocStats, setIocStats] = useState(null)
  useEffect(() => {
    Promise.all([
      fetch(`${API}/phishing/stats`).then(r=>r.json()),
      fetch(`${API}/honeypot/ioc/stats`).then(r=>r.json()),
    ]).then(([ph, ioc]) => { setStats(ph); setIocStats(ioc) }).catch(()=>{})
  }, [])
  const totalUrls = stats?.stats?.total_urls || 0
  const totalIocs = iocStats?.stats?.total_iocs || iocStats?.total_records || 0
  return <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(200px, 1fr))', gap:16, marginBottom:80 }}>
    <Card style={{ textAlign:'center', padding:'24px 16px' }}>
      <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Taranan URL</p>
      <p style={{ fontSize:32, fontWeight:800, color:theme.primary }}><CountUp end={totalUrls} /></p>
    </Card>
    <Card style={{ textAlign:'center', padding:'24px 16px' }}>
      <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Tehdit İndikatörü</p>
      <p style={{ fontSize:32, fontWeight:800, color:theme.accent }}><CountUp end={totalIocs} /></p>
    </Card>
    <Card style={{ textAlign:'center', padding:'24px 16px' }}>
      <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>AI Analiz</p>
      <p style={{ fontSize:32, fontWeight:800, color:theme.warning }}><CountUp end={0} />+</p>
    </Card>
    <Card style={{ textAlign:'center', padding:'24px 16px' }}>
      <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Güvenlik Duvarı</p>
      <p style={{ fontSize:32, fontWeight:800, color:theme.success }}>5 Kat</p>
    </Card>
  </div>
}

/* ======================================
     PLATFORM STATS
  ====================================== */
function PlatformStats() {
  const [phStats, setPhStats] = useState(null)
  const [iocStats, setIocStats] = useState(null)
  useEffect(() => {
    Promise.all([
      fetch(`${API}/phishing/stats`).then(r=>r.json()).catch(()=>{}),
      fetch(`${API}/honeypot/ioc/stats`).then(r=>r.json()).catch(()=>{}),
    ]).then(([ph, ioc]) => { setPhStats(ph); setIocStats(ioc) })
  }, [])

  const stats = iocStats?.stats || iocStats || {}
  const riskDist = stats?.risk_distribution || []
  const weeklyGrowth = stats?.weekly_growth || []
  const topThreats = stats?.top_threats || []

  return <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24 }}>
    {/* Risk Distribution */}
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16 }}>📊 IOC Risk Dağılımı</h3>
      {riskDist.length > 0 ? <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
        {riskDist.map((item,i) => { const colors=['#22c55e','#84cc16','#f59e0b','#ff6b35','#ef4444']; return <div key={i}>
          <div style={{ display:'flex', justifyContent:'space-between', fontSize:12, marginBottom:4 }}>
            <span style={{ color:theme.textMuted }}>{item.range}</span>
            <span style={{ color:'#fff', fontWeight:600 }}>{item.count}</span>
          </div>
          <div style={{ height:8, background:theme.surface, borderRadius:4, overflow:'hidden' }}>
            <div style={{ height:'100%', width:`${Math.min(item.percentage,100)}%`, background:colors[i]||theme.primary, borderRadius:4, transition:'width 1s ease' }} />
          </div>
        </div> })}
      </div> : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
    </Card>

    {/* Weekly Growth */}
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16 }}>📈 Haftalık IOC Artışı</h3>
      {weeklyGrowth.length > 0 ? <div style={{ display:'flex', gap:8, alignItems:'flex-end', height:160 }}>
        {weeklyGrowth.map((item,i) => {
          const maxVal = Math.max(...weeklyGrowth.map(w=>w.count), 1)
          const height = (item.count / maxVal) * 100
          return <div key={i} style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}>
            <span style={{ fontSize:10, color:theme.textMuted }}>{item.count}</span>
            <div style={{ width:'100%', height:`${height}%`, minHeight:4, background:`linear-gradient(to top, ${theme.primary}, ${theme.primary}88)`, borderRadius:'4px 4px 0 0', transition:'height 1s ease' }} />
            <span style={{ fontSize:9, color:theme.textMuted, whiteSpace:'nowrap' }}>{item.date?.slice(5) || ''}</span>
          </div>
        })}
      </div> : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
    </Card>

    {/* Top Threats */}
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12 }}>🔥 En Çok Görülen Tehditler</h3>
      {topThreats.length > 0 ? topThreats.slice(0,8).map((t,i) => <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${theme.border}` }}>
        <span style={{ fontSize:13, color:'#fff' }}>{i+1}. {t.type || t.threat_type || t.name}</span>
        <span style={{ fontSize:13, fontWeight:700, color:theme.danger }}>{t.count}</span>
      </div>) : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
    </Card>

    {/* Source Breakdown */}
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12 }}>📡 Veri Kaynakları</h3>
      {(stats?.source_breakdown || []).slice(0,8).map((s,i) => <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${theme.border}` }}>
        <span style={{ fontSize:13, color:theme.textMuted }}>{s.source}</span>
        <span style={{ fontSize:13, fontWeight:700, color:theme.primary }}>{(s.count||0).toLocaleString('tr-TR')}</span>
      </div>)}
    </Card>
  </div>
}

/* ======================================
     AI ANALYZER PAGE
  ====================================== */
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
    if (!message || message.length < 10) {
      showToast('Lütfen en az 10 karakter girin', 'error'); return
    }
    setAnalyzing(true); setResult(null)
    try {
      const r = await fetch(`${API}/ai-analyzer/analyze`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ message, context }),
      })
      if (!r.ok) { const e = await r.json(); throw new Error(e.detail || 'Analiz hatası') }
      const d = await r.json()
      setResult(d)
      loadHistory()
      setTimeout(() => resultRef.current?.scrollIntoView({ behavior:'smooth', block:'start' }), 200)
    } catch (e) {
      showToast('Analiz hatası: '+e.message, 'error')
    }
    setAnalyzing(false)
  }

  function showToast(msg, type = 'success') {
    setToast({ message:msg, type, visible:true })
    setTimeout(() => setToast(t => ({...t, visible:false})), 3000)
  }

  const examples = [
    { text:'Sayın müşterimiz, hesabınız askıya alınmıştır. Hemen tıklayın: http://bit.ly/3xK...', label:'Phishing Email' },
    { text:'Tebrikler! 100.000 TL kazandınız. Hemen arayın: 0555 123 45 67', label:'SMS Dolandırıcılığı' },
    { text:'Merhaba, fatura ekteki gibidir. Acil ödeme yapınız. Saygılar, Mali İşler', label:'Fatura Dolandırıcılığı' },
  ]

  const sa = result?.security_assessment || {}
  const da = result?.detailed_analysis || {}
  const score = typeof sa.score === 'number' ? Math.round(sa.score) : 50
  const isPhishing = sa.is_phishing
  const isScam = sa.is_scam
  const threatLevel = sa.threat_level || 'medium'
  const recs = result?.recommendations || []
  const beliefs = da?.psychological_triggers || []
  const threats = da?.identified_threats || []
  const suspects = da?.suspicious_elements || []

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast} />
    <SectionHeader badge="AI Analiz Modülü" title="Yapay Zeka ile Güvenlik Analizi" subtitle="Mesaj, e-posta veya metinlerinizi AI ile analiz edin. Phishing, sosyal mühendislik ve kötü amaçlı içerikleri tespit edin." />

    {/* Input Section */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}>
      {/* LEFT */}
      <Card style={{ animation:'slideInLeft 0.5s ease' }}>
        <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📝</span> Analiz Edilecek Metin</h3>
        <div style={{ display:'flex', gap:8, marginBottom:16, flexWrap:'wrap' }}>
          {[{ id:'email', label:'📧 E-posta' },{ id:'sms', label:'💬 SMS' },{ id:'whatsapp', label:'📱 WhatsApp' },{ id:'social_media', label:'🌐 Sosyal Medya' }].map(c =>
            <button key={c.id} onClick={()=>setContext(c.id)} style={{ padding:'6px 14px', borderRadius:'20px', border:'1px solid', cursor:'pointer', fontSize:12, fontWeight:600, background:context===c.id?theme.primary:'transparent', borderColor:context===c.id?theme.primary:theme.border, color:context===c.id?'#000':theme.textMuted, transition:'all 0.2s' }}>{c.label}</button>
          )}
        </div>
        <textarea value={message} onChange={e=>setMessage(e.target.value)} placeholder="Analiz edilecek metni buraya yapıştırın veya yazın..." rows={8} style={{ width:'100%', padding:16, borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:theme.text, fontSize:14, resize:'vertical', outline:'none', lineHeight:1.6 }} />
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:12 }}>
          <span style={{ fontSize:12, color:theme.textMuted }}>{message.length} karakter</span>
          <GlowButton onClick={handleAnalyze} loading={analyzing} disabled={message.length<10}>{analyzing?'Analiz Ediliyor...':'🔍 Analiz Et'}</GlowButton>
        </div>
        <div style={{ marginTop:24 }}>
          <p style={{ fontSize:12, color:theme.textMuted, fontWeight:600, marginBottom:8, textTransform:'uppercase', letterSpacing:'1px' }}>Örnek Metinler</p>
          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            {examples.map((ex,i) => <button key={i} onClick={()=>setMessage(ex.text)} style={{ padding:'10px 14px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, cursor:'pointer', textAlign:'left', fontSize:12, color:theme.textMuted, lineHeight:1.4, transition:'all 0.2s' }}
              onMouseEnter={e=>{e.currentTarget.style.borderColor=theme.primary+'44';e.currentTarget.style.background=theme.surface2}}
              onMouseLeave={e=>{e.currentTarget.style.borderColor=theme.border;e.currentTarget.style.background=theme.surface}}>
              <span style={{ color:theme.primary, fontWeight:600, fontSize:11 }}>{ex.label}</span><br />{ex.text.substring(0,70)}...
            </button>)}
          </div>
        </div>
      </Card>

      {/* RIGHT - Results */}
      <Card ref={resultRef} style={{ animation:'slideInRight 0.5s ease' }}>
        <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📊</span> Analiz Sonuçları</h3>
        {!result && !analyzing && <div style={{ textAlign:'center', padding:'60px 20px', color:theme.textMuted }}>
          <span style={{ fontSize:48, display:'block', marginBottom:16 }}>🔍</span>
          <p style={{ fontSize:14 }}>Henüz analiz yapılmadı</p>
          <p style={{ fontSize:12, marginTop:8 }}>Sol taraftaki metni girin ve "Analiz Et" butonuna tıklayın</p>
        </div>}
        {analyzing && <div style={{ textAlign:'center', padding:'60px 20px' }}><Spinner size={40}/><p style={{ marginTop:16, color:theme.textMuted, fontSize:14 }}>AI analiz ediyor...</p></div>}
        {result && <ResultContent score={score} threatLevel={threatLevel} isPhishing={isPhishing} isScam={isScam} sa={sa} da={da} recs={recs} beliefs={beliefs} threats={threats} suspects={suspects} result={result} />}
      </Card>
    </div>

    {/* History */}
    <Card style={{ marginBottom:48 }}>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>📜</span> Son Analizler</h3>
      {history.length===0 ? <p style={{ color:theme.textMuted, fontSize:13, textAlign:'center', padding:20 }}>Henüz analiz yapılmadı</p> :
      <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
        {history.map(h => <div key={h.id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'12px 16px', background:theme.surface, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
          <div style={{ flex:1, overflow:'hidden' }}>
            <p style={{ fontSize:13, color:'#fff', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>{h.url||h.message||h.text}</p>
            <p style={{ fontSize:11, color:theme.textMuted, marginTop:2 }}>{h.created_at?new Date(h.created_at).toLocaleString('tr-TR'):''}</p>
          </div>
          <RiskBadge level={h.risk_level||h.threat_level||'safe'} />
        </div>)}
      </div>}
    </Card>
  </div>
}

/* ======================================
     RESULT CONTENT
  ====================================== */
function ResultContent({ score, threatLevel, isPhishing, isScam, sa, da, recs, beliefs, threats, suspects, result }) {
  return <div style={{ animation:'scaleIn 0.3s ease' }}>
    {/* Risk Gauge + Status */}
    <div style={{ display:'flex', gap:24, alignItems:'center', marginBottom:20, flexWrap:'wrap' }}>
      <RiskGauge score={score} label="Risk Skoru" />
      <div style={{ flex:1 }}>
        <div style={{ display:'flex', gap:12, flexWrap:'wrap', marginBottom:12 }}>
          <RiskBadge level={threatLevel} size="md" />
          <span style={{ padding:'6px 16px', borderRadius:'20px', fontSize:13, fontWeight:700, background:isPhishing?theme.accentDim:theme.primaryDim, color:isPhishing?theme.accent:theme.primary }}>
            {isPhishing?'⚠️ Phishing':'✅ Güvenli'}
          </span>
          {isScam && <span style={{ padding:'6px 16px', borderRadius:'20px', fontSize:13, fontWeight:700, background:theme.accentDim, color:theme.accent }}>🛑 Scam</span>}
        </div>
        <p style={{ fontSize:13, color:theme.textMuted }}>Güvenlik Durumu: <strong style={{ color:score>70?'#ef4444':score>40?'#f59e0b':'#22c55e' }}>{sa.safety_status||'Bilinmiyor'}</strong> • Aksiyon: {sa.action_required||'YOK'}</p>
      </div>
    </div>

    {/* Summary Card */}
    {result.summary && <Card style={{ padding:16, marginBottom:16, maxHeight:120, overflowY:'auto' }}>
      <p style={{ fontSize:13, lineHeight:1.6, color:theme.textDim, whiteSpace:'pre-wrap' }}>{result.summary}</p>
    </Card>}

    {/* Key Findings Grid */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12, marginBottom:20 }}>
      {/* Identified Threats */}
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}>
        <p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🚨 Tespit Edilen Tehditler</p>
        {threats.length > 0 ? threats.map((t,i) => <div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.accentDim, borderRadius:6, borderLeft:`3px solid ${theme.accent}`, fontSize:12, color:theme.text }}>{t}</div>)
        : <p style={{ fontSize:12, color:theme.textMuted }}>Tehdit tespit edilmedi</p>}
      </Card>
      {/* Psychological Triggers */}
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}>
        <p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🧠 Psikolojik Tetikleyiciler</p>
        {beliefs.length > 0 ? beliefs.map((b,i) => <div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.warning+'22', borderRadius:6, borderLeft:`3px solid ${theme.warning}`, fontSize:12, color:theme.text }}>⚠️ {b}</div>)
        : <p style={{ fontSize:12, color:theme.textMuted }}>Tetikleyici tespit edilmedi</p>}
      </Card>
      {/* Suspicious Elements */}
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}>
        <p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🔍 Şüpheli Öğeler</p>
        {suspects.length > 0 ? suspects.map((s,i) => <div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.primaryDim, borderRadius:6, borderLeft:`3px solid ${theme.primary}`, fontSize:12, color:theme.text }}>• {s}</div>)
        : <p style={{ fontSize:12, color:theme.textMuted }}>Şüpheli öğe yok</p>}
      </Card>
      {/* URL Analysis */}
      <Card style={{ padding:16, maxHeight:200, overflowY:'auto' }}>
        <p style={{ fontSize:12, fontWeight:700, color:'#fff', marginBottom:10 }}>🔗 URL Analizi</p>
        {da?.url_analysis?.length > 0 ? da.url_analysis.map((u,i) => <div key={i} style={{ padding:'6px 10px', marginBottom:6, background:theme.primaryDim, borderRadius:6, fontSize:12, color:theme.text }}>
          <p style={{ wordBreak:'break-all' }}>{u.url||u}</p>
          <span style={{ fontSize:11, color:theme.textMuted }}>Risk: {u.risk_score||'N/A'}</span>
        </div>) : <p style={{ fontSize:12, color:theme.textMuted }}>URL bulunamadı</p>}
      </Card>
    </div>

    {/* Recommendations */}
    {recs.length > 0 && <div style={{ marginBottom:16 }}>
      <p style={{ fontSize:14, fontWeight:700, color:'#fff', marginBottom:12 }}>💡 Öneriler</p>
      <div style={{ display:'flex', flexDirection:'column', gap:8, maxHeight:300, overflowY:'auto' }}>
        {recs.map((rec,i) => <div key={i} style={{ padding:'12px 14px', background:theme.primaryDim, borderRadius:theme.radiusSm, borderLeft:`3px solid ${theme.primary}`, fontSize:13, lineHeight:1.5 }}>
          {rec.description || rec.message || (typeof rec === 'string' ? rec : JSON.stringify(rec))}
        </div>)}
      </div>
    </div>}
  </div>
}

/* ======================================
     PHISHING DETECTOR
  ====================================== */
function PhishingDetector() {
  const [url, setUrl] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [latest, setLatest] = useState([])
  const [stats, setStats] = useState(null)
  const [pageNum, setPageNum] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  useEffect(() => { loadLatest(); loadStats() }, [])

  async function loadLatest(p = 1) {
    try {
      const r = await fetch(`${API}/phishing/latest?limit=20&page=${p}`)
      const d = await r.json()
      setLatest(d.data || [])
      setTotalPages(d.total_pages || 1)
      setPageNum(p)
    } catch {}
  }

  async function loadStats() {
    try { const r = await fetch(`${API}/phishing/stats`); const d = await r.json(); setStats(d) } catch {}
  }

  async function handleCheck() {
    if (!url) return
    setChecking(true); setResult(null)
    try {
      const r = await fetch(`${API}/phishing/check-url`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ url }),
      })
      if (!r.ok) throw new Error('URL kontrol hatası')
      const d = await r.json()
      setResult(d)
    } catch (e) {
      showToast('URL kontrol hatası: '+e.message, 'error')
    }
    setChecking(false)
  }

  function showToast(msg, type='success') { setToast({message:msg,type,visible:true}); setTimeout(()=>setToast(t=>({...t,visible:false})),3000) }

  const totalUrls = stats?.stats?.total_urls || stats?.total_urls || 0
  const phCount = stats?.stats?.phishing_count || stats?.phishing_count || 0
  const safeCount = stats?.stats?.safe_count || stats?.safe_count || 0

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast} />
    <SectionHeader badge="Phishing Dedektörü" title="URL Güvenlik Tarama Motoru" subtitle="1.2M+ phishing URL veritabanı ile anlık güvenlik kontrolü. Anında sonuç, detaylı rapor." />

    {/* Stats */}
    <div style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:16, marginBottom:32 }}>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Toplam URL</p>
        <p style={{ fontSize:32, fontWeight:800, color:theme.primary }}><CountUp end={totalUrls} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Phishing</p>
        <p style={{ fontSize:32, fontWeight:800, color:theme.danger }}><CountUp end={phCount} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Güvenli</p>
        <p style={{ fontSize:32, fontWeight:800, color:theme.success }}><CountUp end={safeCount} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Bugün Taranan</p>
        <p style={{ fontSize:32, fontWeight:800, color:theme.warning }}><CountUp end={stats?.stats?.today_scans||0} /></p>
      </Card>
    </div>

    {/* URL Check */}
    <Card style={{ marginBottom:32 }}>
      <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>🔍</span> URL Güvenlik Kontrolü</h3>
      <div style={{ display:'flex', gap:12, marginBottom:16 }}>
        <input value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://ornek.com/supheli-link" style={{ flex:1, padding:'14px 18px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:14, outline:'none' }} onKeyDown={e=>e.key==='Enter'&&handleCheck()} />
        <GlowButton onClick={handleCheck} loading={checking} disabled={!url}>{checking?'Taranıyor...':'🔍 Tara'}</GlowButton>
      </div>

      {/* Check Result */}
      {result && <div style={{ animation:'scaleIn 0.3s ease', padding:20, background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
        <div style={{ display:'flex', gap:24, alignItems:'flex-start', flexWrap:'wrap' }}>
          <RiskGauge score={typeof result.score==='number'?Math.round(Math.min(result.score,100)):(result.risk_level?.includes('TEHLİKELİ')?85:15)} label="Risk Skoru" />
          <div style={{ flex:1, minWidth:250 }}>
            <div style={{ display:'flex', gap:12, flexWrap:'wrap', marginBottom:12 }}>
              <RiskBadge level={result.risk_level?.includes('TEHLİKELİ')?'high':result.score>50?'high':'safe'} size="md" />
              <span style={{ padding:'4px 14px', borderRadius:'20px', fontSize:12, fontWeight:700, background:result.score>0?theme.accentDim:theme.primaryDim, color:result.score>0?theme.accent:theme.primary }}>
                {result.score>0?'⚠️ PHISHING':'✅ GÜVENLİ'}
              </span>
            </div>
            <p style={{ fontSize:12, color:theme.textMuted, wordBreak:'break-all', marginBottom:12, fontFamily:theme.mono }}>{url}</p>
            {/* Details */}
            {result.details && Array.isArray(result.details) && result.details.map((d,i) => <div key={i} style={{ padding:'6px 10px', marginBottom:4, background:theme.primaryDim, borderRadius:6, fontSize:12, color:theme.text }}>• {d}</div>)}
            {/* Sources */}
            {result.sources && Array.isArray(result.sources) && result.sources.map((s,i) => <div key={i} style={{ padding:'6px 10px', marginBottom:4, background:theme.surface, borderRadius:6, fontSize:12, display:'flex', gap:8, alignItems:'center' }}>
              <span style={{ color:theme.textMuted }}>Kaynak:</span>
              <span style={{ color:'#fff', fontWeight:600 }}>{s.name}</span>
              <span style={{ marginLeft:'auto', color:s.status?.includes('TEHDİT')?theme.danger:theme.success }}>{s.status}</span>
            </div>)}
          </div>
        </div>
      </div>}
    </Card>

    {/* Latest Phishing URLs Table */}
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}>
        <span>📋</span> Son Phishing Verileri
        <span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>
          Toplam {totalPages} sayfa
        </span>
      </h3>
      <div style={{ overflowX:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:13 }}>
          <thead>
            <tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:11, textTransform:'uppercase', letterSpacing:'1px' }}>
              <th style={{ textAlign:'left', padding:'12px 8px' }}>URL</th>
              <th style={{ textAlign:'left', padding:'12px 8px' }}>Domain</th>
              <th style={{ textAlign:'center', padding:'12px 8px' }}>Hedef</th>
              <th style={{ textAlign:'center', padding:'12px 8px' }}>Durum</th>
              <th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th>
            </tr>
          </thead>
          <tbody>
            {latest.length===0 && <tr><td colSpan={5} style={{ textAlign:'center', padding:32, color:theme.textMuted}}>Veri yükleniyor...</td></tr>}
            {latest.map((item,i) => <tr key={item.id||i} style={{ borderBottom:`1px solid ${theme.border}` }}
              onMouseEnter={e=>e.currentTarget.style.background=theme.surface}
              onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
              <td style={{ padding:'10px 8px', maxWidth:300, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}><span style={{ color:theme.text, fontSize:12, fontFamily:theme.mono }}>{item.url}</span></td>
              <td style={{ padding:'10px 8px' }}><span style={{ color:theme.primary, fontSize:12 }}>{item.domain_norm||item.domain||'-'}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'2px 8px', borderRadius:'10px', fontSize:11, background:theme.accentDim, color:theme.accent }}>{item.target||'-'}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:4, fontSize:12 }}><StatusDot active={item.online||false} />{item.online?'ONLINE':'OFFLINE'}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:11 }}>{item.submission_time?new Date(item.submission_time).toLocaleDateString('tr-TR'):item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):'-'}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
      {/* Pagination */}
      {totalPages > 1 && <div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:20 }}>
        <button onClick={()=>loadLatest(pageNum-1)} disabled={pageNum<=1} style={{ padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:pageNum<=1?theme.textMuted:'#fff', cursor:pageNum<=1?'not-allowed':'pointer', fontSize:13, fontWeight:600 }}>← Önceki</button>
        <span style={{ padding:'8px 16px', color:theme.textMuted, fontSize:13 }}>Sayfa {pageNum} / {totalPages}</span>
        <button onClick={()=>loadLatest(pageNum+1)} disabled={pageNum>=totalPages} style={{ padding:'8px 16px', borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, background:theme.surface, color:pageNum>=totalPages?theme.textMuted:'#fff', cursor:pageNum>=totalPages?'not-allowed':'pointer', fontSize:13, fontWeight:600 }}>Sonraki →</button>
      </div>}
    </Card>
  </div>
}

/* ======================================
     HONEYPOT / IOC PAGE
  ====================================== */
function HoneypotIOC() {
  const [iocStats, setIocStats] = useState(null)
  const [iocList, setIocList] = useState([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [searching, setSearching] = useState(false)
  const [activeTab, setActiveTab] = useState('dashboard')
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  useEffect(() => { loadIoCStats(); loadIoCList() }, [])

  async function loadIoCStats() {
    try {
      const r = await fetch(`${API}/honeypot/ioc/stats`)
      const d = await r.json()
      // Backend stats'i stats.stats veya doğrudan dönüyor
      setIocStats(d.stats || d)
    } catch {}
  }

  async function loadIoCList() {
    try {
      const r = await fetch(`${API}/honeypot/ioc/list-collected?limit=25`)
      const d = await r.json()
      setIocList(d.data || d.iocs || d.results || [])
    } catch {}
  }

  async function handleSearch() {
    if (!searchQuery) return
    setSearching(true)
    try {
      const r = await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`)
      const d = await r.json()
      setSearchResults(d.data || d.results || d.iocs || [])
      setActiveTab('search-results')
    } catch {}
    setSearching(false)
  }

  function showToast(msg, type='success') { setToast({message:msg,type,visible:true}); setTimeout(()=>setToast(t=>({...t,visible:false})),3000) }

  const riskDist = iocStats?.risk_distribution || []
  const weeklyGrowth = iocStats?.weekly_growth || []
  const topThreats = iocStats?.top_threats || []
  const sourceBreakdown = iocStats?.source_breakdown || []
  const totalIocs = iocStats?.total_iocs || iocStats?.total_records || 0
  const highRisk = iocStats?.high_risk_count || 0
  const mediumRisk = iocStats?.medium_risk_count || 0
  const lowRisk = iocStats?.low_risk_count || 0

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast} />
    <SectionHeader badge="IOC / Tuzak Modülü" title="Tehdit İstihbaratı & IOC Analizi" subtitle={`${totalIocs.toLocaleString('tr-TR')}+ tehdit indikatörü. Gerçek zamanlı IOC taraması, risk analizi ve kaynak dağılımı.`} />

    {/* Stats Cards */}
    <div style={{ display:'grid', gridTemplateColumns:'repeat(5, 1fr)', gap:16, marginBottom:32 }}>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}>
        <p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Toplam IOC</p>
        <p style={{ fontSize:24, fontWeight:800, color:theme.primary }}><CountUp end={totalIocs} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}>
        <p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Yüksek Risk</p>
        <p style={{ fontSize:24, fontWeight:800, color:theme.danger }}><CountUp end={highRisk} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}>
        <p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Orta Risk</p>
        <p style={{ fontSize:24, fontWeight:800, color:theme.warning }}><CountUp end={mediumRisk} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}>
        <p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Düşük Risk</p>
        <p style={{ fontSize:24, fontWeight:800, color:theme.success }}><CountUp end={lowRisk} /></p>
      </Card>
      <Card style={{ textAlign:'center', padding:'16px 8px' }}>
        <p style={{ fontSize:10, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:6 }}>Kaynak</p>
        <p style={{ fontSize:24, fontWeight:800, color:theme.warning }}>{sourceBreakdown.length}</p>
      </Card>
    </div>

    {/* Main Layout: Charts + Search */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:32 }}>
      {/* LEFT: Charts */}
      <div>
        {/* Risk Distribution */}
        <Card style={{ marginBottom:24 }}>
          <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>📊 Risk Dağılımı</h3>
          {riskDist.length > 0 ? <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
            {riskDist.map((item,i) => { const colors=['#22c55e','#84cc16','#f59e0b','#ff6b35','#ef4444']; return <div key={i}>
              <div style={{ display:'flex', justifyContent:'space-between', fontSize:12, marginBottom:4 }}>
                <span style={{ color:theme.textMuted }}>{item.range}</span>
                <span style={{ color:'#fff', fontWeight:600 }}>{item.count} ({item.percentage?.toFixed(1)}%)</span>
              </div>
              <div style={{ height:10, background:theme.surface, borderRadius:5, overflow:'hidden' }}>
                <div style={{ height:'100%', width:`${Math.min(item.percentage,100)}%`, background:colors[i]||theme.primary, borderRadius:5, transition:'width 1s ease' }} />
              </div>
            </div> })}
          </div> : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
        </Card>

        {/* Source Breakdown */}
        <Card>
          <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:12 }}>📡 Kaynak Dağılımı</h3>
          {sourceBreakdown.length > 0 ? sourceBreakdown.slice(0,8).map((s,i) => <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${theme.border}` }}>
            <span style={{ fontSize:13, color:theme.text }}>{s.source}</span>
            <span style={{ fontSize:13, fontWeight:700, color:theme.primary }}>{(s.count||0).toLocaleString('tr-TR')}</span>
          </div>) : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
        </Card>
      </div>

      {/* RIGHT: Weekly Growth + Search */}
      <div>
        {/* Weekly Growth */}
        <Card style={{ marginBottom:24 }}>
          <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16 }}>📈 Haftalık IOC Artışı</h3>
          {weeklyGrowth.length > 0 ? <div style={{ display:'flex', gap:8, alignItems:'flex-end', height:160 }}>
            {weeklyGrowth.map((item,i) => {
              const maxVal = Math.max(...weeklyGrowth.map(w=>w.count), 1)
              const h = (item.count / maxVal) * 100
              return <div key={i} style={{ flex:1, display:'flex', flexDirection:'column', alignItems:'center', gap:4 }}>
                <span style={{ fontSize:9, color:theme.textMuted }}>{item.count}</span>
                <div style={{ width:'100%', height:`${h}%`, minHeight:4, background:`linear-gradient(to top, ${theme.primary}, ${theme.primary}88)`, borderRadius:'4px 4px 0 0', transition:'height 1s ease' }} />
                <span style={{ fontSize:8, color:theme.textMuted, transform:'rotate(-45deg)', marginTop:4, whiteSpace:'nowrap' }}>{item.date?.slice(5) || ''}</span>
              </div>
            })}
          </div> : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
        </Card>

        {/* IOC Search */}
        <Card>
          <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🔎</span> IOC Sorgula</h3>
          <div style={{ display:'flex', gap:8 }}>
            <input value={searchQuery} onChange={e=>setSearchQuery(e.target.value)} placeholder="IP, domain, URL veya hash..." style={{ flex:1, padding:'12px 16px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:13, outline:'none' }} onKeyDown={e=>e.key==='Enter'&&handleSearch()} />
            <GlowButton onClick={handleSearch} loading={searching}>Ara</GlowButton>
          </div>
          {activeTab === 'search-results' && <div style={{ marginTop:16, maxHeight:300, overflowY:'auto' }}>
            <p style={{ fontSize:12, color:theme.textMuted, marginBottom:8 }}>{searchResults.length} sonuç bulundu</p>
            {searchResults.length > 0 ? searchResults.slice(0,15).map((item,i) => <div key={i} style={{ padding:'10px', marginBottom:6, background:theme.surface, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}`, fontSize:12 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11 }}>{item.value||item.ioc||item.indicator}</span>
                <span style={{ padding:'2px 8px', borderRadius:'10px', fontSize:10, background:theme.accentDim, color:theme.accent }}>{item.type||item.ioc_type||'unknown'}</span>
              </div>
              <p style={{ color:theme.textMuted, marginTop:4, fontSize:11 }}>Risk: {item.risk_score||'N/A'} • Kaynak: {item.source||'N/A'}</p>
            </div>) : <p style={{ color:theme.textMuted, fontSize:13, textAlign:'center' }}>Sonuç bulunamadı</p>}
          </div>}
        </Card>
      </div>
    </div>

    {/* Top Threats + IOC List Table */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 2fr', gap:24, marginBottom:48 }}>
      {/* Top Threats */}
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:12 }}>🔥 En Çok Görülen Tehditler</h3>
        {topThreats.length > 0 ? topThreats.slice(0,10).map((t,i) => <div key={i} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', padding:'8px 0', borderBottom:`1px solid ${theme.border}` }}>
          <span style={{ fontSize:12, color:'#fff' }}>{i+1}. {(t.type||t.threat_type||t.name||'').toUpperCase()}</span>
          <span style={{ fontSize:13, fontWeight:700, color:theme.danger }}>{(t.count||0).toLocaleString('tr-TR')}</span>
        </div>) : <p style={{ color:theme.textMuted, fontSize:13 }}>Veri yükleniyor...</p>}
      </Card>

      {/* IOC List */}
      <Card>
        <h3 style={{ fontSize:15, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}>
          <span>📋</span> Son Eklenen IOC'ler
          <span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>Son 25 kayıt</span>
        </h3>
        <div style={{ overflowX:'auto', maxHeight:400, overflowY:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}>
              <tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:10, textTransform:'uppercase', letterSpacing:'1px' }}>
                <th style={{ textAlign:'left', padding:'10px 6px' }}>Gösterge</th>
                <th style={{ textAlign:'center', padding:'10px 6px' }}>Tür</th>
                <th style={{ textAlign:'center', padding:'10px 6px' }}>Risk</th>
                <th style={{ textAlign:'center', padding:'10px 6px' }}>Kaynak</th>
                <th style={{ textAlign:'right', padding:'10px 6px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {iocList.length===0 && <tr><td colSpan={5} style={{ textAlign:'center', padding:24, color:theme.textMuted }}>Veri yükleniyor...</td></tr>}
              {iocList.map((item,i) => <tr key={item.id||i} style={{ borderBottom:`1px solid ${theme.border}` }}
                onMouseEnter={e=>e.currentTarget.style.background=theme.surface}
                onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                <td style={{ padding:'8px 6px' }}><span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11, wordBreak:'break-all' }}>{item.value||item.ioc||item.indicator||'-'}</span></td>
                <td style={{ padding:'8px 6px', textAlign:'center' }}><span style={{ padding:'2px 6px', borderRadius:'8px', fontSize:10, background:theme.primaryDim, color:theme.primary }}>{item.type||item.ioc_type||'-'}</span></td>
                <td style={{ padding:'8px 6px', textAlign:'center' }}><span style={{ padding:'2px 6px', borderRadius:'8px', fontSize:10, fontWeight:600, background:(item.risk_score||0)>75?theme.accentDim:(item.risk_score||0)>40?theme.warning+'22':theme.primaryDim, color:(item.risk_score||0)>75?theme.accent:(item.risk_score||0)>40?theme.warning:theme.primary }}>{item.risk_score||'-'}</span></td>
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

/* ======================================
     BREACH INTELLIGENCE PAGE
  ====================================== */
function BreachIntel() {
  const [email, setEmail] = useState('')
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState(null)
  const [stats, setStats] = useState(null)
  const [searchHistory, setSearchHistory] = useState([])
  const [toast, setToast] = useState({ message:'', type:'success', visible:false })

  useEffect(() => { loadStats() }, [])

  async function loadStats() {
    try { const r = await fetch(`${API}/breach/stats`); const d = await r.json(); setStats(d) } catch {}
  }

  async function handleCheck() {
    if (!email || !email.includes('@')) {
      showToast('Geçerli bir e-posta adresi girin', 'error'); return
    }
    setChecking(true); setResult(null)
    try {
      const r = await fetch(`${API}/breach/check-email`, {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ email }),
      })
      if (!r.ok) {
        const e = await r.json()
        throw new Error(e.message || e.detail || 'Sorgu hatası')
      }
      const d = await r.json()
      setResult(d)
    } catch (e) {
      showToast('Sorgu hatası: ' + e.message, 'error')
    }
    setChecking(false)
  }

  function showToast(msg, type='success') { setToast({message:msg,type,visible:true}); setTimeout(()=>setToast(t=>({...t,visible:false})),3000) }

  const riskDefs = stats?.risk_score_definitions || {}
  const socialImpact = stats?.social_impact || {}

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast} />
    <SectionHeader badge="Sızıntı İstihbaratı" title="Veri İhlali & Dark Web Taraması" subtitle="E-posta adresinizin sızdırılıp sızdırılmadığını kontrol edin. HIBP, dark web ve sızıntı veritabanlarında arama yapın." />

    {/* Stats Cards */}
    <div style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:16, marginBottom:32 }}>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>İzlenen E-posta</p>
        <p style={{ fontSize:28, fontWeight:800, color:theme.primary }}>{stats?.monitored_emails||0}</p>
      </Card>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Takip Edilen İhlal</p>
        <p style={{ fontSize:28, fontWeight:800, color:theme.danger }}>{stats?.total_tracked_breaches||0}</p>
      </Card>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Risk Türü</p>
        <p style={{ fontSize:28, fontWeight:800, color:theme.warning }}>{Object.keys(riskDefs).length}</p>
      </Card>
      <Card style={{ textAlign:'center', padding:'20px' }}>
        <p style={{ fontSize:11, color:theme.textMuted, textTransform:'uppercase', fontWeight:600, letterSpacing:'1px', marginBottom:8 }}>Sosyal Etki</p>
        <p style={{ fontSize:28, fontWeight:800, color:theme.accent }}>{socialImpact.risk_level||'N/A'}</p>
      </Card>
    </div>

    {/* Main: Info + Check */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}>
      {/* LEFT: Info */}
      <div>
        <Card style={{ marginBottom:24 }}>
          <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🔓</span> Sızıntı Kontrolü Nedir?</h3>
          <p style={{ fontSize:13, color:theme.textDim, lineHeight:1.7 }}>
            Veri ihlalleri, hackerların şirket veritabanlarını ele geçirmesiyle milyonlarca kullanıcının 
            e-posta, şifre ve kişisel bilgilerinin internete sızmasına neden olur. Bu modül, 
            <strong style={{ color:'#fff' }}> Have I Been Pwned</strong>, 
            <strong style={{ color:'#fff' }}> dark web forumları</strong> ve 
            <strong style={{ color:'#fff' }}> sızıntı veritabanlarında</strong> tarama yapar.
          </p>
        </Card>
        <Card>
          <h3 style={{ fontSize:14, fontWeight:700, color:'#fff', marginBottom:12 }}>📡 Risk Skorları</h3>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            {Object.entries(riskDefs).length > 0 ? Object.entries(riskDefs).slice(0,10).map(([k,v]) => <div key={k} style={{ display:'flex', justifyContent:'space-between', padding:'6px 0', borderBottom:`1px solid ${theme.border}`, fontSize:12 }}>
              <span style={{ color:theme.text }}>{k}</span>
              <span style={{ fontWeight:700, color:v>70?theme.danger:v>40?theme.warning:theme.textMuted }}>{v} puan</span>
            </div>) : <p style={{ color:theme.textMuted, fontSize:13 }}>Risk tanımları yükleniyor...</p>}
          </div>
        </Card>
      </div>

      {/* RIGHT: Check Form */}
      <Card>
        <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}><span>🔍</span> E-posta Sızıntı Kontrolü</h3>
        <p style={{ fontSize:13, color:theme.textDim, marginBottom:16 }}>
          E-posta adresinizi girin, veri ihlallerinde sızdırılıp sızdırılmadığını kontrol edelim.
        </p>
        <div style={{ display:'flex', gap:8, marginBottom:16 }}>
          <input value={email} onChange={e=>setEmail(e.target.value)} placeholder="ornek@email.com" style={{ flex:1, padding:'14px 18px', borderRadius:theme.radiusSm, background:theme.bg, border:`1px solid ${theme.border}`, color:'#fff', fontSize:14, outline:'none' }} onKeyDown={e=>e.key==='Enter'&&handleCheck()} />
          <GlowButton onClick={handleCheck} loading={checking} disabled={!email||!email.includes('@')}>{checking?'Taranıyor...':'🔍 Sorgula'}</GlowButton>
        </div>
        <p style={{ fontSize:11, color:theme.textMuted }}>
          Not: HIBP API anahtarı gerektirir. Şu an demo modda çalışmaktadır.
        </p>

        {/* Result */}
        {result && <div style={{ animation:'scaleIn 0.3s ease', marginTop:24, padding:20, background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${theme.border}` }}>
          {result.status === 'error' ? <div style={{ textAlign:'center', padding:20 }}>
            <span style={{ fontSize:48, display:'block', marginBottom:12 }}>⚠️</span>
            <p style={{ color:theme.warning, fontSize:16, fontWeight:600 }}>{result.message}</p>
            <p style={{ color:theme.textMuted, fontSize:12, marginTop:8 }}>{result.hint}</p>
          </div> : result.compromised ? <><div style={{ textAlign:'center', marginBottom:16 }}>
            <span style={{ fontSize:48 }}>⚠️</span>
            <p style={{ color:theme.danger, fontSize:18, fontWeight:700, marginTop:8 }}>Sızıntı Tespit Edildi!</p>
          </div>
          {(result.breaches||[]).map((b,i) => <div key={i} style={{ padding:'10px 14px', marginBottom:8, background:theme.accentDim, borderRadius:theme.radiusSm, borderLeft:`3px solid ${theme.accent}` }}>
            <p style={{ fontSize:13, fontWeight:600, color:'#fff' }}>{b.name||b.source||'Bilinmeyen'}</p>
            <p style={{ fontSize:11, color:theme.textMuted }}>{b.date?new Date(b.date).toLocaleDateString('tr-TR'):''} — {(b.data_classes||b.data||[]).join(', ')}</p>
          </div>)}</> : <div style={{ textAlign:'center', padding:20 }}>
            <span style={{ fontSize:48 }}>✅</span>
            <p style={{ color:theme.success, fontSize:18, fontWeight:700, marginTop:8 }}>Sızıntı Bulunamadı</p>
            <p style={{ color:theme.textMuted, fontSize:13, marginTop:4 }}>{email} adresi bilinen sızıntılarda yok</p>
          </div>}
        </div>}
      </Card>
    </div>

    {/* Password Security & Intervention */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:24, marginBottom:48 }}>
      <Card>
        <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🛡️</span> Şifre Güvenlik Önerileri</h3>
        <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
          {[
            { icon:'🔑', title:'Eşsiz Şifre Kullanın', desc:'Her platform için farklı şifre oluşturun' },
            { icon:'📏', title:'Uzunluk Önemli', desc:'En az 12 karakter, büyük/küçük harf + rakam + sembol' },
            { icon:'🔄', title:'Düzenli Değiştirin', desc:'90 günde bir şifrelerinizi yenileyin' },
            { icon:'🔐', title:'2FA Açın', desc:'İki faktörlü kimlik doğrulama kullanın' },
            { icon:'🕵️', title:'Parola Yöneticisi', desc:'Bitwarden, 1Password gibi araçlar kullanın' },
          ].map((item,i) => <div key={i} style={{ display:'flex', gap:12, alignItems:'flex-start', padding:'10px 14px', background:theme.surface, borderRadius:theme.radiusSm }}>
            <span style={{ fontSize:24 }}>{item.icon}</span>
            <div><p style={{ fontSize:13, fontWeight:600, color:'#fff' }}>{item.title}</p><p style={{ fontSize:12, color:theme.textMuted }}>{item.desc}</p></div>
          </div>)}
        </div>
      </Card>
      <Card>
        <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:12, display:'flex', gap:8, alignItems:'center' }}><span>🚨</span> Sızıntı Sonrası Müdahale</h3>
        <div style={{ display:'flex', flexDirection:'column', gap:10 }}>
          {[{step:'01',title:'Panik Yapmayın',desc:'Sakin olun ve adım adım ilerleyin'},{step:'02',title:'Şifrenizi Hemen Değiştirin',desc:'Sızdırılan platformdaki şifrenizi yenileyin'},{step:'03',title:'Tüm Platformları Güncelleyin',desc:'Aynı şifreyi kullandığınız yerleri değiştirin'},{step:'04',title:'2FA Aktifleştirin',desc:'Tüm kritik hesaplarda 2FA açın'},{step:'05',title:'Hesap Aktivitesini Kontrol Edin',desc:'Şüpheli girişleri inceleyin'},{step:'06',title:'İzlemeye Devam Edin',desc:'Bu modül ile düzenli kontrol yapın'}].map((item,i) => <div key={i} style={{ display:'flex', gap:12, alignItems:'flex-start' }}>
            <span style={{ width:28, height:28, borderRadius:'50%', background:theme.primaryDim, color:theme.primary, display:'flex', alignItems:'center', justifyContent:'center', fontSize:12, fontWeight:700, flexShrink:0 }}>{item.step}</span>
            <div><p style={{ fontSize:13, fontWeight:600, color:'#fff' }}>{item.title}</p><p style={{ fontSize:12, color:theme.textMuted }}>{item.desc}</p></div>
          </div>)}
        </div>
      </Card>
    </div>

    {/* Known Breaches Table */}
    <Card>
      <h3 style={{ fontSize:16, fontWeight:700, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}>
        <span>📋</span> Bilinen Büyük Veri İhlalleri
      </h3>
      <div style={{ overflowX:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:13 }}>
          <thead>
            <tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:11, textTransform:'uppercase', letterSpacing:'1px' }}>
              <th style={{ textAlign:'left', padding:'12px 8px' }}>İhlal</th><th style={{ textAlign:'left', padding:'12px 8px' }}>Şirket</th><th style={{ textAlign:'center', padding:'12px 8px' }}>Sızan Veri</th><th style={{ textAlign:'center', padding:'12px 8px' }}>Boyut</th><th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th>
            </tr>
          </thead>
          <tbody>
            {[
              {name:'Collection #1',company:'Multiple',data:'Email, Password',size:'773M',date:'2019-01'},
              {name:'LinkedIn',company:'LinkedIn',data:'Email, Password',size:'500M',date:'2021-06'},
              {name:'Facebook',company:'Meta',data:'Phone, Email, Name',size:'533M',date:'2021-04'},
              {name:'Twitter',company:'X Corp',data:'Email, Username',size:'235M',date:'2022-12'},
              {name:'Adobe',company:'Adobe',data:'Email, Password, CC',size:'153M',date:'2013-10'},
              {name:'Dropbox',company:'Dropbox',data:'Email, Password',size:'69M',date:'2012-07'},
              {name:'Yahoo',company:'Yahoo',data:'Email, Password, Name',size:'3B',date:'2013-08'},
              {name:'Marriott',company:'Marriott',data:'Passport, Name, Email',size:'500M',date:'2018-11'},
            ].map((b,i) => <tr key={i} style={{ borderBottom:`1px solid ${theme.border}` }}
              onMouseEnter={e=>e.currentTarget.style.background=theme.surface}
              onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
              <td style={{ padding:'10px 8px' }}><span style={{ color:'#fff', fontWeight:600 }}>{b.name}</span></td>
              <td style={{ padding:'10px 8px', color:theme.textMuted }}>{b.company}</td>
              <td style={{ padding:'10px 8px', textAlign:'center', fontSize:12 }}>{b.data}</td>
              <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'2px 8px', borderRadius:'10px', fontSize:11, background:theme.primaryDim, color:theme.primary }}>{b.size}</span></td>
              <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:11 }}>{b.date}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </Card>
  </div>
}
