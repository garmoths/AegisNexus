import { useState, useEffect } from 'react'
import SecurityModulesScrollSection from './sections/SecurityModulesScrollSection'
import PlatformStatsHorizontalSection from './sections/PlatformStatsHorizontalSection'
import { theme } from './theme'

const API = '/api/v2'

function Card({ children, style, ...props }) {
  const [h, sH] = useState(false)
  return <div onMouseEnter={()=>sH(true)} onMouseLeave={()=>sH(false)} style={{ background:`linear-gradient(135deg, ${theme.surface}, ${theme.surface2})`, border:`1px solid ${h?theme.primary+'66':theme.border}`, borderRadius:'12px', padding:24, transition:'all 0.3s cubic-bezier(0.175,0.885,0.32,1.275)', boxShadow:h?'0 0 40px rgba(0,212,255,0.08)':'none', transform:h?'translateY(-2px)':'none', ...style }} {...props}>{children}</div>
}

function GlowButton({ children, onClick, variant='primary', style }) {
  return <button onClick={onClick} style={{ padding:'14px 32px', borderRadius:'8px', border:'none', cursor:'pointer', fontSize:14, fontWeight:700, letterSpacing:'0.5px', background:variant==='primary'?'linear-gradient(135deg, #00d4ff, #0099cc)':'transparent', color:variant==='primary'?'#000':'#00d4ff', border:variant==='primary'?'none':'1px solid #00d4ff44', transition:'all 0.3s ease', boxShadow:variant==='primary'?'0 4px 20px rgba(0,212,255,0.3)':'none', textDecoration:'none', display:'inline-flex', alignItems:'center', gap:8, ...style }}
    onMouseEnter={e=>{if(!e.currentTarget.disabled){e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow='0 8px 30px rgba(0,212,255,0.4)'}}}
    onMouseLeave={e=>{e.currentTarget.style.transform='none';e.currentTarget.style.boxShadow=variant==='primary'?'0 4px 20px rgba(0,212,255,0.3)':'none'}}>{children}</button>
}

export default function LandingPage() {
  const [scrolled, setScrolled] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY>20)
    window.addEventListener('scroll', onScroll, {passive:true})
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const scrollTo = (id) => document.getElementById(id)?.scrollIntoView({behavior:'smooth'})

  return <div style={{ minHeight:'100vh', background:theme.bg, color:theme.text }}>
    <style>{`
      @keyframes fadeInUp { from { opacity:0; transform:translateY(20px) } to { opacity:1; transform:translateY(0) } }
      @keyframes float { 0%,100% { transform:translateY(0px) } 50% { transform:translateY(-8px) } }
      * { scrollbar-width:thin; scrollbar-color:#1e2a4a transparent; }
    `}</style>

    {/* NAVBAR */}
    <nav style={{ position:'fixed', top:0, left:0, right:0, zIndex:1000, background:scrolled?'rgba(8,12,20,0.95)':'rgba(8,12,20,0.8)', backdropFilter:'blur(20px)', borderBottom:`1px solid ${scrolled?theme.border:'transparent'}`, transition:'all 0.3s ease', padding:'0 24px' }}>
      <div style={{ maxWidth:1200, margin:'0 auto', display:'flex', alignItems:'center', justifyContent:'space-between', height:70 }}>
        <div style={{ display:'flex', alignItems:'center', gap:12 }}>
          <svg width="32" height="32" viewBox="0 0 36 36" fill="none">
            <path d="M18 4L6 11V18C6 23.5 10 28.5 18 30C26 28.5 30 23.5 30 18V11L18 4Z" stroke="#00d4ff" strokeWidth="2" fill="none"/>
            <path d="M14 18L17 21L23 15" stroke="#00d4ff" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <span style={{ fontSize:20, fontWeight:700, color:'#fff', letterSpacing:'-0.5px' }}>Aegis<span style={{ color:'#00d4ff' }}>Nexus</span></span>
        </div>
        <div style={{ display:'flex', gap:20, alignItems:'center' }}>
          {['Moduller','Ozellikler','Iletisim'].map(item =>
            <button key={item} onClick={()=>scrollTo(item==='Moduller'?'modules':item==='Ozellikler'?'features':'contact')}
              style={{ background:'none', border:'none', color:theme.textMuted, cursor:'pointer', fontSize:14, fontWeight:500, transition:'color 0.2s' }}
              onMouseEnter={e=>e.currentTarget.style.color='#00d4ff'}
              onMouseLeave={e=>e.currentTarget.style.color='#64748b'}>{item}</button>
          )}
          <a href="https://modules.aegisnexus.dev" style={{ padding:'10px 24px', borderRadius:'8px', border:'none', cursor:'pointer', fontSize:13, fontWeight:700, background:'linear-gradient(135deg, #00d4ff, #0099cc)', color:'#000', textDecoration:'none', boxShadow:'0 4px 20px rgba(0,212,255,0.3)', transition:'all 0.3s' }}
            onMouseEnter={e=>{e.currentTarget.style.transform='translateY(-2px)';e.currentTarget.style.boxShadow='0 8px 30px rgba(0,212,255,0.4)'}}
            onMouseLeave={e=>{e.currentTarget.style.transform='none';e.currentTarget.style.boxShadow='0 4px 20px rgba(0,212,255,0.3)'}}>Panele Git →</a>
        </div>
      </div>
    </nav>

    {/* HERO */}
    <div style={{ textAlign:'center', padding:'140px 24px 80px', position:'relative', overflow:'hidden', minHeight:'85vh', display:'flex', alignItems:'center', justifyContent:'center' }}>
      <div style={{ position:'absolute', top:'50%', left:'50%', transform:'translate(-50%,-50%)', width:800, height:800, background:'radial-gradient(circle, rgba(0,212,255,0.08) 0%, transparent 70%)', pointerEvents:'none' }} />
      <div style={{ position:'relative', zIndex:1, maxWidth:900 }}>
        <span style={{ display:'inline-block', padding:'8px 20px', background:'rgba(0,212,255,0.1)', border:'1px solid #00d4ff33', borderRadius:'20px', fontSize:12, fontWeight:700, color:'#00d4ff', textTransform:'uppercase', letterSpacing:'2px', marginBottom:24 }}>🛡️ 5 Katmanli Guvenlik Kalkani</span>
        <h1 style={{ fontSize:'clamp(42px, 7vw, 72px)', fontWeight:900, color:'#fff', lineHeight:1.05, marginBottom:24, letterSpacing:'-2px' }}>
          Siber Tehditlere Karsi<br />
          <span style={{ background:'linear-gradient(135deg, #00d4ff, #0099cc)', WebkitBackgroundClip:'text', WebkitTextFillColor:'transparent' }}>Proaktif Koruma</span>
        </h1>
        <p style={{ color:theme.textMuted, fontSize:'clamp(16px, 2vw, 20px)', maxWidth:680, margin:'0 auto', lineHeight:1.7, marginBottom:40 }}>
          Bireyler ve KOBİ'ler icin yapay zeka destekli, gercek zamanli siber guvenlik platformu.
          Phishing, veri sizintilari ve sosyal muhendislik saldirilarina karsi 5 katmanli koruma.
        </p>
        <div style={{ display:'flex', gap:16, justifyContent:'center', flexWrap:'wrap' }}>
          <a href="https://modules.aegisnexus.dev" style={{ textDecoration:'none' }}><GlowButton>🚀 Paneli Ac</GlowButton></a>
          <GlowButton variant="outline" onClick={()=>scrollTo('modules')}>📦 Modulleri Kesfet</GlowButton>
        </div>
      </div>
    </div>

    <SecurityModulesScrollSection />

    <PlatformStatsHorizontalSection />

    {/* WHY */}
    <div style={{ padding:'60px 24px', maxWidth:1200, margin:'0 auto' }}>
      <h2 style={{ fontSize:36, fontWeight:800, color:'#fff', textAlign:'center', marginBottom:48, letterSpacing:'-1px' }}>
        Neden <span style={{ color:'#00d4ff' }}>AegisNexus</span>?
      </h2>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(300px, 1fr))', gap:24 }}>
        {[
          { icon:'🧠', title:'Yapay Zeka Destekli', desc:'DeepSeek ve Groq AI modelleri ile gercek zamanli tehdit analizi. Saniyeler icinde phishing ve sosyal muhendislik tespiti.' },
          { icon:'🌐', title:'Gercek Zamanli IStihbarat', desc:'1.2M+ phishing URL, 9K+ IOC, AbuseIPDB, URLhaus, AlienVault OTX gibi 10+ kaynaktan beslenen tehdit istihbarati.' },
          { icon:'🛡️', title:'5 Katmanli Koruma', desc:'AI Analiz → Phishing Tarama → IOC Tespit → Sizinti Kontrolu → Kriptografik Koruma. Her acidan guvende olun.' },
          { icon:'🇹🇷', title:'Turkce & KVKK Uyumlu', desc:'Tamamen Turkce arayuz. KVKK ve GDPR uyumlu veri isleme. Turkiyedeki siber tehditlere ozel analiz.' },
          { icon:'🔒', title:'Gizlilik Odakli', desc:'Hicbir veriniz ucuncu taraflarla paylasilmaz. Sifreleriniz sadece sizin bilgisayarinizda olusturulur.' },
          { icon:'📊', title:'Detayli Raporlama', desc:'Her analiz icin kapsamli raporlar. PDF export, e-posta bildirimleri ve dashboard ile takip.' },
        ].map((item,i) => <Card key={i} style={{ textAlign:'center', padding:'32px 24px' }}>
          <span style={{ fontSize:48, display:'block', marginBottom:16, animation:'float 3s ease-in-out infinite', animationDelay:`${i*0.3}s` }}>{item.icon}</span>
          <h3 style={{ fontSize:18, fontWeight:700, color:'#fff', marginBottom:12 }}>{item.title}</h3>
          <p style={{ fontSize:14, color:theme.textMuted, lineHeight:1.7 }}>{item.desc}</p>
        </Card>)}
      </div>
    </div>

    {/* CONTACT */}
    <div id="contact" style={{ padding:'60px 24px 80px', maxWidth:600, margin:'0 auto', textAlign:'center' }}>
      <h2 style={{ fontSize:36, fontWeight:800, color:'#fff', marginBottom:16, letterSpacing:'-1px' }}>Iletisim</h2>
      <p style={{ color:theme.textMuted, fontSize:16, marginBottom:32 }}>Sorulariniz mi var? Bize ulasin, en kisa surede donus yapalim.</p>
      <form onSubmit={e=>{e.preventDefault();alert('Tesekkurler! En kisa surede donus yapacagiz.')}} style={{ display:'flex', flexDirection:'column', gap:16, alignItems:'center' }}>
        <div style={{ display:'flex', gap:12, width:'100%', maxWidth:500 }}>
          <input type="email" placeholder="E-posta adresiniz" required style={{ flex:1, padding:'14px 18px', borderRadius:'8px', background:'#080c14', border:'1px solid #1e2a4a', color:'#fff', fontSize:14, outline:'none' }} />
          <button type="submit" style={{ padding:'14px 28px', borderRadius:'8px', border:'none', cursor:'pointer', fontSize:14, fontWeight:700, background:'linear-gradient(135deg, #00d4ff, #0099cc)', color:'#000', boxShadow:'0 4px 20px rgba(0,212,255,0.3)' }}>Gonder</button>
        </div>
        <div style={{ display:'flex', gap:24, marginTop:16, color:theme.textMuted, fontSize:13 }}>
          <span>📧 info@aegisnexus.dev</span>
          <span>🌐 github.com/garmoths/AegisNexus</span>
        </div>
      </form>
    </div>

    {/* FOOTER */}
    <footer style={{ borderTop:`1px solid ${theme.border}`, padding:'24px', textAlign:'center', color:theme.textMuted, fontSize:13 }}>
      <p>AegisNexus — Enterprise Cybersecurity Platform &copy; 2026</p>
      <div style={{ display:'flex', gap:24, justifyContent:'center', marginTop:12 }}>
        <a href={API+'/docs'} style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">API Docs</a>
        <a href="https://github.com/garmoths/AegisNexus" style={{ color:theme.textMuted, textDecoration:'none' }} target="_blank">GitHub</a>
        <a href="https://modules.aegisnexus.dev" style={{ color:'#00d4ff', textDecoration:'none' }} target="_blank">Module Paneli →</a>
      </div>
    </footer>
  </div>
}
