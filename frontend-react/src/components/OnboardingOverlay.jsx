import { useState, useEffect, useCallback } from 'react'

const STORAGE_KEY = 'aegis_onboarding_v3'

/* ── CSS ─────────────────────────────────────── */
const STYLE_ID = 'aegis-ob-css'
const CSS = `
/* ── Base animations ── */
@keyframes ob-backdrop-in  { from{opacity:0} to{opacity:1} }
@keyframes ob-backdrop-out { from{opacity:1} to{opacity:0} }
@keyframes ob-card-in      { from{opacity:0;transform:translateY(22px) scale(0.96)} to{opacity:1;transform:translateY(0) scale(1)} }
@keyframes ob-slide-in     { from{opacity:0;transform:translateX(32px)} to{opacity:1;transform:translateX(0)} }
@keyframes ob-slide-out    { from{opacity:1;transform:translateX(0)} to{opacity:0;transform:translateX(-32px)} }

/* ── Terminal animation (step 1) ── */
@keyframes ob-line-in { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:translateY(0)} }
@keyframes ob-cursor  { 0%,100%{opacity:1} 50%{opacity:0} }
@keyframes ob-counter { from{opacity:0.4} to{opacity:1} }

/* ── Map pulse (step 2) ── */
@keyframes ob-pulse {
  0%  { transform:scale(1);   opacity:0.9 }
  50% { transform:scale(1.7); opacity:0.3 }
  100%{ transform:scale(1);   opacity:0.9 }
}
@keyframes ob-dot-appear { from{opacity:0;transform:scale(0)} to{opacity:1;transform:scale(1)} }
@keyframes ob-ripple {
  0%  { transform:scale(1); opacity:0.6 }
  100%{ transform:scale(3); opacity:0 }
}

/* ── Email scanner (step 3) ── */
@keyframes ob-scan-beam {
  0%   { top:0%;    opacity:0 }
  5%   { opacity:1 }
  95%  { opacity:1 }
  100% { top:100%;  opacity:0 }
}
@keyframes ob-badge-in { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }

/* ── Layout ── */
.ob-backdrop {
  position:fixed; inset:0; z-index:9999;
  display:flex; align-items:center; justify-content:center;
  padding:16px;
  background:rgba(5,8,15,0.92);
  backdrop-filter:blur(4px);
  font-family:'Inter',sans-serif;
  animation: ob-backdrop-in 300ms ease forwards;
}
.ob-backdrop.ob-closing { animation: ob-backdrop-out 260ms ease forwards; }

.ob-card {
  position:relative; width:100%; max-width:780px;
  background:#0b1120;
  border:1px solid #1e2a4a;
  border-radius:22px;
  overflow:hidden;
  box-shadow:0 48px 120px rgba(0,0,0,0.75), 0 0 0 1px rgba(0,212,255,0.06), inset 0 1px 0 rgba(255,255,255,0.04);
  animation: ob-card-in 420ms cubic-bezier(0.16,1,0.3,1) forwards;
}

.ob-inner {
  display:grid; grid-template-columns:1fr 1fr;
  min-height:460px;
}
@media(max-width:620px){
  .ob-inner { grid-template-columns:1fr; }
  .ob-anim-panel { display:none; }
  .ob-card { max-width:100%; }
}

/* ── Left panel ── */
.ob-left {
  padding:44px 40px 36px;
  display:flex; flex-direction:column;
  border-right:1px solid #1e2a4a;
  position:relative;
}

.ob-close {
  position:absolute; top:14px; right:14px;
  background:rgba(15,22,41,0.85); border:1px solid #1e2a4a;
  color:#475569; font-size:20px; line-height:1;
  cursor:pointer; padding:5px 9px; border-radius:8px;
  transition:color 150ms, background 150ms, border-color 150ms;
  z-index:10;
}
.ob-close:hover { color:#e2e8f0; background:rgba(255,255,255,0.08); border-color:#2d3e5e; }

.ob-dots {
  display:flex; align-items:center; gap:8px; margin-bottom:32px;
}
.ob-dot {
  height:6px; border-radius:99px;
  transition:width 350ms cubic-bezier(0.16,1,0.3,1), background 300ms;
}
.ob-dot.ob-active   { width:22px; background:#00d4ff; }
.ob-dot.ob-inactive { width:6px;  background:#1e2a4a; }

.ob-step-content {
  flex:1; display:flex; flex-direction:column; justify-content:center;
  animation: ob-slide-in 380ms cubic-bezier(0.16,1,0.3,1) forwards;
}
.ob-step-content.ob-leaving { animation: ob-slide-out 260ms ease forwards; }

.ob-tag-label {
  font-size:10px; font-weight:800; color:#00d4ff;
  text-transform:uppercase; letter-spacing:3px;
  margin-bottom:14px;
}
.ob-title {
  font-size:24px; font-weight:800; color:#e2e8f0;
  margin:0 0 14px; letter-spacing:-0.6px; line-height:1.25;
}
.ob-desc {
  font-size:14px; color:#64748b; line-height:1.7; margin:0 0 24px;
}

.ob-stats {
  display:grid; grid-template-columns:repeat(3,1fr); gap:10px; margin-top:auto;
}
.ob-stat {
  background:rgba(0,212,255,0.05); border:1px solid rgba(0,212,255,0.1);
  border-radius:10px; padding:12px 8px; text-align:center;
}
.ob-stat-val  { font-size:19px; font-weight:800; color:#00d4ff; display:block; line-height:1; margin-bottom:3px; }
.ob-stat-lbl  { font-size:10px; color:#475569; text-transform:uppercase; letter-spacing:0.6px; }

.ob-module-tags { display:flex; flex-wrap:wrap; gap:7px; margin-top:auto; }
.ob-mtag {
  padding:5px 11px; border-radius:20px;
  background:rgba(255,255,255,0.04); border:1px solid #1e2a4a;
  font-size:11px; color:#94a3b8; letter-spacing:0.2px;
  transition:border-color 180ms, color 180ms;
}
.ob-mtag:hover { border-color:rgba(0,212,255,0.3); color:#00d4ff; }

.ob-footer {
  display:flex; align-items:center; justify-content:space-between;
  padding:20px 40px 28px;
  border-top:1px solid #1e2a4a;
}
.ob-step-counter { font-size:12px; color:#334155; font-weight:600; }

.ob-btn {
  display:inline-flex; align-items:center; gap:7px;
  padding:10px 20px; border-radius:22px; border:none;
  background:rgba(0,212,255,0.12); color:#00d4ff;
  font-size:13px; font-weight:700; font-family:'Inter',sans-serif;
  cursor:pointer; letter-spacing:0.3px;
  transition:background 150ms, transform 120ms;
}
.ob-btn:hover  { background:rgba(0,212,255,0.22); }
.ob-btn:active { transform:scale(0.96); }

.ob-btn-circle {
  width:36px; height:36px; border-radius:50%;
  background:rgba(0,212,255,0.12); color:#00d4ff;
  border:none; cursor:pointer; font-size:18px;
  display:flex; align-items:center; justify-content:center;
  transition:background 150ms, transform 120ms;
}
.ob-btn-circle:hover  { background:rgba(0,212,255,0.22); }
.ob-btn-circle:active { transform:scale(0.94); }

/* ── Right animation panel ── */
.ob-anim-panel {
  background:#060b15;
  position:relative; overflow:hidden;
  display:flex; align-items:center; justify-content:center;
}
.ob-anim-inner { width:100%; height:100%; position:relative; }

/* ── Terminal (step 1) ── */
.ob-terminal {
  margin:24px; background:#040810;
  border:1px solid #1e2a4a; border-radius:12px;
  overflow:hidden; height:calc(100% - 48px);
  display:flex; flex-direction:column;
}
.ob-term-header {
  padding:10px 16px; border-bottom:1px solid #1e2a4a;
  display:flex; align-items:center; justify-content:space-between;
}
.ob-term-dot-row { display:flex; gap:6px; }
.ob-term-dot-r { width:10px;height:10px;border-radius:50%;background:#ef4444;opacity:0.7; }
.ob-term-dot-y { width:10px;height:10px;border-radius:50%;background:#f59e0b;opacity:0.7; }
.ob-term-dot-g { width:10px;height:10px;border-radius:50%;background:#22c55e;opacity:0.7; }
.ob-term-title { font-size:10px; font-weight:700; color:#334155; text-transform:uppercase; letter-spacing:2px; }
.ob-term-badge { font-size:9px; font-weight:700; color:#22c55e; background:rgba(34,197,94,0.1); border:1px solid rgba(34,197,94,0.25); border-radius:4px; padding:2px 7px; display:flex; align-items:center; gap:4px; }
.ob-term-badge::before { content:''; width:5px; height:5px; border-radius:50%; background:#22c55e; animation:ob-pulse 1.5s ease infinite; }
.ob-term-body { flex:1; padding:14px 16px; overflow:hidden; font-family:'JetBrains Mono','Fira Code',monospace; font-size:11px; line-height:1.9; }
.ob-term-counter { font-size:10px; color:#334155; margin-bottom:10px; animation:ob-counter 2s ease infinite alternate; }
.ob-tl { opacity:0; }
.ob-tl.ob-t1  { animation:ob-line-in 0.35s ease 0.4s  forwards; }
.ob-tl.ob-t2  { animation:ob-line-in 0.35s ease 1.2s  forwards; }
.ob-tl.ob-t3  { animation:ob-line-in 0.35s ease 1.9s  forwards; }
.ob-tl.ob-t4  { animation:ob-line-in 0.35s ease 2.8s  forwards; }
.ob-tl.ob-t5  { animation:ob-line-in 0.35s ease 3.6s  forwards; }
.ob-tl.ob-t6  { animation:ob-line-in 0.35s ease 4.4s  forwards; }
.ob-scan-c  { color:#64748b; }
.ob-scan-url{ color:#94a3b8; }
.ob-block   { color:#ef4444; font-weight:700; }
.ob-safe    { color:#22c55e; font-weight:700; }
.ob-conf    { color:#f59e0b; font-size:10px; }
.ob-cursor  { display:inline-block; width:7px; height:13px; background:#00d4ff; vertical-align:middle; margin-left:3px; animation:ob-cursor 1s step-end infinite; }

/* ── Map dots (step 2) ── */
.ob-map-wrap {
  width:100%; height:100%; position:relative;
  display:flex; align-items:center; justify-content:center;
}
.ob-map-title {
  position:absolute; top:24px; left:0; right:0; text-align:center;
  font-size:10px; font-weight:800; color:#334155; text-transform:uppercase; letter-spacing:2.5px;
}
.ob-map-grid {
  width:240px; height:200px; position:relative;
}
.ob-mdot {
  position:absolute;
  width:8px; height:8px; border-radius:50%;
  background:#00d4ff;
  opacity:0;
  animation:ob-dot-appear 0.4s cubic-bezier(0.16,1,0.3,1) forwards;
}
.ob-mdot::after {
  content:''; position:absolute; inset:-4px; border-radius:50%;
  border:1.5px solid #00d4ff; opacity:0;
  animation:ob-ripple 2.5s ease infinite;
}
.ob-mdot.ob-red    { background:#ef4444; }
.ob-mdot.ob-red::after  { border-color:#ef4444; }
.ob-mdot.ob-amber  { background:#f59e0b; }
.ob-mdot.ob-amber::after{ border-color:#f59e0b; }
.ob-map-legend {
  position:absolute; bottom:20px; left:0; right:0;
  display:flex; justify-content:center; gap:16px;
}
.ob-ml-item { display:flex; align-items:center; gap:5px; font-size:10px; color:#475569; }
.ob-ml-dot  { width:7px; height:7px; border-radius:50%; }

/* ── Email scanner (step 3) ── */
.ob-email-wrap {
  width:100%; height:100%; position:relative;
  display:flex; align-items:center; justify-content:center;
  flex-direction:column; gap:16px;
}
.ob-mail-box {
  width:220px; background:#040810;
  border:1px solid #1e2a4a; border-radius:10px;
  overflow:hidden; position:relative;
}
.ob-mail-header {
  padding:10px 14px; border-bottom:1px solid #1e2a4a;
  display:flex; align-items:center; gap:8px;
}
.ob-mail-icon { width:22px; height:22px; }
.ob-mail-from { font-size:10px; color:#475569; font-family:monospace; }
.ob-mail-subject { font-size:9px; color:#334155; font-family:monospace; margin-top:1px; }
.ob-mail-body { padding:12px 14px; position:relative; overflow:hidden; min-height:90px; }
.ob-mail-line {
  height:6px; border-radius:3px; background:#0f1629;
  margin-bottom:7px;
}
.ob-scan-beam {
  position:absolute; left:0; right:0; height:2px;
  background:linear-gradient(90deg, transparent, rgba(0,212,255,0.8), transparent);
  animation:ob-scan-beam 2.8s ease-in-out infinite;
  box-shadow:0 0 8px rgba(0,212,255,0.6);
}
.ob-badges { display:flex; gap:8px; flex-wrap:wrap; justify-content:center; }
.ob-badge {
  padding:5px 11px; border-radius:6px; font-size:10px; font-weight:700;
  font-family:monospace; opacity:0;
  animation:ob-badge-in 0.3s ease forwards;
}
.ob-badge.ob-ok  { background:rgba(34,197,94,0.1);  border:1px solid rgba(34,197,94,0.3);  color:#22c55e; }
.ob-badge.ob-err { background:rgba(239,68,68,0.1);   border:1px solid rgba(239,68,68,0.3);  color:#ef4444; }
`

function injectStyles() {
  if (document.getElementById(STYLE_ID)) return
  const s = document.createElement('style')
  s.id = STYLE_ID; s.textContent = CSS
  document.head.appendChild(s)
}

/* ── Animation panels ─────────────────────────── */
function TerminalAnim() {
  return (
    <div className="ob-terminal">
      <div className="ob-term-header">
        <div className="ob-term-dot-row">
          <div className="ob-term-dot-r"/><div className="ob-term-dot-y"/><div className="ob-term-dot-g"/>
        </div>
        <span className="ob-term-title">Threat Scanner</span>
        <span className="ob-term-badge">LIVE</span>
      </div>
      <div className="ob-term-body">
        <div className="ob-term-counter">1.724.831 URLs Scanned</div>
        <div className="ob-tl ob-t1"><span className="ob-scan-c">[SCAN] </span><span className="ob-scan-url">→ hxxps://secure-login-paypal[.]com</span></div>
        <div className="ob-tl ob-t2"><span className="ob-block">[BLOCK] </span><span className="ob-block">✕ PHISHING</span><span className="ob-conf"> — 99.1% confidence</span></div>
        <div className="ob-tl ob-t3"><span className="ob-scan-c">[SCAN] </span><span className="ob-scan-url">→ hxxps://ptt-kargo-takip[.]net</span></div>
        <div className="ob-tl ob-t4"><span className="ob-block">[BLOCK] </span><span className="ob-block">✕ PHISHING</span><span className="ob-conf"> — 97.4% confidence</span></div>
        <div className="ob-tl ob-t5"><span className="ob-scan-c">[SCAN] </span><span className="ob-scan-url">→ hxxps://akbank-destek[.]org</span></div>
        <div className="ob-tl ob-t6"><span className="ob-safe">[SAFE] </span><span className="ob-safe">✓ Temiz</span></div>
        <span className="ob-cursor"/>
      </div>
    </div>
  )
}

const MAP_DOTS = [
  {x:'18%',y:'22%',delay:0.3,cls:'ob-red'},
  {x:'35%',y:'15%',delay:0.5,cls:''},
  {x:'55%',y:'18%',delay:0.7,cls:'ob-amber'},
  {x:'72%',y:'25%',delay:0.9,cls:'ob-red'},
  {x:'80%',y:'40%',delay:1.1,cls:''},
  {x:'68%',y:'55%',delay:1.3,cls:'ob-amber'},
  {x:'45%',y:'60%',delay:1.5,cls:'ob-red'},
  {x:'25%',y:'50%',delay:1.7,cls:''},
  {x:'12%',y:'40%',delay:1.9,cls:'ob-red'},
  {x:'50%',y:'38%',delay:2.1,cls:''},
  {x:'60%',y:'72%',delay:2.3,cls:'ob-amber'},
  {x:'30%',y:'75%',delay:2.5,cls:'ob-red'},
]

function MapAnim() {
  return (
    <div className="ob-map-wrap">
      <div className="ob-map-title">Mağduriyet Atlası — 81 İl</div>
      <div className="ob-map-grid">
        {MAP_DOTS.map((d,i) => (
          <div key={i} className={`ob-mdot ${d.cls}`}
            style={{left:d.x, top:d.y, animationDelay:`${d.delay}s`, animationDuration:`${0.4+i*0.02}s`}}>
            <div style={{position:'absolute',inset:'-4px',borderRadius:'50%',border:`1.5px solid ${d.cls==='ob-red'?'#ef4444':d.cls==='ob-amber'?'#f59e0b':'#00d4ff'}`,animation:`ob-ripple ${2+i*0.15}s ease ${d.delay+0.5}s infinite`}}/>
          </div>
        ))}
      </div>
      <div className="ob-map-legend">
        <div className="ob-ml-item"><div className="ob-ml-dot" style={{background:'#ef4444'}}/><span>Phishing</span></div>
        <div className="ob-ml-item"><div className="ob-ml-dot" style={{background:'#f59e0b'}}/><span>Dolandırıcılık</span></div>
        <div className="ob-ml-item"><div className="ob-ml-dot" style={{background:'#00d4ff'}}/><span>İzleniyor</span></div>
      </div>
    </div>
  )
}

const EMAIL_BADGES = [
  {label:'SPF ✓',  cls:'ob-ok',  delay:'0.4s'},
  {label:'DKIM ✓', cls:'ob-ok',  delay:'0.8s'},
  {label:'Header ✓',cls:'ob-ok', delay:'1.2s'},
  {label:'PHISHING ✕', cls:'ob-err', delay:'1.7s'},
]

function EmailAnim() {
  return (
    <div className="ob-email-wrap">
      <div style={{fontSize:'10px',fontWeight:800,color:'#334155',textTransform:'uppercase',letterSpacing:'2.5px',marginBottom:4}}>E-posta Analizi</div>
      <div className="ob-mail-box">
        <div className="ob-mail-header">
          <svg className="ob-mail-icon" viewBox="0 0 24 24" fill="none" stroke="#00d4ff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
            <rect x="2" y="4" width="20" height="16" rx="2"/><polyline points="2,4 12,13 22,4"/>
          </svg>
          <div>
            <div className="ob-mail-from">from: ptt-bildirim@ptt-kargo[.]net</div>
            <div className="ob-mail-subject">Kargonuz teslim edilemedi</div>
          </div>
        </div>
        <div className="ob-mail-body">
          <div className="ob-scan-beam"/>
          <div className="ob-mail-line" style={{width:'90%'}}/>
          <div className="ob-mail-line" style={{width:'75%'}}/>
          <div className="ob-mail-line" style={{width:'85%'}}/>
          <div className="ob-mail-line" style={{width:'60%'}}/>
          <div className="ob-mail-line" style={{width:'80%'}}/>
        </div>
      </div>
      <div className="ob-badges">
        {EMAIL_BADGES.map((b,i) => (
          <div key={i} className={`ob-badge ${b.cls}`} style={{animationDelay:b.delay}}>{b.label}</div>
        ))}
      </div>
    </div>
  )
}

/* ── Step data ─────────────────────────────────── */
const STEPS = [
  {
    tag:   'Tehdit Tespiti',
    title: 'Gerçek zamanlı tehdit tespiti',
    desc:  'SMS, e-posta veya URL yapıştır — sistem saniyeler içinde phishing, dolandırıcılık ve zararlı içerikleri analiz eder.',
    Anim:  TerminalAnim,
    stats: [
      {val:'1.5M+', lbl:'Tarama'},
      {val:'<3sn',  lbl:'Yanıt Süresi'},
      {val:'%97',   lbl:'Doğruluk'},
    ],
  },
  {
    tag:   'Platform',
    title: '8 modül, tek platform',
    desc:  'Phishing tarama, veri sızıntısı kontrolü, honeypot ve yapay zeka analizini tek ekrandan yönet.',
    Anim:  MapAnim,
    tags:  ['AI Analiz','Phishing','Breach Intel','Password Shield','Honeypot','Victim Atlas','IOC Tuzak','Risk Paneli'],
  },
  {
    tag:   'Türkiye Odaklı',
    title: 'Türkiye odaklı koruma',
    desc:  "PTT, SGK, MEB, Akbank gibi 30+ kurumu taklit eden sahte domainleri ve Türkiye'ye özel dolandırıcılık taktiklerini tanır.",
    Anim:  EmailAnim,
    stats: [
      {val:'30+',  lbl:'Türk Kurumu'},
      {val:'81',   lbl:'İl Takibi'},
      {val:'500+', lbl:'Sahte Domain'},
    ],
  },
]

/* ── Main component ───────────────────────────── */
export default function OnboardingOverlay() {
  const [visible,  setVisible]  = useState(false)
  const [closing,  setClosing]  = useState(false)
  const [step,     setStep]     = useState(0)
  const [leaving,  setLeaving]  = useState(false)
  const [stepKey,  setStepKey]  = useState(0)

  useEffect(() => {
    injectStyles()
    if (localStorage.getItem(STORAGE_KEY) !== '1') setVisible(true)
  }, [])

  const dismiss = useCallback(() => {
    setClosing(true)
    setTimeout(() => { localStorage.setItem(STORAGE_KEY,'1'); setVisible(false); setClosing(false) }, 260)
  }, [])

  const nextStep = useCallback(() => {
    if (step >= STEPS.length - 1) { dismiss(); return }
    setLeaving(true)
    setTimeout(() => { setStep(s => s+1); setStepKey(k => k+1); setLeaving(false) }, 240)
  }, [step, dismiss])

  useEffect(() => {
    const fn = e => { if (e.key==='Escape') dismiss() }
    if (visible) document.addEventListener('keydown', fn)
    return () => document.removeEventListener('keydown', fn)
  }, [visible, dismiss])

  if (!visible) return null

  const { tag, title, desc, Anim, stats, tags } = STEPS[step]
  const isLast = step === STEPS.length - 1

  return (
    <div className={`ob-backdrop${closing?' ob-closing':''}`} onClick={e => { if (e.target===e.currentTarget) dismiss() }}>
      <div className="ob-card" role="dialog" aria-modal="true" aria-label="AegisNexus tanıtımı">

        <button className="ob-close" onClick={dismiss} aria-label="Kapat">×</button>

        <div className="ob-inner">
          {/* Left — text */}
          <div className="ob-left">
            <div className="ob-dots">
              {STEPS.map((_,i) => <div key={i} className={`ob-dot ${i===step?'ob-active':'ob-inactive'}`}/>)}
            </div>

            <div key={stepKey} className={`ob-step-content${leaving?' ob-leaving':''}`}>
              <div className="ob-tag-label">{tag}</div>
              <p className="ob-title">{title}</p>
              <p className="ob-desc">{desc}</p>

              {stats && (
                <div className="ob-stats">
                  {stats.map((s,i) => (
                    <div key={i} className="ob-stat">
                      <span className="ob-stat-val">{s.val}</span>
                      <span className="ob-stat-lbl">{s.lbl}</span>
                    </div>
                  ))}
                </div>
              )}

              {tags && (
                <div className="ob-module-tags">
                  {tags.map((t,i) => <span key={i} className="ob-mtag">{t}</span>)}
                </div>
              )}
            </div>
          </div>

          {/* Right — animation */}
          <div className="ob-anim-panel">
            <div className="ob-anim-inner">
              <Anim key={stepKey} />
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="ob-footer">
          <span className="ob-step-counter">{step+1} / {STEPS.length}</span>
          {isLast ? (
            <button className="ob-btn" onClick={dismiss}>
              Başla
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
              </svg>
            </button>
          ) : (
            <button className="ob-btn-circle" onClick={nextStep} aria-label="Sonraki">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
              </svg>
            </button>
          )}
        </div>

      </div>
    </div>
  )
}
