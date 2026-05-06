import { useState } from 'react'
import { motion } from 'framer-motion'

const C = {
  bg: '#080c14', surface: '#0f1629', surface2: '#1a2342', surface3: '#0c1322',
  border: '#1e2a4a',
  cyan: '#00d4ff',   cyanDim: 'rgba(0,212,255,0.12)',
  green: '#22c55e',  greenDim: 'rgba(34,197,94,0.15)',
  red: '#ef4444',    redDim: 'rgba(239,68,68,0.15)',
  violet: '#9f7aea', violetDim: 'rgba(159,122,234,0.15)',
  orange: '#f97316', orangeDim: 'rgba(249,115,22,0.15)',
  amber: '#f59e0b',  amberDim: 'rgba(245,158,11,0.15)',
  blue: '#3b82f6',   blueDim: 'rgba(59,130,246,0.15)',
  text: '#e2e8f0', muted: '#64748b',
  mono: "'JetBrains Mono', monospace",
}

/* ─── küçük yardımcılar ─── */
function Arrow({ color = C.muted }) {
  return (
    <div style={{ display:'flex', justifyContent:'center', margin:'2px 0' }}>
      <svg width="16" height="20" viewBox="0 0 16 20">
        <line x1="8" y1="0" x2="8" y2="14" stroke={color} strokeWidth="1.5" strokeDasharray="3,2" />
        <polygon points="4,14 12,14 8,20" fill={color} opacity="0.7" />
      </svg>
    </div>
  )
}

function Box({ label, sub, color, dim, badge, delay = 0, wide = false, onClick, active }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.3 }}
      onClick={onClick}
      style={{
        border: `1px solid ${active ? color : color + '55'}`,
        borderRadius: 10, background: active ? dim : color + '18',
        padding: '10px 16px', cursor: onClick ? 'pointer' : 'default',
        boxShadow: active ? `0 0 18px ${color}25` : 'none',
        transition: 'all 0.18s',
        width: wide ? '100%' : undefined,
      }}
    >
      <div style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:8, flexWrap:'wrap' }}>
        {badge && (
          <span style={{ fontSize:9, fontWeight:800, padding:'2px 7px', borderRadius:4,
            background: color + '22', color, border:`1px solid ${color}44`,
            fontFamily: C.mono, letterSpacing:'0.5px', flexShrink:0 }}>{badge}</span>
        )}
        <span style={{ fontSize:13, fontWeight:700, color: C.text, textAlign:'center' }}>{label}</span>
      </div>
      {sub && <p style={{ fontSize:11, color: C.muted, textAlign:'center', marginTop:4, lineHeight:1.5 }}>{sub}</p>}
    </motion.div>
  )
}

function SectionWrap({ label, children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }}
      transition={{ delay, duration: 0.4 }}
      style={{
        border: `1px dashed ${C.border}`, borderRadius: 14,
        padding: '12px 14px', marginBottom: 4,
        background: 'rgba(255,255,255,0.015)',
      }}
    >
      <p style={{ fontSize:10, fontWeight:700, color: C.muted, textTransform:'uppercase',
        letterSpacing:'1.5px', marginBottom:10 }}>{label}</p>
      {children}
    </motion.div>
  )
}

/* ─── Tooltip detay paneli ─── */
const DETAILS = {
  cache:    { title:'Cache Kontrolü', color: C.cyan,   body: 'Redis (~0.3ms) → url_hash key ile arama. Miss ise SQLite fallback (30 gün TTL). force_fresh=true parametresi her iki cache\'i bypass eder.' },
  wl:       { title:'Global Whitelist', color: C.green, body: 'SQLite whitelist_domains tablosu + hardcoded WHITELIST seti. Exact match ve subdomain match. Eşleşirse score=100, analiz biter.' },
  db:       { title:'İç Veritabanı + Tehdit DB', color: C.red, body: 'PhishingURL tablosunda url_hash ve canonical_url exact match. Sonra kendi tehdit veritabanı kontrolü. Eşleşirse score=0, analiz biter.' },
  ml_pre:   { title:'ML Ön Tarama', color: C.violet, body: '23 URL özelliği çıkartılır (entropy, uzunluk, nokta sayısı, punycode...). preliminary_score = 100 − ml_penalty. Bu skor kullanıcıya "analiz ediliyor" ekranında gösterilir.' },
  http:     { title:'HTTP Canlılık + HTML', color: C.muted, body: 'requests.get(timeout=8). HTTP→HTTPS fallback. Erişilemezse erken döner. Erişilebilirse page_content alınır ve BeautifulSoup DOM analizi yapılır (gizli formlar, obfuscation).' },
  ti:       { title:'Paralel TI — max 40s', color: C.blue, body: '6 görev ThreadPoolExecutor\'da aynı anda:\n• Screenshot → Playwright + OCR + Groq AI\n• VirusTotal → +40/+20/+10\n• Google Safe Browsing → +50\n• AbuseIPDB → +25/+10\n• Spamhaus + URLhaus + ThreatFox → +25–40\n• RDAP domain yaşı → +65 (<7g) / 403: +0\n• TLD bonus: edu.tr –20, com.tr –10' },
  struct:   { title:'Yapısal Analiz', color: C.orange, body: 'HTTPS yok: −25 / IP domain: −35 / @ işareti: −25 / Standart dışı port: −5 / URL >100 karakter: −5 / Şüpheli kelimeler URL\'de: max −30 / IOC DB eşleşmesi: −30' },
  ml_url:   { title:'ML URL Sınıflandırması', color: C.amber, body: '23 özellik ağırlıklı risk skoru → normalize (0–100). ml_score ≥60: −20 / ≥35: −12 / ≥20: −5. Özellikler: url_entropy, domain_entropy, subdomain_count, risky_tld, has_punycode...' },
  ai:       { title:'AI İçerik Analizi', color: C.red, body: 'NLP regex (aciliyet, doğrulama, ödül, finansal) + /blog/ path → ×0.5 indirim. Marka taklit (Google, MS, Ziraat, eDevlet...). Credential harvesting → ek −35. Zararlı JS. Toplam max −60.' },
  final:    { title:'Final Skor', color: C.green, body: 'final_score = max(0, min(100, score)). Whitelist override: min 95. Bayesian combiner paralelde çalışır. Sonuç Redis\'e + SQLite\'a yazılır → frontend polling ile alır.' },
}

function DetailPanel({ id, onClose }) {
  const d = DETAILS[id]
  if (!d) return null
  return (
    <motion.div
      initial={{ opacity:0, y:8 }} animate={{ opacity:1, y:0 }}
      exit={{ opacity:0 }} transition={{ duration:0.2 }}
      style={{
        border:`1px solid ${d.color}55`, borderRadius:10,
        background: d.color + '10', padding:'12px 16px',
        marginTop:8,
      }}
    >
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
        <span style={{ fontSize:12, fontWeight:800, color: d.color }}>{d.title}</span>
        <button onClick={onClose} style={{ background:'none', border:'none', cursor:'pointer', color: C.muted, fontSize:16, lineHeight:1 }}>×</button>
      </div>
      <p style={{ fontSize:11, color: C.muted, lineHeight:1.7, whiteSpace:'pre-line' }}>{d.body}</p>
    </motion.div>
  )
}

/* ─── Ana bileşen ─── */
export default function ScoringPipelineDiagram() {
  const [active, setActive] = useState(null)
  const toggle = (id) => setActive(v => v === id ? null : id)

  return (
    <div style={{ fontFamily: "'Inter', sans-serif", color: C.text }}>
      {/* Entry */}
      <motion.div initial={{ opacity:0, y:-8 }} animate={{ opacity:1, y:0 }} transition={{ duration:0.3 }}
        style={{ border:`1px solid ${C.border}`, borderRadius:10, padding:'10px 16px', background: C.surface2, textAlign:'center', marginBottom:4 }}>
        <span style={{ fontSize:13, fontWeight:700, color: C.text }}>İstek geldi — URL</span>
      </motion.div>
      <Arrow />

      {/* Katman 0 */}
      <Box delay={0.05} wide label="Katman 0 — Cache kontrolü"
        sub="Redis (~0.3ms) → SQLite 30 gün → cache varsa döner"
        color={C.cyan} dim={C.cyanDim} badge="K0"
        onClick={() => toggle('cache')} active={active === 'cache'} />
      {active === 'cache' && <DetailPanel id="cache" onClose={() => setActive(null)} />}
      <Arrow color={C.cyan} />

      {/* Aşama A */}
      <SectionWrap label="Aşama A — Hızlı katmanlar (~200ms, ağ yok)" delay={0.1}>
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginBottom:8 }}>
          <div>
            <Box delay={0.12} label="K1 — Global whitelist"
              sub="Eşleşirse → 100, biter"
              color={C.green} dim={C.greenDim} badge="K1"
              onClick={() => toggle('wl')} active={active === 'wl'} />
          </div>
          <div>
            <Box delay={0.14} label="K2+K3 — İç DB + Tehdit DB"
              sub="Eşleşirse → 0, biter"
              color={C.red} dim={C.redDim} badge="K2-3"
              onClick={() => toggle('db')} active={active === 'db'} />
          </div>
        </div>
        {(active === 'wl' || active === 'db') && <DetailPanel id={active} onClose={() => setActive(null)} />}

        <Arrow color={C.violet} />
        <Box delay={0.18} wide label="ML ön tarama — preliminary_score"
          sub="23 URL özelliği → kullanıcıya gösterilir"
          color={C.violet} dim={C.violetDim} badge="ML"
          onClick={() => toggle('ml_pre')} active={active === 'ml_pre'} />
        {active === 'ml_pre' && <DetailPanel id="ml_pre" onClose={() => setActive(null)} />}
      </SectionWrap>
      <Arrow />

      {/* Aşama B */}
      <SectionWrap label="Aşama B — Celery ağır analiz (score = 100 ile başlar)" delay={0.2}>
        {/* K4 */}
        <Box delay={0.22} wide label="K4 — HTTP canlılık + HTML analiz"
          sub="Erişilemezse → erken dön; erişilebilirse devam"
          color={C.muted} dim="rgba(100,116,139,0.12)" badge="K4"
          onClick={() => toggle('http')} active={active === 'http'} />
        {active === 'http' && <DetailPanel id="http" onClose={() => setActive(null)} />}
        <Arrow color={C.blue} />

        {/* K8 TI */}
        <Box delay={0.25} wide label="K8 — Paralel TI (max 40s)"
          sub="Screenshot + VT + GSB + AbuseIPDB + Spamhaus + RDAP + Domain Age"
          color={C.blue} dim={C.blueDim} badge="K8"
          onClick={() => toggle('ti')} active={active === 'ti'} />
        {active === 'ti' && <DetailPanel id="ti" onClose={() => setActive(null)} />}
        <Arrow />

        {/* K5 + K6 yan yana */}
        <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:8 }}>
          <div>
            <Box delay={0.28} label="K5 — Yapısal analiz"
              sub="HTTPS, port, @, IP, yönlendirme"
              color={C.orange} dim={C.orangeDim} badge="K5"
              onClick={() => toggle('struct')} active={active === 'struct'} />
          </div>
          <div>
            <Box delay={0.30} label="K6 — ML URL sınıflandırması"
              sub="ml_score ≥60 → −20 puan"
              color={C.amber} dim={C.amberDim} badge="K6"
              onClick={() => toggle('ml_url')} active={active === 'ml_url'} />
          </div>
        </div>
        {(active === 'struct' || active === 'ml_url') && <DetailPanel id={active} onClose={() => setActive(null)} />}
        <Arrow color={C.red} />

        {/* K7 */}
        <Box delay={0.33} wide label="K7 — AI içerik analizi (max −60 puan)"
          sub="NLP + marka taklit + credential harvesting + zararlı JS"
          color={C.red} dim={C.redDim} badge="K7"
          onClick={() => toggle('ai')} active={active === 'ai'} />
        {active === 'ai' && <DetailPanel id="ai" onClose={() => setActive(null)} />}
      </SectionWrap>
      <Arrow color={C.green} />

      {/* Final */}
      <Box delay={0.36} wide label="Aşama C — Final skor"
        sub="max(0, min(100, score)) → Redis + SQLite → frontend"
        color={C.green} dim={C.greenDim} badge="SON"
        onClick={() => toggle('final')} active={active === 'final'} />
      {active === 'final' && <DetailPanel id="final" onClose={() => setActive(null)} />}

      {/* Score legend */}
      <motion.div initial={{ opacity:0 }} animate={{ opacity:1 }} transition={{ delay:0.4 }}
        style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:6, marginTop:12 }}>
        {[
          { label:'≥80 Güvenli', color: C.green },
          { label:'60–79 Şüpheli', color: C.amber },
          { label:'40–59 Orta', color: C.orange },
          { label:'<40 Tehlikeli', color: C.red },
        ].map(s => (
          <div key={s.label} style={{
            padding:'7px 6px', borderRadius:8, textAlign:'center',
            background: s.color + '18', border:`1px solid ${s.color}44`,
          }}>
            <span style={{ fontSize:11, fontWeight:700, color: s.color }}>{s.label}</span>
          </div>
        ))}
      </motion.div>

      <p style={{ fontSize:10, color: C.muted, textAlign:'center', marginTop:10 }}>
        Kutulara tıklayarak detayları gör
      </p>
    </div>
  )
}
