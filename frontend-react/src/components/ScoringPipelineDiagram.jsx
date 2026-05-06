import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const C = {
  surface: '#0f1629', surface2: '#1a2342', surface3: '#0c1322',
  border: '#1e2a4a',
  cyan: '#00d4ff',
  green: '#22c55e',
  red: '#ef4444',
  violet: '#a78bfa',
  orange: '#fb923c',
  amber: '#fbbf24',
  blue: '#60a5fa',
  slate: '#94a3b8',
  text: '#f1f5f9', muted: '#64748b', sub: '#94a3b8',
  mono: "ui-monospace, 'JetBrains Mono', monospace",
}

const DETAIL = {
  cache: {
    color: C.cyan,
    lines: [
      'Redis lookup (~0.3ms) — url_hash anahtarıyla arama',
      'Miss ise SQLite fallback — 30 günlük TTL',
      'force_fresh=true parametresi her iki cache\'i bypass eder',
    ],
  },
  wl: {
    color: C.green,
    lines: [
      'SQLite whitelist_domains tablosu — exact + subdomain match',
      'Hardcoded WHITELIST seti (binlerce güvenilir domain)',
      'Eşleşme → score = 100, analiz tamamen biter',
    ],
  },
  db: {
    color: C.red,
    lines: [
      'PhishingURL tablosu — url_hash ve canonical_url ile sorgu',
      'Kendi tehdit veritabanı — daha önce işaretlenmiş domainler',
      'Eşleşme → score = 0, analiz tamamen biter',
    ],
  },
  ml_pre: {
    color: C.violet,
    lines: [
      '23 URL özelliği çıkartılır: entropy, uzunluk, nokta, punycode...',
      'preliminary_score = 100 − ml_penalty hesaplanır',
      'Bu skor "analiz ediliyor" ekranında kullanıcıya gösterilir',
    ],
  },
  http: {
    color: C.slate,
    lines: [
      'requests.get(timeout=8) — HTTP→HTTPS fallback dener',
      'Erişilemezse erken döner, TI sonuçlarıyla birlikte',
      'Erişilebilirse page_content alınır, BeautifulSoup DOM analizi yapılır',
    ],
  },
  ti: {
    color: C.blue,
    lines: [
      'Screenshot → Playwright + OCR + Groq AI',
      'VirusTotal → ≥3 motor: +40 / ≥1: +20 / suspicious: +10',
      'Google Safe Browsing → tehdit: +50',
      'AbuseIPDB → ≥70%: +25 / ≥30%: +10',
      'Spamhaus + URLhaus + ThreatFox → +25–40',
      'RDAP domain yaşı → <7g: +65 / 403 erişim kısıtlı: +0',
      'Güvenilir TLD bonusu → edu.tr: −20 / com.tr: −10',
    ],
  },
  struct: {
    color: C.orange,
    lines: [
      'HTTPS yok → −25 / IP adres domain → −35',
      '@ işareti URL\'de → −25 / Standart dışı port → −5',
      'URL >100 karakter → −5 / Şüpheli kelimeler → max −30',
      'IOC veritabanı eşleşmesi → −30',
    ],
  },
  ml_url: {
    color: C.amber,
    lines: [
      '23 özellik ağırlıklı risk skoru → 0–100 normalize',
      'ml_score ≥60 → −20 / ≥35 → −12 / ≥20 → −5',
      'Özellikler: url_entropy, domain_entropy, subdomain_count, risky_tld',
    ],
  },
  ai: {
    color: C.red,
    lines: [
      'NLP regex: aciliyet, doğrulama, ödül, tehdit, finansal pattern',
      '/blog/ /haber/ /makale/ path tespiti → NLP ceza × 0.5',
      'Marka taklit: Google, Microsoft, Ziraat Bankası, e-Devlet...',
      'Credential harvesting tespit → ek −35 ceza',
      'Zararlı JS: eval, atob, obfuscation pattern',
      'Toplam AI ceza: max −60',
    ],
  },
  final: {
    color: C.green,
    lines: [
      'final_score = max(0, min(100, score))',
      'Whitelist eşleşmesi varsa: min 95 override uygulanır',
      'Bayesian probability combiner paralelde çalışır',
      'Sonuç Redis + SQLite\'a yazılır → frontend polling ile alır',
    ],
  },
}

function Arrow({ color = '#334155', dashed = false }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0, margin: '0 auto', width: 24 }}>
      <div style={{
        width: 2, height: 20,
        background: dashed
          ? `repeating-linear-gradient(to bottom, ${color} 0, ${color} 4px, transparent 4px, transparent 8px)`
          : `linear-gradient(to bottom, ${color}cc, ${color}44)`,
      }} />
      <svg width="10" height="6" style={{ display: 'block' }}>
        <polygon points="5,6 0,0 10,0" fill={color} opacity="0.7" />
      </svg>
    </div>
  )
}

function Block({ label, sub, color, badge, delay = 0, onClick, active, fullWidth = true }) {
  const isActive = active
  return (
    <motion.button
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay, duration: 0.28 }}
      whileHover={{ scale: 1.01 }}
      whileTap={{ scale: 0.99 }}
      onClick={onClick}
      style={{
        width: fullWidth ? '100%' : undefined,
        display: 'block', textAlign: 'center', cursor: 'pointer',
        border: 'none', outline: 'none',
        borderRadius: 12,
        padding: '12px 18px',
        background: isActive
          ? `linear-gradient(135deg, ${color}28, ${color}14)`
          : `linear-gradient(135deg, ${color}18, ${color}0a)`,
        boxShadow: isActive
          ? `0 0 0 1.5px ${color}88, 0 4px 24px ${color}22`
          : `0 0 0 1px ${color}33`,
        transition: 'box-shadow 0.18s, background 0.18s',
      }}
    >
      {badge && (
        <div style={{
          display: 'inline-block', marginBottom: 5,
          padding: '2px 9px', borderRadius: 20,
          background: color + '22', border: `1px solid ${color}44`,
          fontSize: 9, fontWeight: 800, color,
          fontFamily: C.mono, letterSpacing: '0.8px', textTransform: 'uppercase',
        }}>{badge}</div>
      )}
      <div style={{ fontSize: 13, fontWeight: 700, color: isActive ? color : C.text, lineHeight: 1.3 }}>{label}</div>
      {sub && <div style={{ fontSize: 11, color: C.muted, marginTop: 3, lineHeight: 1.4 }}>{sub}</div>}
    </motion.button>
  )
}

function Section({ title, color = C.border, children, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay, duration: 0.3 }}
      style={{
        borderRadius: 14,
        border: `1px solid ${C.border}`,
        background: 'rgba(15,22,41,0.6)',
        padding: '14px 14px 10px',
        marginBottom: 0,
      }}
    >
      <div style={{
        fontSize: 10, fontWeight: 700, color: C.muted,
        textTransform: 'uppercase', letterSpacing: '1.5px',
        marginBottom: 12, paddingLeft: 2,
      }}>{title}</div>
      {children}
    </motion.div>
  )
}

function Detail({ id }) {
  const d = DETAIL[id]
  if (!d) return null
  return (
    <motion.div
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: 'auto' }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.22 }}
      style={{ overflow: 'hidden' }}
    >
      <div style={{
        margin: '8px 0 0',
        padding: '10px 14px',
        borderRadius: 10,
        background: d.color + '0e',
        border: `1px solid ${d.color}33`,
      }}>
        {d.lines.map((line, i) => (
          <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: i < d.lines.length - 1 ? 5 : 0 }}>
            <div style={{ width: 4, height: 4, borderRadius: '50%', background: d.color, marginTop: 5, flexShrink: 0, opacity: 0.8 }} />
            <span style={{ fontSize: 11, color: C.sub, lineHeight: 1.55 }}>{line}</span>
          </div>
        ))}
      </div>
    </motion.div>
  )
}

export default function ScoringPipelineDiagram() {
  const [open, setOpen] = useState(null)
  const tog = (id) => setOpen(v => v === id ? null : id)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0, fontFamily: "'Inter', sans-serif" }}>

      {/* Giriş */}
      <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }}
        style={{
          textAlign: 'center', padding: '11px 20px', borderRadius: 12,
          background: C.surface2, border: `1px solid ${C.border}`,
        }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: C.text, letterSpacing: '-0.2px' }}>İstek geldi — URL</span>
      </motion.div>

      <div style={{ display: 'flex', justifyContent: 'center' }}><Arrow /></div>

      {/* K0 Cache */}
      <Block delay={0.04} label="Katman 0 — Cache kontrolü" badge="K0"
        sub="Redis (~0.3ms) → SQLite 30 gün → cache varsa döner"
        color={C.cyan} onClick={() => tog('cache')} active={open === 'cache'} />
      <AnimatePresence>{open === 'cache' && <Detail id="cache" />}</AnimatePresence>

      <div style={{ display: 'flex', justifyContent: 'center' }}><Arrow color={C.cyan} /></div>

      {/* Aşama A */}
      <Section title="Aşama A — Hızlı katmanlar · ~200ms · ağ yok" delay={0.08}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <div>
            <Block delay={0.10} label="K1 — Global Whitelist" badge="K1"
              sub="Eşleşirse → 100, biter" fullWidth
              color={C.green} onClick={() => tog('wl')} active={open === 'wl'} />
          </div>
          <div>
            <Block delay={0.12} label="K2–K3 — İç DB + Tehdit DB" badge="K2-3"
              sub="Eşleşirse → 0, biter" fullWidth
              color={C.red} onClick={() => tog('db')} active={open === 'db'} />
          </div>
        </div>
        <AnimatePresence>
          {open === 'wl' && <Detail id="wl" />}
          {open === 'db' && <Detail id="db" />}
        </AnimatePresence>

        <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}><Arrow color={C.violet} dashed /></div>

        <Block delay={0.14} label="ML Ön Tarama — preliminary_score" badge="ML"
          sub="23 URL özelliği hesaplanır, kullanıcıya gösterilir"
          color={C.violet} onClick={() => tog('ml_pre')} active={open === 'ml_pre'} />
        <AnimatePresence>{open === 'ml_pre' && <Detail id="ml_pre" />}</AnimatePresence>
      </Section>

      <div style={{ display: 'flex', justifyContent: 'center' }}><Arrow /></div>

      {/* Aşama B */}
      <Section title="Aşama B — Celery ağır analiz · score = 100 ile başlar" delay={0.16}>

        <Block delay={0.18} label="K4 — HTTP Canlılık + HTML Analiz" badge="K4"
          sub="Erişilemezse erken döner · erişilebilirse page_content + DOM"
          color={C.slate} onClick={() => tog('http')} active={open === 'http'} />
        <AnimatePresence>{open === 'http' && <Detail id="http" />}</AnimatePresence>

        <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}><Arrow color={C.blue} /></div>

        <Block delay={0.20} label="K8 — Paralel Tehdit İstihbaratı · max 40s" badge="K8"
          sub="Screenshot · VT · GSB · AbuseIPDB · Spamhaus · RDAP · TLD Bonus"
          color={C.blue} onClick={() => tog('ti')} active={open === 'ti'} />
        <AnimatePresence>{open === 'ti' && <Detail id="ti" />}</AnimatePresence>

        <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}><Arrow /></div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          <div>
            <Block delay={0.22} label="K5 — Yapısal Analiz" badge="K5"
              sub="HTTPS · port · @ · IP · yönlendirme" fullWidth
              color={C.orange} onClick={() => tog('struct')} active={open === 'struct'} />
          </div>
          <div>
            <Block delay={0.24} label="K6 — ML Sınıflandırma" badge="K6"
              sub="ml_score ≥60 → −20 puan" fullWidth
              color={C.amber} onClick={() => tog('ml_url')} active={open === 'ml_url'} />
          </div>
        </div>
        <AnimatePresence>
          {open === 'struct' && <Detail id="struct" />}
          {open === 'ml_url' && <Detail id="ml_url" />}
        </AnimatePresence>

        <div style={{ display: 'flex', justifyContent: 'center', margin: '4px 0' }}><Arrow color={C.red} /></div>

        <Block delay={0.26} label="K7 — AI İçerik Analizi · max −60 puan" badge="K7"
          sub="NLP · Marka Taklit · Credential Harvesting · Zararlı JS"
          color={C.red} onClick={() => tog('ai')} active={open === 'ai'} />
        <AnimatePresence>{open === 'ai' && <Detail id="ai" />}</AnimatePresence>

      </Section>

      <div style={{ display: 'flex', justifyContent: 'center' }}><Arrow color={C.green} /></div>

      {/* Final */}
      <Block delay={0.28} label="Aşama C — Final Skor" badge="SON"
        sub="max(0, min(100, score)) → Redis + SQLite → frontend"
        color={C.green} onClick={() => tog('final')} active={open === 'final'} />
      <AnimatePresence>{open === 'final' && <Detail id="final" />}</AnimatePresence>

      {/* Score legend */}
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.32 }}
        style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 6, marginTop: 14 }}>
        {[
          { label: '≥80 Güvenli',   color: C.green },
          { label: '60–79 Şüpheli', color: C.amber },
          { label: '40–59 Orta',    color: C.orange },
          { label: '<40 Tehlikeli', color: C.red },
        ].map(s => (
          <div key={s.label} style={{
            padding: '8px 4px', borderRadius: 9, textAlign: 'center',
            background: s.color + '15',
            border: `1px solid ${s.color}30`,
          }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: s.color, display: 'block' }}>{s.label}</span>
          </div>
        ))}
      </motion.div>

      <p style={{ fontSize: 10, color: C.muted, textAlign: 'center', marginTop: 10, marginBottom: 0 }}>
        Kutulara tıkla → detayları gör
      </p>
    </div>
  )
}
