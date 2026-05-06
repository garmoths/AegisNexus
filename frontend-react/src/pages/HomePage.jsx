import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { theme } from '../theme'
import { statsAPI, casesAPI } from '../lib/endpoints'
import StatCounter from '../components/StatCounter'
import ThreatTicker from '../components/ThreatTicker'

export default function HomePage() {
  const [stats, setStats] = useState(null)
  const [hotCases, setHotCases] = useState([])

  useEffect(() => {
    statsAPI.overview().then(r => setStats(r.data)).catch(() => {})
    casesAPI.list({ hot_set_only: true, limit: 5 }).then(r => {
      setHotCases(r.data?.data || [])
    }).catch(() => {})
  }, [])

  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      {/* Hero */}
      <section style={{
        position: 'relative', padding: '100px 24px 60px',
        background: theme.gradientHero,
        textAlign: 'center',
        overflow: 'hidden',
      }}>
        {/* Grid overlay */}
        <div style={{
          position: 'absolute', inset: 0,
          backgroundImage: theme.gridPattern,
          backgroundSize: theme.gridPatternSize,
          opacity: 0.5,
        }} />

        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: theme.ease.out }}
          style={{
            fontSize: 48, fontWeight: 800, color: theme.text,
            margin: '0 0 16px', position: 'relative',
            letterSpacing: '-1px',
          }}
        >
          Siber Mağduriyet{' '}
          <span style={{
            background: theme.gradientPrimary,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}>
            Atlası
          </span>
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.6 }}
          style={{
            fontSize: 18, color: theme.textMuted, maxWidth: 600,
            margin: '0 auto 40px', lineHeight: 1.6, position: 'relative',
          }}
        >
          Türkiye'deki siber dolandırıcılık vakalarını izleyin, analiz edin ve korunma planı oluşturun.
        </motion.p>

        {/* Stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.6 }}
          style={{
            display: 'flex', justifyContent: 'center', gap: 48,
            flexWrap: 'wrap', position: 'relative',
          }}
        >
          <StatCounter value={stats?.total_cases || 0} label="Toplam Vaka" />
          <StatCounter value={stats?.hot_cases || 0} label="Aktif Tehdit" />
          <StatCounter value={stats?.weekly_new_cases || 0} label="Bu Hafta" />
        </motion.div>
      </section>

      {/* Threat Ticker */}
      <section style={{ maxWidth: 900, margin: '0 auto', padding: '20px 24px' }}>
        {hotCases.length > 0 && <ThreatTicker cases={hotCases} />}
      </section>

      {/* CTA Cards */}
      <section style={{
        maxWidth: 900, margin: '0 auto', padding: '40px 24px',
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
        gap: 20,
      }}>
        {[
          { to: '/atlas', icon: '🗺️', title: 'Vaka Atlası', desc: 'Tüm siber dolandırıcılık vakalarını keşfedin' },
          { to: '/analyze', icon: '🔍', title: 'Analiz Aracı', desc: 'Yaşadığınız olayı AI ile analiz edin' },
          { to: '/harita', icon: '🌍', title: 'Tehdit Haritası', desc: 'İl bazlı vaka yoğunluğunu görün' },
        ].map((card, i) => (
          <motion.div
            key={card.to}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 * i, duration: 0.5 }}
          >
            <Link to={card.to} style={{ textDecoration: 'none' }}>
              <div style={{
                background: theme.gradientSurface,
                border: `1px solid ${theme.border}`,
                borderRadius: theme.radius.lg,
                padding: '28px 24px',
                transition: 'all 0.3s',
                cursor: 'pointer',
              }}>
                <span style={{ fontSize: 32 }}>{card.icon}</span>
                <h3 style={{ color: theme.text, fontSize: 18, fontWeight: 600, margin: '12px 0 8px' }}>
                  {card.title}
                </h3>
                <p style={{ color: theme.textMuted, fontSize: 14, margin: 0, lineHeight: 1.5 }}>
                  {card.desc}
                </p>
              </div>
            </Link>
          </motion.div>
        ))}
      </section>
    </div>
  )
}
