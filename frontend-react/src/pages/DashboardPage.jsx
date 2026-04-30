import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { theme } from '../theme'
import { statsAPI } from '../lib/endpoints'
import StatCounter from '../components/StatCounter'

export default function DashboardPage() {
  const [overview, setOverview] = useState(null)
  const [digest, setDigest] = useState(null)

  useEffect(() => {
    statsAPI.overview().then(r => setOverview(r.data)).catch(() => {})
    statsAPI.weeklyDigest().then(r => setDigest(r.data)).catch(() => {})
  }, [])

  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      <section style={{
        background: theme.gradientHero,
        padding: '60px 24px 30px',
        textAlign: 'center',
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: theme.text, margin: '0 0 8px' }}>
          📊 Dashboard
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 15, margin: 0 }}>
          Siber dolandırıcılık genel görünüm
        </p>
      </section>

      {/* Stats Cards */}
      <section style={{
        maxWidth: 1000, margin: '0 auto', padding: '30px 24px',
        display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: 16,
      }}>
        {[
          { label: 'Toplam Vaka', value: overview?.total_cases || 0 },
          { label: 'Aktif Tehdit', value: overview?.hot_cases || 0 },
          { label: 'Yayınlanan', value: overview?.published_cases || 0 },
          { label: 'Bu Hafta', value: overview?.weekly_new_cases || 0 },
        ].map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            style={{
              background: theme.gradientSurface,
              border: `1px solid ${theme.border}`,
              borderRadius: theme.radius.lg,
              padding: '24px 20px',
              textAlign: 'center',
            }}
          >
            <StatCounter value={s.value} label={s.label} />
          </motion.div>
        ))}
      </section>

      {/* Top Attack Methods */}
      {overview?.top_attack_methods?.length > 0 && (
        <section style={{
          maxWidth: 1000, margin: '0 auto', padding: '0 24px 30px',
        }}>
          <h2 style={{ color: theme.primary, fontSize: 18, fontWeight: 600, margin: '0 0 16px' }}>
            En Yaygın Saldırı Türleri
          </h2>
          <div style={{
            background: theme.gradientSurface,
            border: `1px solid ${theme.border}`,
            borderRadius: theme.radius.lg, padding: 20,
          }}>
            {overview.top_attack_methods.map((m, i) => {
              const maxC = overview.top_attack_methods[0]?.count || 1
              const pct = (m.count / maxC) * 100
              return (
                <div key={m.method} style={{ marginBottom: i < overview.top_attack_methods.length - 1 ? 12 : 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ color: theme.text, fontSize: 14, fontWeight: 500 }}>{m.method}</span>
                    <span style={{ color: theme.primary, fontSize: 14, fontWeight: 700, fontFamily: 'monospace' }}>{m.count}</span>
                  </div>
                  <div style={{
                    height: 8, borderRadius: 4, background: theme.surface,
                    overflow: 'hidden',
                  }}>
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${pct}%` }}
                      transition={{ delay: 0.3 + i * 0.1, duration: 0.8, ease: theme.ease.out }}
                      style={{
                        height: '100%', borderRadius: 4,
                        background: theme.gradientPrimary,
                      }}
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </section>
      )}

      {/* Weekly Digest */}
      {digest?.digest && (
        <section style={{
          maxWidth: 1000, margin: '0 auto', padding: '0 24px 40px',
        }}>
          <h2 style={{ color: theme.primary, fontSize: 18, fontWeight: 600, margin: '0 0 16px' }}>
            📰 Haftalık Bülten
          </h2>
          <div style={{
            background: theme.gradientSurface,
            border: `1px solid ${theme.border}`,
            borderRadius: theme.radius.lg, padding: 24,
            whiteSpace: 'pre-wrap', color: theme.text, fontSize: 14,
            lineHeight: 1.7,
          }}>
            {digest.digest}
          </div>
        </section>
      )}
    </div>
  )
}
