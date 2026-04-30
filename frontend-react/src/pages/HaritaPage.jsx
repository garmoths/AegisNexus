import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { theme } from '../theme'
import { statsAPI } from '../lib/endpoints'

export default function HaritaPage() {
  const [features, setFeatures] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    statsAPI.heatmap().then(r => {
      setFeatures(r.data?.features || [])
    }).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const maxCount = Math.max(...features.map(f => f.properties?.case_count || 0), 1)

  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      <section style={{
        background: theme.gradientHero,
        padding: '60px 24px 30px',
        textAlign: 'center',
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: theme.text, margin: '0 0 8px' }}>
          🌍 Tehdit Haritası
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 15, margin: 0 }}>
          Türkiye il bazlı siber dolandırıcılık vaka yoğunluğu
        </p>
      </section>

      <section style={{ maxWidth: 1000, margin: '0 auto', padding: '30px 24px' }}>
        {loading ? (
          <p style={{ color: theme.textMuted, textAlign: 'center' }}>Yükleniyor...</p>
        ) : features.length === 0 ? (
          <p style={{ color: theme.textMuted, textAlign: 'center' }}>Henüz harita verisi yok.</p>
        ) : (
          <div style={{
            display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))',
            gap: 12,
          }}>
            {features
              .sort((a, b) => (b.properties?.case_count || 0) - (a.properties?.case_count || 0))
              .map((f, i) => {
                const count = f.properties?.case_count || 0
                const name = f.properties?.name || '?'
                const intensity = count / maxCount

                return (
                  <motion.div
                    key={name}
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.03, duration: 0.3 }}
                    style={{
                      background: theme.gradientSurface,
                      border: `1px solid ${theme.border}`,
                      borderRadius: theme.radius.md,
                      padding: 16,
                      position: 'relative',
                      overflow: 'hidden',
                    }}
                  >
                    {/* Heat bar */}
                    <div style={{
                      position: 'absolute', bottom: 0, left: 0, right: 0,
                      height: `${Math.max(intensity * 100, 8)}%`,
                      background: `linear-gradient(to top, ${theme.danger}${Math.round(intensity * 200).toString(16).padStart(2, '0')}, transparent)`,
                      pointerEvents: 'none',
                    }} />

                    <div style={{ position: 'relative' }}>
                      <h3 style={{ color: theme.text, fontSize: 15, fontWeight: 600, margin: '0 0 4px' }}>
                        {name}
                      </h3>
                      <span style={{
                        fontSize: 24, fontWeight: 800, color: intensity > 0.6 ? theme.danger : intensity > 0.3 ? theme.warning : theme.success,
                        fontFamily: 'monospace',
                      }}>
                        {count}
                      </span>
                      <span style={{ fontSize: 12, color: theme.textMuted, marginLeft: 4 }}>vaka</span>
                    </div>
                  </motion.div>
                )
              })}
          </div>
        )}
      </section>
    </div>
  )
}
