import { useState } from 'react'
import { motion } from 'framer-motion'
import { theme } from '../theme'
import { reportsAPI } from '../lib/endpoints'
import useAuthStore from '../stores/authStore'
import GeminiLoader from '../components/GeminiLoader'
import RiskBadge from '../components/RiskBadge'

export default function AnalyzePage() {
  const [description, setDescription] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [reports, setReports] = useState([])
  const isAuthenticated = useAuthStore(s => s.isAuthenticated)

  const analyze = async () => {
    if (!description.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await reportsAPI.analyze(description)
      setResult(res.data)
    } catch (e) {
      if (e.response?.status === 401) {
        setResult({ error: 'Analiz için giriş yapmanız gerekiyor.' })
      } else {
        setResult({ error: 'Analiz sırasında hata oluştu.' })
      }
    }
    setLoading(false)
  }

  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      <section style={{
        background: theme.gradientHero,
        padding: '60px 24px 30px',
        textAlign: 'center',
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: theme.text, margin: '0 0 8px' }}>
          🔍 Analiz Aracı
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 15, margin: 0, maxWidth: 500, marginLeft: 'auto', marginRight: 'auto' }}>
          Yaşadığınız siber olayı anlatın, Gemini size özel korunma planı üretsin.
        </p>
      </section>

      <section style={{ maxWidth: 700, margin: '0 auto', padding: '30px 24px' }}>
        {/* Input */}
        <div style={{
          background: theme.gradientSurface,
          border: `1px solid ${theme.border}`,
          borderRadius: theme.radius.lg,
          padding: 24,
        }}>
          <textarea
            value={description}
            onChange={e => setDescription(e.target.value)}
            placeholder="Örnek: Dün telefonuma 'Şüpheli işlem tespit edildi, hesabınızı doğrulamak için tıklayın' diye bir SMS geldi. Linke tıkladım ve banka bilgilerimi girdim..."
            rows={6}
            style={{
              width: '100%', padding: 14, background: theme.surface,
              border: `1px solid ${theme.border}`, borderRadius: theme.radius.sm,
              color: theme.text, fontSize: 14, lineHeight: 1.6,
              resize: 'vertical', outline: 'none', fontFamily: 'inherit',
            }}
          />

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
            <button
              onClick={analyze}
              disabled={loading || !description.trim()}
              style={{
                padding: '12px 32px',
                background: loading || !description.trim() ? theme.surface : theme.gradientPrimary,
                color: loading || !description.trim() ? theme.textMuted : theme.bgDeep,
                fontWeight: 700, border: 'none',
                borderRadius: theme.radius.sm, cursor: loading ? 'wait' : 'pointer',
                fontSize: 14,
              }}
            >
              {loading ? 'Analiz Ediliyor...' : '🤖 Gemini ile Analiz Et'}
            </button>
          </div>
        </div>

        {/* Loading */}
        {loading && <GeminiLoader text="Gemini olayınızı analiz ediyor..." />}

        {/* Result */}
        {result && !result.error && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            style={{
              marginTop: 24, background: theme.gradientSurface,
              border: `1px solid ${theme.border}`,
              borderRadius: theme.radius.lg, padding: 24,
            }}
          >
            <div style={{ display: 'flex', gap: 20, alignItems: 'center', marginBottom: 20 }}>
              <RiskBadge score={result.risk_score || 50} type="severity" size="md" />
              <div>
                <h3 style={{ color: theme.text, fontSize: 18, fontWeight: 600, margin: '0 0 4px' }}>
                  Saldırı Tipi: {result.attack_type || 'Bilinmiyor'}
                </h3>
                <p style={{ color: theme.textMuted, fontSize: 13, margin: 0 }}>
                  Rapor ID: {result.id}
                </p>
              </div>
            </div>

            {result.critical_warning && (
              <div style={{
                padding: '12px 16px', marginBottom: 16,
                background: `${theme.danger}12`, border: `1px solid ${theme.danger}30`,
                borderRadius: theme.radius.sm, color: theme.text, fontSize: 14,
              }}>
                ⚠️ {result.critical_warning}
              </div>
            )}

            {result.protection_plan && (
              <div>
                <h4 style={{ color: theme.primary, fontSize: 15, fontWeight: 600, margin: '0 0 12px' }}>
                  🛡️ Korunma Planı
                </h4>
                <div style={{
                  whiteSpace: 'pre-wrap', color: theme.text, fontSize: 14,
                  lineHeight: 1.7, background: `${theme.primary}08`,
                  padding: 16, borderRadius: theme.radius.sm,
                  border: `1px solid ${theme.primarySoft}`,
                }}>
                  {result.protection_plan}
                </div>
              </div>
            )}

            <p style={{ color: theme.success, fontSize: 13, marginTop: 16, fontWeight: 500 }}>
              ✅ {result.message}
            </p>
          </motion.div>
        )}

        {result?.error && (
          <div style={{
            marginTop: 24, padding: 16, background: `${theme.danger}12`,
            border: `1px solid ${theme.danger}30`, borderRadius: theme.radius.sm,
            color: theme.danger, fontSize: 14,
          }}>
            {result.error}
          </div>
        )}
      </section>
    </div>
  )
}
