import { useState } from 'react'
import { motion } from 'framer-motion'
import { theme } from '../theme'
import { reportsAPI, smsGuardAPI } from '../lib/endpoints'
import GeminiLoader from '../components/GeminiLoader'
import RiskBadge from '../components/RiskBadge'

export default function AnalyzePage() {
  const [description, setDescription] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  // SMS Widget state
  const [smsText, setSmsText] = useState('')
  const [smsSender, setSmsSender] = useState('')
  const [smsResult, setSmsResult] = useState(null)
  const [smsLoading, setSmsLoading] = useState(false)

  const analyze = async () => {
    if (!description.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const res = await reportsAPI.analyze(description)
      setResult(res.data)
    } catch (error) {
      if (error.response?.status === 401) {
        setResult({ error: 'Analiz için giriş yapmanız gerekiyor.' })
      } else {
        setResult({ error: 'Analiz sırasında hata oluştu.' })
      }
    }
    setLoading(false)
  }

  const analyzeSMS = async () => {
    if (!smsText.trim()) return
    setSmsLoading(true)
    setSmsResult(null)
    try {
      const res = await smsGuardAPI.analyze(smsText, smsSender)
      setSmsResult(res.data)
    } catch {
      setSmsResult({ error: 'SMS analizi sırasında hata oluştu.' })
    }
    setSmsLoading(false)
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

      {/* SMS Guard Widget */}
      <section style={{ maxWidth: 700, margin: '0 auto', padding: '30px 24px' }}>
        <div style={{
          background: theme.gradientSurface,
          border: `1px solid ${theme.border}`,
          borderRadius: theme.radius.lg,
          padding: 24,
        }}>
          <h3 style={{ color: theme.text, fontSize: 16, fontWeight: 600, margin: '0 0 16px' }}>
            📱 SMS Güvenlik Analizi (Demo)
          </h3>

          <input
            value={smsSender}
            onChange={e => setSmsSender(e.target.value)}
            placeholder="Gönderen numara/başlık (opsiyonel)"
            style={{
              width: '100%', padding: '12px 14px', marginBottom: 12,
              background: theme.surface, border: `1px solid ${theme.border}`,
              borderRadius: theme.radius.sm, color: theme.text, fontSize: 14,
              outline: 'none',
            }}
          />

          <textarea
            value={smsText}
            onChange={e => setSmsText(e.target.value)}
            placeholder="SMS içeriğini yapıştırın..."
            rows={4}
            style={{
              width: '100%', padding: '14px', background: theme.surface,
              border: `1px solid ${theme.border}`, borderRadius: theme.radius.sm,
              color: theme.text, fontSize: 14, lineHeight: 1.6,
              resize: 'vertical', outline: 'none', fontFamily: 'inherit',
            }}
          />

          <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 16 }}>
            <button
              onClick={analyzeSMS}
              disabled={smsLoading || !smsText.trim()}
              style={{
                padding: '12px 32px',
                background: smsLoading || !smsText.trim() ? theme.surface : theme.gradientPrimary,
                color: smsLoading || !smsText.trim() ? theme.textMuted : theme.bgDeep,
                fontWeight: 700, border: 'none',
                borderRadius: theme.radius.sm, cursor: smsLoading ? 'wait' : 'pointer',
                fontSize: 14,
              }}
            >
              {smsLoading ? 'Analiz Ediliyor...' : '🔍 SMS Analizi'}
            </button>
          </div>

          {smsResult && !smsResult.error && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              style={{
                marginTop: 20, background: theme.bg,
                border: `1px solid ${theme.border}`,
                borderRadius: theme.radius.md, padding: 16,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                <span style={{
                  padding: '4px 12px', borderRadius: 12, fontSize: 11, fontWeight: 700,
                  background: smsResult.action === 'BLOCK' ? `${theme.danger}20` : smsResult.action === 'WARN' ? `${theme.warning}20` : `${theme.success}20`,
                  color: smsResult.action === 'BLOCK' ? theme.danger : smsResult.action === 'WARN' ? theme.warning : theme.success,
                }}>
                  {smsResult.action}: {smsResult.category}
                </span>
                <span style={{ fontSize: 20, fontWeight: 800, color: smsResult.risk_score >= 75 ? theme.danger : smsResult.risk_score >= 45 ? theme.warning : theme.success }}>
                  {smsResult.risk_score}
                </span>
              </div>
              <p style={{ color: theme.text, fontSize: 13, lineHeight: 1.6, margin: '0 0 12px' }}>
                {smsResult.explanation}
              </p>
              {smsResult.urls && smsResult.urls.length > 0 && (
                <div>
                  <p style={{ color: theme.textMuted, fontSize: 11, margin: '0 0 8px', fontWeight: 600 }}>
                    Tespit edilen URL'ler:
                  </p>
                  {smsResult.urls.map((u, i) => (
                    <div key={i} style={{
                      padding: '8px 12px', marginBottom: 6,
                      background: u.is_suspicious ? `${theme.danger}10` : `${theme.success}08`,
                      border: `1px solid ${u.is_suspicious ? `${theme.danger}20` : `${theme.success}20`}`,
                      borderRadius: theme.radius.sm, fontSize: 12,
                    }}>
                      <div style={{ color: theme.primary, fontFamily: 'monospace', marginBottom: 4 }}>
                        {u.url}
                      </div>
                      <div style={{ color: theme.textMuted, fontSize: 11 }}>
                        {u.reason}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          )}

          {smsResult?.error && (
            <div style={{
              marginTop: 20, padding: 12, background: `${theme.danger}12`,
              border: `1px solid ${theme.danger}30`, borderRadius: theme.radius.sm,
              color: theme.danger, fontSize: 13,
            }}>
              {smsResult.error}
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
