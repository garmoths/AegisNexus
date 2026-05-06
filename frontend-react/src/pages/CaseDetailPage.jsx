import { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { theme } from '../theme'
import { casesAPI } from '../lib/endpoints'
import useAuthStore from '../stores/authStore'
import AttackTypeBadge from '../components/AttackTypeBadge'
import RiskBadge from '../components/RiskBadge'
import GeminiLoader from '../components/GeminiLoader'
import PremiumGate from '../components/PremiumGate'
import ProtectionPlan from '../components/ProtectionPlan'

export default function CaseDetailPage() {
  const { id } = useParams()
  const [caseData, setCaseData] = useState(null)
  const [card, setCard] = useState(null)
  const [cardLoading, setCardLoading] = useState(false)
  const isPremium = useAuthStore(s => s.isPremium)

  useEffect(() => {
    casesAPI.get(id).then(r => {
      setCaseData(r.data?.data)
    }).catch(() => { void 0 })
  }, [id])

  const loadProtectionCard = async () => {
    setCardLoading(true)
    try {
      const res = await casesAPI.protectionCard(id)
      setCard(res.data?.data)
    } catch {
      void 0
    } finally {
      setCardLoading(false)
    }
  }

  if (!caseData) return (
    <div style={{ minHeight: '100vh', background: theme.bg, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <p style={{ color: theme.textMuted }}>Yükleniyor...</p>
    </div>
  )

  const c = caseData

  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      {/* Back */}
      <div style={{ maxWidth: 900, margin: '0 auto', padding: '20px 24px 0' }}>
        <Link to="/atlas" style={{ color: theme.primary, fontSize: 14, textDecoration: 'none' }}>
          ← Atlas'a Dön
        </Link>
      </div>

      {/* Hero */}
      <motion.section
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        style={{
          maxWidth: 900, margin: '0 auto', padding: '30px 24px',
          background: theme.gradientSurface,
          border: `1px solid ${theme.border}`,
          borderRadius: theme.radius.lg,
          marginTop: 12,
        }}
      >
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
          {/* Left */}
          <div style={{ flex: '1 1 500px' }}>
            <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
              <AttackTypeBadge type={c.attack_method} label={c.attack_method_tr} size="md" />
              {c.region && (
                <span style={{
                  padding: '6px 14px', fontSize: 13, color: theme.primary,
                  background: theme.primaryDim, border: `1px solid ${theme.primarySoft}`,
                  borderRadius: theme.radius.sm,
                }}>📍 {c.region}</span>
              )}
            </div>

            <h1 style={{ fontSize: 26, fontWeight: 700, color: theme.text, margin: '0 0 16px', lineHeight: 1.3 }}>
              {c.case_title}
            </h1>

            <p style={{ fontSize: 15, color: theme.textMuted, lineHeight: 1.7, margin: 0 }}>
              {c.narrative_summary}
            </p>
          </div>

          {/* Right — Scores */}
          <div style={{ display: 'flex', gap: 20, alignItems: 'flex-start' }}>
            <RiskBadge score={c.severity_score} type="severity" size="md" />
            <RiskBadge score={c.confidence_score} type="confidence" size="md" />
          </div>
        </div>

        {/* Critical Warning */}
        {c.critical_warning && (
          <div style={{
            marginTop: 20, padding: '14px 18px',
            background: `${theme.danger}12`,
            border: `1px solid ${theme.danger}30`,
            borderRadius: theme.radius.sm,
            display: 'flex', gap: 10, alignItems: 'flex-start',
          }}>
            <span style={{ fontSize: 18 }}>⚠️</span>
            <div>
              <strong style={{ color: theme.danger, fontSize: 13, textTransform: 'uppercase' }}>Kritik Uyarı</strong>
              <p style={{ color: theme.text, fontSize: 14, margin: '4px 0 0', lineHeight: 1.5 }}>
                {c.critical_warning}
              </p>
            </div>
          </div>
        )}
      </motion.section>

      <ProtectionPlan steps={c.defense_steps_json || []} />

      {/* Protection Card (Premium) */}
      <section style={{
        maxWidth: 900, margin: '20px auto 0', padding: '24px',
        background: theme.gradientSurface,
        border: `1px solid ${theme.border}`,
        borderRadius: theme.radius.lg,
      }}>
        <h2 style={{ fontSize: 18, fontWeight: 600, color: theme.primary, margin: '0 0 16px' }}>
          🤖 Gemini Korunma Kartı
        </h2>

        {isPremium() ? (
          <>
            {!card && !cardLoading && (
              <button
                onClick={loadProtectionCard}
                style={{
                  padding: '10px 24px', background: theme.gradientPrimary,
                  color: theme.bgDeep, fontWeight: 700, border: 'none',
                  borderRadius: theme.radius.sm, cursor: 'pointer', fontSize: 14,
                }}
              >
                Korunma Kartı Üret
              </button>
            )}
            {cardLoading && <GeminiLoader text="Gemini korunma kartı üretiyor..." />}
            {card?.card_text && (
              <div style={{
                whiteSpace: 'pre-wrap', color: theme.text, fontSize: 14,
                lineHeight: 1.7, background: `${theme.primary}08`,
                padding: 20, borderRadius: theme.radius.sm,
                border: `1px solid ${theme.primarySoft}`,
              }}>
                {card.card_text}
              </div>
            )}
          </>
        ) : (
          <PremiumGate />
        )}
      </section>

      {/* Meta */}
      <section style={{
        maxWidth: 900, margin: '20px auto 40px', padding: '16px 24px',
        display: 'flex', gap: 24, flexWrap: 'wrap',
        color: theme.textSubtle, fontSize: 12,
      }}>
        {c.first_seen && <span>İlk görülme: {new Date(c.first_seen).toLocaleDateString('tr-TR')}</span>}
        {c.last_seen && <span>Son görülme: {new Date(c.last_seen).toLocaleDateString('tr-TR')}</span>}
        {c.loss_type && <span>Kayıp türü: {c.loss_type_tr || c.loss_type}</span>}
        {c.target_platform && <span>Platform: {c.target_platform_tr || c.target_platform}</span>}
      </section>
    </div>
  )
}
