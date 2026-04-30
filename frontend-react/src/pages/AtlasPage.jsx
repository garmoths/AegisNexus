import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { theme } from '../theme'
import { casesAPI } from '../lib/endpoints'
import CaseCard from '../components/CaseCard'
import AttackTypeBadge from '../components/AttackTypeBadge'

const ATTACK_METHODS = ['phishing', 'smishing', 'vishing', 'sahte_mobil_uygulama', 'banka_taklit', 'social_engineering', 'malware_assisted']

export default function AtlasPage() {
  const nav = useNavigate()
  const [cases, setCases] = useState([])
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)

  // Filters
  const [attackMethod, setAttackMethod] = useState('')
  const [severityMin, setSeverityMin] = useState(0)
  const [search, setSearch] = useState('')

  const fetchCases = useCallback(async () => {
    setLoading(true)
    try {
      const params = {
        page,
        limit: 20,
        severity_min: severityMin,
        hot_set_only: false,
      }
      if (attackMethod) params.attack_method = attackMethod
      if (search) params.q = search

      const res = await casesAPI.list(params)
      setCases(res.data?.data || [])
      setTotal(res.data?.total || 0)
    } catch {}
    setLoading(false)
  }, [page, attackMethod, severityMin, search])

  useEffect(() => { fetchCases() }, [fetchCases])

  const totalPages = Math.max(1, Math.ceil(total / 20))

  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      {/* Header */}
      <section style={{
        background: theme.gradientHero,
        padding: '60px 24px 30px',
        textAlign: 'center',
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: theme.text, margin: '0 0 8px' }}>
          🗺️ Vaka Atlası
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 15, margin: 0 }}>
          {total} vaka kayıtlı
        </p>
      </section>

      {/* Filters */}
      <section style={{
        maxWidth: 1200, margin: '0 auto', padding: '20px 24px',
        display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center',
      }}>
        {/* Search */}
        <input
          type="text"
          placeholder="Vaka ara..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(1) }}
          style={{
            flex: '1 1 240px', padding: '10px 16px',
            background: theme.surface, border: `1px solid ${theme.border}`,
            borderRadius: theme.radius.sm, color: theme.text, fontSize: 14,
            outline: 'none',
          }}
        />

        {/* Attack method */}
        <select
          value={attackMethod}
          onChange={e => { setAttackMethod(e.target.value); setPage(1) }}
          style={{
            padding: '10px 14px', background: theme.surface,
            border: `1px solid ${theme.border}`, borderRadius: theme.radius.sm,
            color: theme.text, fontSize: 14,
          }}
        >
          <option value="">Tüm Saldırılar</option>
          {ATTACK_METHODS.map(m => (
            <option key={m} value={m}>{m.replace(/_/g, ' ')}</option>
          ))}
        </select>

        {/* Severity */}
        <select
          value={severityMin}
          onChange={e => { setSeverityMin(Number(e.target.value)); setPage(1) }}
          style={{
            padding: '10px 14px', background: theme.surface,
            border: `1px solid ${theme.border}`, borderRadius: theme.radius.sm,
            color: theme.text, fontSize: 14,
          }}
        >
          <option value={0}>Tüm Şiddet</option>
          <option value={30}>Orta+ (30+)</option>
          <option value={60}>Yüksek+ (60+)</option>
          <option value={80}>Kritik (80+)</option>
        </select>
      </section>

      {/* Grid */}
      <section style={{
        maxWidth: 1200, margin: '0 auto', padding: '0 24px 40px',
        display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
        gap: 20,
      }}>
        <AnimatePresence>
          {loading ? (
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              style={{ gridColumn: '1/-1', textAlign: 'center', padding: 60, color: theme.textMuted }}
            >
              Yükleniyor...
            </motion.div>
          ) : cases.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }} animate={{ opacity: 1 }}
              style={{ gridColumn: '1/-1', textAlign: 'center', padding: 60, color: theme.textMuted }}
            >
              Vaka bulunamadı.
            </motion.div>
          ) : (
            cases.map((c, i) => (
              <motion.div
                key={c.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05, duration: 0.4 }}
              >
                <CaseCard case={c} onClick={() => nav(`/atlas/${c.id}`)} />
              </motion.div>
            ))
          )}
        </AnimatePresence>
      </section>

      {/* Pagination */}
      {totalPages > 1 && (
        <div style={{
          maxWidth: 1200, margin: '0 auto', padding: '0 24px 40px',
          display: 'flex', justifyContent: 'center', gap: 8,
        }}>
          <button
            disabled={page <= 1}
            onClick={() => setPage(p => Math.max(1, p - 1))}
            style={{
              padding: '8px 18px', background: theme.surface,
              border: `1px solid ${theme.border}`, borderRadius: theme.radius.sm,
              color: theme.text, cursor: page <= 1 ? 'not-allowed' : 'pointer',
              opacity: page <= 1 ? 0.4 : 1,
            }}
          >← Önceki</button>
          <span style={{ padding: '8px 14px', color: theme.textMuted, fontSize: 14 }}>
            {page} / {totalPages}
          </span>
          <button
            disabled={page >= totalPages}
            onClick={() => setPage(p => p + 1)}
            style={{
              padding: '8px 18px', background: theme.surface,
              border: `1px solid ${theme.border}`, borderRadius: theme.radius.sm,
              color: theme.text, cursor: page >= totalPages ? 'not-allowed' : 'pointer',
              opacity: page >= totalPages ? 0.4 : 1,
            }}
          >Sonraki →</button>
        </div>
      )}
    </div>
  )
}
