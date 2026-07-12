import { motion } from 'framer-motion'
import { theme } from '../theme'
import { MapPin } from 'lucide-react'
import AttackTypeBadge from './AttackTypeBadge'
import RiskBadge from './RiskBadge'

export default function CaseCard({ case: c, onClick }) {
  return (
    <motion.div
      whileHover={{ y: -4, boxShadow: theme.shadow.glow }}
      transition={{ duration: 0.25, ease: theme.ease.out }}
      onClick={() => onClick?.(c)}
      style={{
        background: theme.gradientSurface,
        border: `1px solid ${theme.border}`,
        borderRadius: theme.radius.md,
        padding: '20px',
        cursor: 'pointer',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      {/* Glow line */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${theme.primary}, transparent)`,
      }} />

      {/* Header */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
        marginBottom: 12,
      }}>
        <h3 style={{
          fontSize: 15, fontWeight: 600, color: theme.text,
          margin: 0, lineHeight: 1.4,
          display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
          flex: 1, marginRight: 12,
        }}>
          {c.case_title}
        </h3>
        <RiskBadge score={c.severity_score} size="sm" />
      </div>

      {/* Tags */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
        <AttackTypeBadge type={c.attack_method} label={c.attack_method_tr} />
        {c.region && (
          <span style={{
            padding: '4px 10px', fontSize: 11, fontWeight: 500,
            color: theme.primary, background: theme.primaryDim,
            border: `1px solid ${theme.primarySoft}`,
            borderRadius: theme.radius.sm,
          }}>
            <MapPin size={10} style={{marginRight:3}}/>{c.region}
          </span>
        )}
      </div>

      {/* Summary */}
      <p style={{
        fontSize: 13, color: theme.textMuted, margin: 0,
        lineHeight: 1.5,
        display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical',
        overflow: 'hidden',
      }}>
        {c.narrative_summary}
      </p>

      {/* Footer */}
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginTop: 16, paddingTop: 12,
        borderTop: `1px solid ${theme.borderSoft}`,
      }}>
        <span style={{ fontSize: 11, color: theme.textSubtle }}>
          {c.last_seen ? new Date(c.last_seen).toLocaleDateString('tr-TR') : ''}
        </span>
        <span style={{
          fontSize: 11, fontWeight: 600, color: theme.primary,
          letterSpacing: '0.5px',
        }}>
          DETAY →
        </span>
      </div>
    </motion.div>
  )
}
