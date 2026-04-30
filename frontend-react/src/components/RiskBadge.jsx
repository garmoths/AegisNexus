import { theme } from '../theme'

const LEVELS = [
  { min: 0, max: 30, label: 'Düşük', color: theme.success, bg: 'rgba(34,197,94,0.12)' },
  { min: 31, max: 60, label: 'Orta', color: theme.warning, bg: 'rgba(245,158,11,0.12)' },
  { min: 61, max: 80, label: 'Yüksek', color: theme.accent, bg: 'rgba(255,107,53,0.12)' },
  { min: 81, max: 100, label: 'Kritik', color: theme.danger, bg: 'rgba(239,68,68,0.12)' },
]

function getLevel(score) {
  return LEVELS.find(l => score >= l.min && score <= l.max) || LEVELS[0]
}

export default function RiskBadge({ score, type = 'severity', size = 'sm' }) {
  const level = getLevel(score)
  const isSeverity = type === 'severity'

  const sizes = {
    sm: { width: 48, height: 48, fontSize: 14, labelSize: 10 },
    md: { width: 60, height: 60, fontSize: 18, labelSize: 12 },
    lg: { width: 76, height: 76, fontSize: 24, labelSize: 14 },
  }
  const s = sizes[size]

  return (
    <div style={{
      display: 'inline-flex',
      flexDirection: 'column',
      alignItems: 'center',
      gap: '4px',
    }}>
      <div style={{
        width: s.width,
        height: s.height,
        borderRadius: '50%',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: level.bg,
        border: `2px solid ${level.color}`,
        boxShadow: `0 0 20px ${level.color}30`,
        fontSize: s.fontSize,
        fontWeight: 700,
        color: level.color,
        fontFamily: 'monospace',
      }}>
        {score}
      </div>
      <span style={{
        fontSize: s.labelSize,
        color: level.color,
        fontWeight: 600,
        textTransform: 'uppercase',
        letterSpacing: '0.5px',
      }}>
        {isSeverity ? 'Şiddet' : 'Güven'} · {level.label}
      </span>
    </div>
  )
}
