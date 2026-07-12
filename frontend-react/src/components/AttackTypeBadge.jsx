import { theme } from '../theme'

const ATTACK_COLORS = {
  phishing: theme.accent,
  smishing: '#ff6b35',
  vishing: '#f59e0b',
  sahte_mobil_uygulama: '#ef4444',
  banka_taklit: '#ef4444',
  social_engineering: '#9f7aea',
  malware_assisted: '#6366f1',
  other: theme.textMuted,
}

const ATTACK_LABELS = {
  phishing: 'Oltalama',
  smishing: 'SMS Oltalaması',
  vishing: 'Telefon Dolandırıcılığı',
  sahte_mobil_uygulama: 'Sahte Mobil Uygulama',
  banka_taklit: 'Banka Taklidi',
  social_engineering: 'Sosyal Mühendislik',
  malware_assisted: 'Zararlı Yazılım',
  other: 'Diğer',
}

export default function AttackTypeBadge({ type, label, size = 'sm' }) {
  const color = ATTACK_COLORS[type] || ATTACK_COLORS.other
  const text = label || ATTACK_LABELS[type] || type

  const sizes = {
    sm: { padding: '4px 10px', fontSize: '11px' },
    md: { padding: '6px 14px', fontSize: '13px' },
    lg: { padding: '8px 18px', fontSize: '15px' },
  }

  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '6px',
      padding: sizes[size].padding,
      fontSize: sizes[size].fontSize,
      fontWeight: 600,
      color,
      background: `${color}18`,
      border: `1px solid ${color}40`,
      borderRadius: theme.radius.sm,
      letterSpacing: '0.5px',
      textTransform: 'uppercase',
    }}>
      <span style={{
        width: 6, height: 6, borderRadius: '50%',
        background: color,
        boxShadow: `0 0 6px ${color}`,
      }} />
      {text}
    </span>
  )
}
