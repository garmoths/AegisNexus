import { theme } from '../theme'
import useAuthStore from '../stores/authStore'

export default function PremiumGate({ children, fallback }) {
  const isPremium = useAuthStore(s => s.isPremium)

  if (isPremium()) return children

  if (fallback) return fallback

  return (
    <div style={{
      background: theme.gradientSurface,
      border: `1px solid ${theme.border}`,
      borderRadius: theme.radius.lg,
      padding: '32px',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: 40, marginBottom: 12 }}>🔒</div>
      <h3 style={{ color: theme.text, fontSize: 18, fontWeight: 600, margin: '0 0 8px' }}>
        Premium Özellik
      </h3>
      <p style={{ color: theme.textMuted, fontSize: 14, margin: '0 0 20px' }}>
        Bu özellik Premium ve üzeri planlarda kullanılabilir.
      </p>
      <a href="/subscription" style={{
        display: 'inline-block',
        padding: '10px 24px',
        background: theme.gradientPrimary,
        color: theme.bgDeep,
        fontWeight: 700,
        borderRadius: theme.radius.sm,
        textDecoration: 'none',
        fontSize: 14,
      }}>
        Plan Yükselt
      </a>
    </div>
  )
}
