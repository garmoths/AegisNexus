import { theme } from '../theme'

export default function ProtectionPlan({ steps = [] }) {
  if (!steps.length) return null

  return (
    <section style={{
      maxWidth: 900, margin: '20px auto 0', padding: '24px',
      background: theme.gradientSurface,
      border: `1px solid ${theme.border}`,
      borderRadius: theme.radius.lg,
    }}>
      <h2 style={{ fontSize: 18, fontWeight: 600, color: theme.primary, margin: '0 0 16px' }}>
        🛡️ Korunma Adımları
      </h2>
      <ol style={{ margin: 0, paddingLeft: 24 }}>
        {steps.map((step, i) => (
          <li key={i} style={{ color: theme.text, fontSize: 14, lineHeight: 1.7, marginBottom: 8 }}>
            {step}
          </li>
        ))}
      </ol>
    </section>
  )
}
