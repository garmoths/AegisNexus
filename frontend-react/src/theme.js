export const theme = {
  bg: '#080c14',
  bgDeep: '#05080f',
  surface: '#0f1629',
  surface2: '#1a2342',
  surface3: '#0c1322',
  border: '#1e2a4a',
  borderSoft: '#162038',
  primary: '#00d4ff',
  primaryDim: 'rgba(0,212,255,0.1)',
  primarySoft: 'rgba(0,212,255,0.18)',
  accent: '#ff6b35',
  accentSoft: 'rgba(255,107,53,0.18)',
  violet: '#9f7aea',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',
  text: '#e2e8f0',
  textMuted: '#64748b',
  textSubtle: '#475569',

  gradientHero: 'radial-gradient(ellipse at 50% 0%, rgba(0,212,255,0.18) 0%, transparent 60%), radial-gradient(ellipse at 50% 100%, rgba(159,122,234,0.12) 0%, transparent 65%)',
  gradientPrimary: 'linear-gradient(135deg, #00d4ff, #0099cc)',
  gradientAccent: 'linear-gradient(135deg, #ff6b35, #c9472b)',
  gradientSurface: 'linear-gradient(145deg, #0f1629 0%, #1a2342 100%)',
  gradientGlow: 'linear-gradient(90deg, transparent, rgba(0,212,255,0.4), transparent)',
  gridPattern: `
    linear-gradient(rgba(0,212,255,0.04) 1px, transparent 1px),
    linear-gradient(90deg, rgba(0,212,255,0.04) 1px, transparent 1px)
  `,
  gridPatternSize: '48px 48px',

  shadow: {
    card: '0 10px 30px rgba(0,0,0,0.35)',
    glow: '0 0 40px rgba(0,212,255,0.18)',
    glowStrong: '0 0 60px rgba(0,212,255,0.35)',
  },

  ease: {
    out: 'cubic-bezier(0.16, 1, 0.3, 1)',
    spring: 'cubic-bezier(0.175, 0.885, 0.32, 1.275)',
  },

  radius: {
    sm: '8px',
    md: '12px',
    lg: '18px',
    xl: '24px',
  },
}
