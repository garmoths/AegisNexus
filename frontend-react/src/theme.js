// AegisNexus tasarım token'ları — tek kaynak.
// Renkler 6 haneli hex olmalı: kodda `theme.primary + '33'` gibi alfa eklemeleri var.
// `accent` = tehlike rengi (kırmızı); marka vurgusu `primary` (sinyal camgöbeği).
export const theme = {
  bg: '#07090d',
  bgDeep: '#05070a',
  surface: '#0b0e14',
  surface2: '#10141c',
  surface3: '#0d1118',
  border: '#1c2230',
  borderSoft: '#151a24',
  borderLight: '#1c223099',

  primary: '#5ce1e6',
  primaryDim: 'rgba(92,225,230,0.07)',
  primarySoft: 'rgba(92,225,230,0.14)',
  accent: '#ef4444',
  accentDim: 'rgba(239,68,68,0.10)',
  accentSoft: 'rgba(239,68,68,0.18)',
  violet: '#8b96a8',
  success: '#22c55e',
  warning: '#f59e0b',
  danger: '#ef4444',

  text: '#e8edf5',
  textMuted: '#8b96a8',
  textSubtle: '#5b6577',
  textDim: '#5b6577',
  textSecondary: '#c4ccd8',

  font: "'Geist', 'Inter', sans-serif",
  display: "'Space Grotesk', 'Geist', sans-serif",
  mono: "'Geist Mono', 'JetBrains Mono', monospace",
  navFont: "'Geist', 'Inter', sans-serif",

  radius: { sm: '8px', md: '12px', lg: '16px', xl: '22px' },
  radiusSm: '8px',
  radiusMd: '12px',
  radiusLg: '16px',
  radiusXl: '22px',

  glow: '0 0 0 1px rgba(92,225,230,0.25), 0 0 24px -6px rgba(92,225,230,0.45)',
  cardShadow: '0 0 0 1px rgba(255,255,255,0.02), 0 16px 40px -24px rgba(0,0,0,0.9)',
  cardShadowHover: '0 0 0 1px rgba(92,225,230,0.18), 0 20px 48px -24px rgba(0,0,0,0.9)',

  gradientHero: 'none',
  gradientPrimary: '#5ce1e6',
  gradientAccent: '#ef4444',
  gradientSurface: '#0b0e14',
  gradientGlow: 'transparent',
  gridPattern: 'none',
  gridPatternSize: '48px 48px',

  shadow: {
    card: '0 0 0 1px rgba(255,255,255,0.02), 0 16px 40px -24px rgba(0,0,0,0.9)',
    glow: '0 0 24px -6px rgba(92,225,230,0.45)',
    glowStrong: '0 0 40px -8px rgba(92,225,230,0.6)',
  },

  ease: {
    out: 'cubic-bezier(0.16, 1, 0.3, 1)',
    spring: 'cubic-bezier(0.34, 1.56, 0.64, 1)',
  },
}
