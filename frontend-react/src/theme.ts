// AegisNexus tasarım token'ları — tek kaynak.
// Renkler 6 haneli hex olmalı: kodda `theme.primary + '33'` gibi alfa eklemeleri var.
// `accent` = tehlike rengi (kırmızı); marka vurgusu `primary` (turuncu).
export const theme = {
  bg: '#0d0b0a',
  bgDeep: '#090807',
  surface: '#151210',
  surface2: '#1c1916',
  surface3: '#171412',
  border: '#2b2622',
  borderSoft: '#211d1a',
  borderLight: '#2b262299',

  primary: '#f26a2e',
  primaryDim: 'rgba(242,106,46,0.07)',
  primarySoft: 'rgba(242,106,46,0.14)',
  accent: '#ef4444',
  accentDim: 'rgba(239,68,68,0.10)',
  accentSoft: 'rgba(239,68,68,0.18)',
  violet: '#a39a8f',
  success: '#22c55e',
  warning: '#eab308',
  danger: '#ef4444',

  text: '#f2ede6',
  textMuted: '#a39a8f',
  textSubtle: '#756d63',
  textDim: '#756d63',
  textSecondary: '#cfc7bc',

  font: "'Geist', 'Inter', sans-serif",
  display: "'Space Grotesk', 'Geist', sans-serif",
  mono: "'Geist Mono', 'JetBrains Mono', monospace",
  navFont: "'Geist', 'Inter', sans-serif",

  radius: { sm: '8px', md: '12px', lg: '16px', xl: '22px' },
  radiusSm: '8px',
  radiusMd: '12px',
  radiusLg: '16px',
  radiusXl: '22px',

  glow: '0 0 0 1px rgba(242,106,46,0.25), 0 0 24px -6px rgba(242,106,46,0.45)',
  cardShadow: '0 0 0 1px rgba(255,255,255,0.02), 0 16px 40px -24px rgba(0,0,0,0.9)',
  cardShadowHover: '0 0 0 1px rgba(242,106,46,0.18), 0 20px 48px -24px rgba(0,0,0,0.9)',

  gradientHero: 'none',
  gradientPrimary: '#f26a2e',
  gradientAccent: '#ef4444',
  gradientSurface: '#151210',
  gradientGlow: 'transparent',
  gridPattern: 'none',
  gridPatternSize: '48px 48px',

  shadow: {
    card: '0 0 0 1px rgba(255,255,255,0.02), 0 16px 40px -24px rgba(0,0,0,0.9)',
    glow: '0 0 24px -6px rgba(242,106,46,0.45)',
    glowStrong: '0 0 40px -8px rgba(242,106,46,0.6)',
  },

  // framer-motion kübik bezier kontrol noktaları ister, CSS metni değil.
  ease: {
    out: [0.16, 1, 0.3, 1] as [number, number, number, number],
    spring: [0.34, 1.56, 0.64, 1] as [number, number, number, number],
  },
}
