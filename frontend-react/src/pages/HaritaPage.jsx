import TurkeyHeatmapSection from '../components/TurkeyHeatmapSection.jsx'
import { theme } from '../theme'

export default function HaritaPage() {
  return (
    <div style={{ minHeight: '100vh', background: theme.bg }}>
      <section style={{
        background: theme.gradientHero,
        padding: '60px 24px 30px',
        textAlign: 'center',
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 800, color: theme.text, margin: '0 0 8px' }}>
          🗺️ Tehdit Haritası
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 15, margin: 0 }}>
          Türkiye il bazlı siber dolandırıcılık vaka yoğunluğu
        </p>
      </section>

      <TurkeyHeatmapSection compact={false} />
    </div>
  )
}
