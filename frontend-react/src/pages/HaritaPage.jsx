import { useEffect, useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { theme } from '../theme'
import { statsAPI } from '../lib/endpoints'

// Türkiye il bazlı GeoJSON (sadece id ve isim)
const TURKEY_GEO = {
  type: 'FeatureCollection',
  features: [
    { type: 'Feature', id: '01', properties: { name: 'Adana' }, geometry: null },
    { type: 'Feature', id: '02', properties: { name: 'Adıyaman' }, geometry: null },
    { type: 'Feature', id: '03', properties: { name: 'Afyonkarahisar' }, geometry: null },
    { type: 'Feature', id: '04', properties: { name: 'Ağrı' }, geometry: null },
    { type: 'Feature', id: '05', properties: { name: 'Amasya' }, geometry: null },
    { type: 'Feature', id: '06', properties: { name: 'Ankara' }, geometry: null },
    { type: 'Feature', id: '07', properties: { name: 'Antalya' }, geometry: null },
    { type: 'Feature', id: '08', properties: { name: 'Artvin' }, geometry: null },
    { type: 'Feature', id: '09', properties: { name: 'Aydın' }, geometry: null },
    { type: 'Feature', id: '10', properties: { name: 'Balıkesir' }, geometry: null },
    { type: 'Feature', id: '11', properties: { name: 'Bilecik' }, geometry: null },
    { type: 'Feature', id: '12', properties: { name: 'Bingöl' }, geometry: null },
    { type: 'Feature', id: '13', properties: { name: 'Bitlis' }, geometry: null },
    { type: 'Feature', id: '14', properties: { name: 'Bolu' }, geometry: null },
    { type: 'Feature', id: '15', properties: { name: 'Burdur' }, geometry: null },
    { type: 'Feature', id: '16', properties: { name: 'Bursa' }, geometry: null },
    { type: 'Feature', id: '17', properties: { name: 'Çanakkale' }, geometry: null },
    { type: 'Feature', id: '18', properties: { name: 'Çankırı' }, geometry: null },
    { type: 'Feature', id: '19', properties: { name: 'Çorum' }, geometry: null },
    { type: 'Feature', id: '20', properties: { name: 'Denizli' }, geometry: null },
    { type: 'Feature', id: '21', properties: { name: 'Diyarbakır' }, geometry: null },
    { type: 'Feature', id: '22', properties: { name: 'Edirne' }, geometry: null },
    { type: 'Feature', id: '23', properties: { name: 'Elazığ' }, geometry: null },
    { type: 'Feature', id: '24', properties: { name: 'Erzincan' }, geometry: null },
    { type: 'Feature', id: '25', properties: { name: 'Erzurum' }, geometry: null },
    { type: 'Feature', id: '26', properties: { name: 'Eskişehir' }, geometry: null },
    { type: 'Feature', id: '27', properties: { name: 'Gaziantep' }, geometry: null },
    { type: 'Feature', id: '28', properties: { name: 'Giresun' }, geometry: null },
    { type: 'Feature', id: '29', properties: { name: 'Gümüşhane' }, geometry: null },
    { type: 'Feature', id: '30', properties: { name: 'Hakkari' }, geometry: null },
    { type: 'Feature', id: '31', properties: { name: 'Hatay' }, geometry: null },
    { type: 'Feature', id: '32', properties: { name: 'Isparta' }, geometry: null },
    { type: 'Feature', id: '33', properties: { name: 'Mersin' }, geometry: null },
    { type: 'Feature', id: '34', properties: { name: 'İstanbul' }, geometry: null },
    { type: 'Feature', id: '35', properties: { name: 'İzmir' }, geometry: null },
    { type: 'Feature', id: '36', properties: { name: 'Kars' }, geometry: null },
    { type: 'Feature', id: '37', properties: { name: 'Kastamonu' }, geometry: null },
    { type: 'Feature', id: '38', properties: { name: 'Kayseri' }, geometry: null },
    { type: 'Feature', id: '39', properties: { name: 'Kırklareli' }, geometry: null },
    { type: 'Feature', id: '40', properties: { name: 'Kırşehir' }, geometry: null },
    { type: 'Feature', id: '41', properties: { name: 'Kocaeli' }, geometry: null },
    { type: 'Feature', id: '42', properties: { name: 'Konya' }, geometry: null },
    { type: 'Feature', id: '43', properties: { name: 'Kütahya' }, geometry: null },
    { type: 'Feature', id: '44', properties: { name: 'Malatya' }, geometry: null },
    { type: 'Feature', id: '45', properties: { name: 'Manisa' }, geometry: null },
    { type: 'Feature', id: '46', properties: { name: 'Kahramanmaraş' }, geometry: null },
    { type: 'Feature', id: '47', properties: { name: 'Mardin' }, geometry: null },
    { type: 'Feature', id: '48', properties: { name: 'Muğla' }, geometry: null },
    { type: 'Feature', id: '49', properties: { name: 'Muş' }, geometry: null },
    { type: 'Feature', id: '50', properties: { name: 'Nevşehir' }, geometry: null },
    { type: 'Feature', id: '51', properties: { name: 'Niğde' }, geometry: null },
    { type: 'Feature', id: '52', properties: { name: 'Ordu' }, geometry: null },
    { type: 'Feature', id: '53', properties: { name: 'Rize' }, geometry: null },
    { type: 'Feature', id: '54', properties: { name: 'Sakarya' }, geometry: null },
    { type: 'Feature', id: '55', properties: { name: 'Samsun' }, geometry: null },
    { type: 'Feature', id: '56', properties: { name: 'Siirt' }, geometry: null },
    { type: 'Feature', id: '57', properties: { name: 'Sinop' }, geometry: null },
    { type: 'Feature', id: '58', properties: { name: 'Sivas' }, geometry: null },
    { type: 'Feature', id: '59', properties: { name: 'Tekirdağ' }, geometry: null },
    { type: 'Feature', id: '60', properties: { name: 'Tokat' }, geometry: null },
    { type: 'Feature', id: '61', properties: { name: 'Trabzon' }, geometry: null },
    { type: 'Feature', id: '62', properties: { name: 'Tunceli' }, geometry: null },
    { type: 'Feature', id: '63', properties: { name: 'Şanlıurfa' }, geometry: null },
    { type: 'Feature', id: '64', properties: { name: 'Uşak' }, geometry: null },
    { type: 'Feature', id: '65', properties: { name: 'Van' }, geometry: null },
    { type: 'Feature', id: '66', properties: { name: 'Yozgat' }, geometry: null },
    { type: 'Feature', id: '67', properties: { name: 'Zonguldak' }, geometry: null },
    { type: 'Feature', id: '68', properties: { name: 'Aksaray' }, geometry: null },
    { type: 'Feature', id: '69', properties: { name: 'Bayburt' }, geometry: null },
    { type: 'Feature', id: '70', properties: { name: 'Karaman' }, geometry: null },
    { type: 'Feature', id: '71', properties: { name: 'Kırıkkale' }, geometry: null },
    { type: 'Feature', id: '72', properties: { name: 'Batman' }, geometry: null },
    { type: 'Feature', id: '73', properties: { name: 'Şırnak' }, geometry: null },
    { type: 'Feature', id: '74', properties: { name: 'Bartın' }, geometry: null },
    { type: 'Feature', id: '75', properties: { name: 'Ardahan' }, geometry: null },
    { type: 'Feature', id: '76', properties: { name: 'Iğdır' }, geometry: null },
    { type: 'Feature', id: '77', properties: { name: 'Yalova' }, geometry: null },
    { type: 'Feature', id: '78', properties: { name: 'Karabük' }, geometry: null },
    { type: 'Feature', id: '79', properties: { name: 'Kilis' }, geometry: null },
    { type: 'Feature', id: '80', properties: { name: 'Osmaniye' }, geometry: null },
    { type: 'Feature', id: '81', properties: { name: 'Düzce' }, geometry: null },
  ],
}

export default function HaritaPage() {
  const [features, setFeatures] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [hoveredProv, setHoveredProv] = useState(null)

  useEffect(() => {
    let cancelled = false

    statsAPI.heatmap()
      .then((r) => {
        if (!cancelled) {
          setFeatures(r.data?.features || [])
          setError('')
        }
      })
      .catch((err) => {
        if (!cancelled) {
          setFeatures([])
          setError(err?.response?.data?.detail || err?.response?.data?.message || 'Harita verisi alınamadı.')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  const regionMap = useMemo(() => {
    const map = {}
    features.forEach((f) => {
      const name = f.properties?.name
      if (name) map[name.toLowerCase()] = f.properties?.case_count || 0
    })
    return map
  }, [features])

  const regionEntries = useMemo(
    () => Object.entries(regionMap).map(([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count),
    [regionMap],
  )

  const maxCount = Math.max(...Object.values(regionMap), 1)
  const totalCount = regionEntries.reduce((sum, item) => sum + item.count, 0)
  const activeRegionCount = regionEntries.filter((item) => item.count > 0).length
  const topRegion = regionEntries[0] || null

  const getColor = (count) => {
    if (count === 0) return '#2a2a35'
    const intensity = count / maxCount
    if (intensity > 0.7) return '#ef4444'
    if (intensity > 0.4) return '#f59e0b'
    return '#22c55e'
  }

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

      <section style={{ maxWidth: 1000, margin: '0 auto', padding: '30px 24px' }}>
        {loading ? (
          <p style={{ color: theme.textMuted, textAlign: 'center' }}>Yükleniyor...</p>
        ) : (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 18 }}>
              {[
                { label: 'Toplam Vaka', value: totalCount, color: theme.primary },
                { label: 'Verisi Olan İl', value: activeRegionCount, color: theme.success },
                { label: 'En Yoğun İl', value: topRegion ? topRegion.name.replace(/^./, (ch) => ch.toUpperCase()) : '-', color: theme.warning },
              ].map((item) => (
                <div key={item.label} style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.md, padding: '14px 16px' }}>
                  <div style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 6 }}>{item.label}</div>
                  <div style={{ fontSize: 22, fontWeight: 800, color: item.color, wordBreak: 'break-word' }}>{item.value}</div>
                </div>
              ))}
            </div>

            <div style={{
              background: theme.surface,
              border: `1px solid ${theme.border}`,
              borderRadius: theme.radius.lg,
              padding: 20,
              marginBottom: 24,
              position: 'relative',
            }}>
              {/* Hover info */}
              {hoveredProv && (
                <div style={{
                  position: 'absolute', top: 20, right: 20,
                  background: theme.bg, border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.md, padding: '12px 16px',
                  zIndex: 10,
                }}>
                  <h3 style={{ color: theme.text, fontSize: 14, fontWeight: 600, margin: '0 0 4px' }}>
                    {hoveredProv}
                  </h3>
                  <p style={{ color: theme.textMuted, fontSize: 12, margin: 0 }}>
                    Vaka: {regionMap[hoveredProv.toLowerCase()] || 0}
                  </p>
                </div>
              )}

              {error && (
                <div style={{
                  marginBottom: 16,
                  padding: '12px 14px',
                  borderRadius: theme.radius.md,
                  border: `1px solid ${theme.warning}44`,
                  background: `${theme.warning}10`,
                  color: theme.text,
                  fontSize: 13,
                  lineHeight: 1.6,
                }}>
                  <strong style={{ color: theme.warning }}>Not:</strong> {error} Harita yine de sıfır verili görünümde açıldı.
                </div>
              )}

              {/* Simple grid map - placeholder for react-simple-maps */}
              <div style={{
                display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))',
                gap: 8,
              }}>
                {TURKEY_GEO.features.map((prov) => {
                  const name = prov.properties.name
                  const count = regionMap[name.toLowerCase()] || 0
                  const color = getColor(count)

                  return (
                    <motion.div
                      key={prov.id}
                      initial={{ opacity: 0, scale: 0.9 }}
                      animate={{ opacity: 1, scale: 1 }}
                      transition={{ delay: parseInt(prov.id) * 0.01, duration: 0.3 }}
                      onMouseEnter={() => setHoveredProv(name)}
                      onMouseLeave={() => setHoveredProv(null)}
                      style={{
                        background: color,
                        borderRadius: theme.radius.sm,
                        padding: 12,
                        cursor: 'pointer',
                        transition: 'transform 0.15s ease, box-shadow 0.15s ease',
                        border: hoveredProv === name ? `2px solid ${theme.primary}` : '2px solid transparent',
                      }}
                      whileHover={{ scale: 1.05, boxShadow: '0 4px 12px rgba(0,0,0,0.3)' }}
                    >
                      <h4 style={{ color: '#fff', fontSize: 12, fontWeight: 600, margin: '0 0 4px' }}>
                        {name}
                      </h4>
                      <span style={{ color: '#fff', fontSize: 16, fontWeight: 800 }}>
                        {count}
                      </span>
                    </motion.div>
                  )
                })}
              </div>
            </div>

            {/* Legend */}
            <div style={{
              display: 'flex', justifyContent: 'center', gap: 18, flexWrap: 'wrap',
              background: theme.surface, border: `1px solid ${theme.border}`,
              borderRadius: theme.radius.md, padding: 16,
            }}>
              {[
                { label: 'Düşük', color: '#22c55e' },
                { label: 'Orta', color: '#f59e0b' },
                { label: 'Yüksek', color: '#ef4444' },
                { label: 'Veri yok', color: '#2a2a35' },
              ].map((l, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 16, height: 16, borderRadius: 4, background: l.color }} />
                  <span style={{ color: theme.text, fontSize: 12 }}>{l.label}</span>
                </div>
              ))}
            </div>

            {regionEntries.length > 0 && (
              <div style={{ marginTop: 22, background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.md, padding: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
                  <h3 style={{ margin: 0, color: theme.text, fontSize: 14, fontWeight: 700 }}>İlk 10 İl</h3>
                  <span style={{ color: theme.textMuted, fontSize: 12 }}>Toplam {regionEntries.length} il verisi</span>
                </div>
                <div style={{ display: 'grid', gap: 8 }}>
                  {regionEntries.slice(0, 10).map((item, index) => {
                    const intensity = item.count / maxCount
                    const barColor = item.count === 0 ? '#2a2a35' : intensity > 0.7 ? '#ef4444' : intensity > 0.4 ? '#f59e0b' : '#22c55e'
                    return (
                      <div key={item.name} style={{ display: 'grid', gridTemplateColumns: '32px 1fr 56px', gap: 10, alignItems: 'center' }}>
                        <span style={{ color: theme.textMuted, fontSize: 12, textAlign: 'right' }}>{index + 1}</span>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ color: theme.text, fontSize: 13, fontWeight: 600 }}>{item.name.replace(/^./, (ch) => ch.toUpperCase())}</span>
                            <span style={{ color: barColor, fontSize: 12, fontWeight: 700 }}>{item.count}</span>
                          </div>
                          <div style={{ height: 6, borderRadius: 999, background: theme.bgDeep, overflow: 'hidden' }}>
                            <div style={{ width: `${Math.max((item.count / maxCount) * 100, item.count > 0 ? 8 : 0)}%`, height: '100%', background: barColor, borderRadius: 999 }} />
                          </div>
                        </div>
                        <span style={{ color: theme.textMuted, fontSize: 11, textAlign: 'right' }}>vaka</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  )
}
