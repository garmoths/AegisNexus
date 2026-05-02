import { cloneElement, useEffect, useMemo, useState } from 'react'
import TurkeyMap from 'turkey-map-react'
import { theme } from '../theme'
import { statsAPI } from '../lib/endpoints'

const TURKEY_PROVINCES = [
  { id: '01', name: 'Adana' }, { id: '02', name: 'Adıyaman' }, { id: '03', name: 'Afyonkarahisar' },
  { id: '04', name: 'Ağrı' }, { id: '05', name: 'Amasya' }, { id: '06', name: 'Ankara' },
  { id: '07', name: 'Antalya' }, { id: '08', name: 'Artvin' }, { id: '09', name: 'Aydın' },
  { id: '10', name: 'Balıkesir' }, { id: '11', name: 'Bilecik' }, { id: '12', name: 'Bingöl' },
  { id: '13', name: 'Bitlis' }, { id: '14', name: 'Bolu' }, { id: '15', name: 'Burdur' },
  { id: '16', name: 'Bursa' }, { id: '17', name: 'Çanakkale' }, { id: '18', name: 'Çankırı' },
  { id: '19', name: 'Çorum' }, { id: '20', name: 'Denizli' }, { id: '21', name: 'Diyarbakır' },
  { id: '22', name: 'Edirne' }, { id: '23', name: 'Elazığ' }, { id: '24', name: 'Erzincan' },
  { id: '25', name: 'Erzurum' }, { id: '26', name: 'Eskişehir' }, { id: '27', name: 'Gaziantep' },
  { id: '28', name: 'Giresun' }, { id: '29', name: 'Gümüşhane' }, { id: '30', name: 'Hakkari' },
  { id: '31', name: 'Hatay' }, { id: '32', name: 'Isparta' }, { id: '33', name: 'Mersin' },
  { id: '34', name: 'İstanbul' }, { id: '35', name: 'İzmir' }, { id: '36', name: 'Kars' },
  { id: '37', name: 'Kastamonu' }, { id: '38', name: 'Kayseri' }, { id: '39', name: 'Kırklareli' },
  { id: '40', name: 'Kırşehir' }, { id: '41', name: 'Kocaeli' }, { id: '42', name: 'Konya' },
  { id: '43', name: 'Kütahya' }, { id: '44', name: 'Malatya' }, { id: '45', name: 'Manisa' },
  { id: '46', name: 'Kahramanmaraş' }, { id: '47', name: 'Mardin' }, { id: '48', name: 'Muğla' },
  { id: '49', name: 'Muş' }, { id: '50', name: 'Nevşehir' }, { id: '51', name: 'Niğde' },
  { id: '52', name: 'Ordu' }, { id: '53', name: 'Rize' }, { id: '54', name: 'Sakarya' },
  { id: '55', name: 'Samsun' }, { id: '56', name: 'Siirt' }, { id: '57', name: 'Sinop' },
  { id: '58', name: 'Sivas' }, { id: '59', name: 'Tekirdağ' }, { id: '60', name: 'Tokat' },
  { id: '61', name: 'Trabzon' }, { id: '62', name: 'Tunceli' }, { id: '63', name: 'Şanlıurfa' },
  { id: '64', name: 'Uşak' }, { id: '65', name: 'Van' }, { id: '66', name: 'Yozgat' },
  { id: '67', name: 'Zonguldak' }, { id: '68', name: 'Aksaray' }, { id: '69', name: 'Bayburt' },
  { id: '70', name: 'Karaman' }, { id: '71', name: 'Kırıkkale' }, { id: '72', name: 'Batman' },
  { id: '73', name: 'Şırnak' }, { id: '74', name: 'Bartın' }, { id: '75', name: 'Ardahan' },
  { id: '76', name: 'Iğdır' }, { id: '77', name: 'Yalova' }, { id: '78', name: 'Karabük' },
  { id: '79', name: 'Kilis' }, { id: '80', name: 'Osmaniye' }, { id: '81', name: 'Düzce' },
]

const normalizeProvinceKey = (value = '') => value
  .toLocaleLowerCase('tr-TR')
  .normalize('NFD')
  .replace(/[\u0300-\u036f]/g, '')
  .replace(/ı/g, 'i')

const getProvinceColor = (count, maxCount) => {
  if (count === 0) return '#262633'
  const intensity = count / maxCount
  if (intensity > 0.7) return '#ef4444'
  if (intensity > 0.4) return '#f59e0b'
  return '#22c55e'
}

function ProvinceShape({ cityComponent, city, count, hoveredProvince, onHoverProvince, onLeaveProvince, maxCount }) {
  const pathElement = cityComponent?.props?.children
  const provinceFill = hoveredProvince === city.name
    ? (count === 0 ? '#394150' : '#f59e0b')
    : getProvinceColor(count, maxCount)

  const childPath = Array.isArray(pathElement) ? pathElement[0] : pathElement

  return cloneElement(cityComponent, {
    onMouseEnter: () => onHoverProvince(city.name),
    onMouseLeave: () => onLeaveProvince(),
    children: childPath
      ? cloneElement(childPath, {
          style: {
            ...(childPath.props?.style || {}),
            cursor: 'pointer',
            fill: provinceFill,
            stroke: hoveredProvince === city.name ? '#ffffff' : '#101018',
            strokeWidth: hoveredProvince === city.name ? 2 : 1,
            transition: 'fill 120ms ease, stroke 120ms ease',
          },
        })
      : childPath,
  })
}

export default function TurkeyHeatmapSection({ compact = false }) {
  const [features, setFeatures] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [hoveredProvince, setHoveredProvince] = useState(null)

  useEffect(() => {
    let cancelled = false

    statsAPI.heatmap()
      .then((response) => {
        if (cancelled) return
        setFeatures(response.data?.features || [])
        setError('')
      })
      .catch((err) => {
        if (cancelled) return
        setFeatures([])
        setError(err?.response?.data?.detail || err?.response?.data?.message || 'Harita verisi alınamadı.')
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
    features.forEach((feature) => {
      const name = feature.properties?.name
      if (name) map[normalizeProvinceKey(name)] = feature.properties?.case_count || 0
    })
    return map
  }, [features])

  const regionEntries = useMemo(
    () => TURKEY_PROVINCES.map((province) => ({ ...province, count: regionMap[normalizeProvinceKey(province.name)] || 0 })).sort((a, b) => b.count - a.count),
    [regionMap],
  )

  const maxCount = Math.max(...regionEntries.map((item) => item.count), 1)
  const totalCount = regionEntries.reduce((sum, item) => sum + item.count, 0)
  const activeRegionCount = regionEntries.filter((item) => item.count > 0).length
  const topRegion = regionEntries[0] || null
  const hoveredCount = hoveredProvince ? (regionMap[normalizeProvinceKey(hoveredProvince)] || 0) : null

  const renderCityWrapper = (cityComponent, city) => (
    <ProvinceShape
      cityComponent={cityComponent}
      city={city}
      count={regionMap[normalizeProvinceKey(city.name)] || 0}
      hoveredProvince={hoveredProvince}
      onHoverProvince={setHoveredProvince}
      onLeaveProvince={() => setHoveredProvince(null)}
      maxCount={maxCount}
    />
  )

  return (
    <section style={{ maxWidth: compact ? '100%' : 1200, margin: '0 auto', padding: compact ? '0' : '30px 24px' }}>
      {loading ? (
        <p style={{ color: theme.textMuted, textAlign: 'center', padding: '18px 0' }}>Yükleniyor...</p>
      ) : (
        <div style={{ display: 'grid', gap: 18 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12 }}>
            {[
              { label: 'Toplam Vaka', value: totalCount, color: theme.primary },
              { label: 'Verisi Olan İl', value: activeRegionCount, color: theme.success },
              { label: 'En Yoğun İl', value: topRegion ? topRegion.name : '-', color: theme.warning },
            ].map((item) => (
              <div key={item.label} style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.md, padding: '14px 16px' }}>
                <div style={{ fontSize: 11, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 6 }}>{item.label}</div>
                <div style={{ fontSize: 22, fontWeight: 800, color: item.color, wordBreak: 'break-word' }}>{item.value}</div>
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: compact ? '1fr' : 'minmax(320px, 1.2fr) minmax(280px, 0.8fr)', gap: 18, alignItems: 'stretch' }}>
            <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.lg, padding: 18, position: 'relative', overflow: 'hidden' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
                <div>
                  <h2 style={{ color: theme.text, margin: 0, fontSize: 18, fontWeight: 800 }}>Türkiye Haritası</h2>
                  <p style={{ color: theme.textMuted, margin: '6px 0 0', fontSize: 13 }}>İl bazlı vaka yoğunluğu, gerçek Türkiye silueti üzerinde gösterilir.</p>
                </div>
                <div style={{ background: `${theme.primary}14`, color: theme.primary, border: `1px solid ${theme.primary}33`, borderRadius: 999, padding: '8px 12px', fontSize: 12, fontWeight: 700 }}>
                  {totalCount > 0 ? 'Canlı yoğunluk' : 'Veri yok'}
                </div>
              </div>

              {error && (
                <div style={{ marginBottom: 14, padding: '12px 14px', borderRadius: theme.radius.md, border: `1px solid ${theme.warning}44`, background: `${theme.warning}10`, color: theme.text, fontSize: 13, lineHeight: 1.6 }}>
                  <strong style={{ color: theme.warning }}>Not:</strong> {error}
                </div>
              )}

              <div style={{ position: 'relative', borderRadius: theme.radius.lg, overflow: 'hidden', background: 'radial-gradient(circle at 50% 45%, rgba(245,158,11,0.12), transparent 60%), linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.08))' }}>
                <TurkeyMap
                  showTooltip={false}
                  hoverable={false}
                  customStyle={{ idleColor: '#262633', hoverColor: '#f59e0b' }}
                  cityWrapper={renderCityWrapper}
                />

                <div style={{ position: 'absolute', left: 16, bottom: 16, background: 'rgba(8,8,14,0.78)', backdropFilter: 'blur(10px)', border: `1px solid ${theme.border}`, borderRadius: theme.radius.md, padding: '12px 14px', minWidth: 210 }}>
                  <div style={{ color: theme.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 6 }}>Harita özeti</div>
                  <div style={{ color: theme.text, fontSize: 18, fontWeight: 800 }}>{hoveredProvince || 'Türkiye'}</div>
                  <div style={{ color: theme.textMuted, fontSize: 12, marginTop: 4 }}>
                    {hoveredProvince ? `Vaka: ${hoveredCount}` : `Toplam ${totalCount} vaka, ${activeRegionCount} ilde veri`}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginTop: 16 }}>
                {[
                  { label: 'Düşük', color: '#22c55e' },
                  { label: 'Orta', color: '#f59e0b' },
                  { label: 'Yüksek', color: '#ef4444' },
                  { label: 'Veri yok', color: '#262633' },
                ].map((item) => (
                  <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 14, height: 14, borderRadius: 4, background: item.color, border: item.label === 'Veri yok' ? `1px solid ${theme.border}` : 'none' }} />
                    <span style={{ color: theme.text, fontSize: 12 }}>{item.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div style={{ display: 'grid', gap: 18 }}>
              <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.lg, padding: 18 }}>
                <h3 style={{ margin: '0 0 12px', color: theme.text, fontSize: 15, fontWeight: 800 }}>İlk 10 İl</h3>
                <div style={{ display: 'grid', gap: 10 }}>
                  {regionEntries.slice(0, 10).map((item, index) => {
                    const intensity = item.count / maxCount
                    const barColor = item.count === 0 ? '#262633' : intensity > 0.7 ? '#ef4444' : intensity > 0.4 ? '#f59e0b' : '#22c55e'
                    return (
                      <div key={item.id} style={{ display: 'grid', gridTemplateColumns: '28px 1fr 52px', gap: 10, alignItems: 'center' }}>
                        <span style={{ color: theme.textMuted, fontSize: 12, textAlign: 'right' }}>{index + 1}</span>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                            <span style={{ color: theme.text, fontSize: 13, fontWeight: 600 }}>{item.name}</span>
                            <span style={{ color: barColor, fontSize: 12, fontWeight: 800 }}>{item.count}</span>
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

              <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.lg, padding: 18 }}>
                <h3 style={{ margin: '0 0 12px', color: theme.text, fontSize: 15, fontWeight: 800 }}>Neden burada?</h3>
                <p style={{ margin: 0, color: theme.textMuted, lineHeight: 1.7, fontSize: 13 }}>
                  Bu harita Mağduriyet Atlası içinde görünür; roadmap’in istediği kullanım da bu. Aşağıdaki vaka kartlarıyla birlikte,
                  yoğunluk dağılımını tek sayfada vererek operasyon ekibine ve dış sunuma hazır bir görünüm sağlar.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}