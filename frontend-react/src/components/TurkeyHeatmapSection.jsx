import { useEffect, useMemo, useState } from 'react'
import { theme } from '../theme'
import { statsAPI } from '../lib/endpoints'
import { simplemapsTurkeyAdmin1MapInfo } from '../assets/maps/simplemaps_tr_admin1_mapinfo.js'

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

const ATTACK_METHOD_COLORS = {
  phishing: '#ef4444',
  smishing: '#f59e0b',
  vishing: '#8b5cf6',
  social_engineering: '#06b6d4',
  malware_assisted: '#ec4899',
  sahte_mobil_uygulama: '#10b981',
  banka_taklit: '#f97316',
}

const normalizeProvinceKey = (value = '') => value
  .toLocaleLowerCase('tr-TR')
  .normalize('NFD')
  .replace(/[\u0300-\u036f]/g, '')
  .replace(/ı/g, 'i')

const getProvinceColor = (attackMethod) => {
  return ATTACK_METHOD_COLORS[attackMethod] || '#262633'
}

const mapPaths = simplemapsTurkeyAdmin1MapInfo.paths || {}
const mapBBoxes = simplemapsTurkeyAdmin1MapInfo.state_bbox_array || {}

export default function TurkeyHeatmapSection({ compact = false }) {
  const [heatmapFeatures, setHeatmapFeatures] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [hoveredProvince, setHoveredProvince] = useState(null)

  useEffect(() => {
    let cancelled = false
    statsAPI.heatmap()
      .then((response) => {
        if (cancelled) return
        setHeatmapFeatures(response.data?.features || [])
        setError('')
      })
      .catch((err) => {
        if (cancelled) return
        setHeatmapFeatures([])
        setError(err?.response?.data?.detail || err?.response?.data?.message || 'Harita verisi alınamadı.')
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [])

  // heatmap features'dan bölge verisi: { count, attackMethod }
  const regionDataMap = useMemo(() => {
    const map = {}
    heatmapFeatures.forEach((feature) => {
      const region = feature?.properties?.name
      const count = Number(feature?.properties?.case_count || 0)
      const attackMethod = feature?.properties?.attack_method || null
      if (region && count > 0) {
        map[normalizeProvinceKey(region)] = { count, attackMethod }
      }
    })
    return map
  }, [heatmapFeatures])

  const regionEntries = useMemo(
    () => TURKEY_PROVINCES.map((province) => {
      const key = normalizeProvinceKey(province.name)
      const data = regionDataMap[key]
      return { ...province, attackMethod: data?.attackMethod ?? null, count: data?.count ?? 0 }
    }).sort((a, b) => b.count - a.count),
    [regionDataMap],
  )

  const totalCount = regionEntries.reduce((s, r) => s + r.count, 0)
  const activeRegionCount = regionEntries.filter((item) => item.count > 0).length
  const topRegion = regionEntries[0] || null
  const hoveredKey = hoveredProvince ? normalizeProvinceKey(hoveredProvince) : ''
  const hoveredData = hoveredKey ? regionDataMap[hoveredKey] : null
  const hoveredCount = hoveredData?.count ?? 0
  const hoveredMethod = hoveredData?.attackMethod ?? null

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

          <div style={{ display: 'grid', gridTemplateColumns: compact ? '1fr' : 'minmax(520px, 1.45fr) minmax(260px, 0.55fr)', gap: 18, alignItems: 'start' }}>
            <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.lg, padding: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
                <div>
                  <h2 style={{ color: theme.text, margin: 0, fontSize: 18, fontWeight: 800 }}>İller Bazlı Vaka Dağılımı</h2>
                  <p style={{ color: theme.textMuted, margin: '6px 0 0', fontSize: 13 }}>İller dolandırıcılık yöntemlerine göre renklendirilir.</p>
                </div>
                <div style={{ background: `${theme.primary}14`, color: theme.primary, border: `1px solid ${theme.primary}33`, borderRadius: 999, padding: '8px 12px', fontSize: 12, fontWeight: 700 }}>
                  {totalCount > 0 ? 'Canlı veri' : 'Veri yok'}
                </div>
              </div>

              {error && (
                <div style={{ marginBottom: 14, padding: '12px 14px', borderRadius: theme.radius.md, border: `1px solid ${theme.warning}44`, background: `${theme.warning}10`, color: theme.text, fontSize: 13, lineHeight: 1.6 }}>
                  <strong style={{ color: theme.warning }}>Not:</strong> {error}
                </div>
              )}

              <div style={{ position: 'relative', borderRadius: theme.radius.lg, overflow: 'hidden', background: 'radial-gradient(circle at 50% 42%, rgba(0,212,255,0.16), transparent 58%), linear-gradient(135deg, rgba(15,23,42,0.92), rgba(8,12,20,0.99))', border: `1px solid ${theme.border}`, padding: '10px 14px 4px', minHeight: 260 }}>
                <svg viewBox="0 0 1000 422" role="img" aria-label="Türkiye il bazlı vaka haritası" style={{ width: '100%', height: '260px', display: 'block', filter: 'drop-shadow(0 22px 28px rgba(0,0,0,0.28))' }} preserveAspectRatio="xMidYMid meet">
                  <defs>
                    <filter id="provinceGlow" x="-30%" y="-30%" width="160%" height="160%">
                      <feGaussianBlur stdDeviation="3" result="blur" />
                      <feMerge>
                        <feMergeNode in="blur" />
                        <feMergeNode in="SourceGraphic" />
                      </feMerge>
                    </filter>
                    <linearGradient id="mapFrame" x1="0" x2="1" y1="0" y2="1">
                      <stop offset="0%" stopColor="rgba(255,255,255,0.08)" />
                      <stop offset="100%" stopColor="rgba(255,255,255,0.01)" />
                    </linearGradient>
                  </defs>
                  <rect x="0" y="0" width="1000" height="422" rx="28" fill="url(#mapFrame)" opacity="0.18" />
                  {TURKEY_PROVINCES.map((province) => {
                    const path = mapPaths[`TR${province.id}`]
                    const bbox = mapBBoxes[`TR${province.id}`]
                    const data = regionDataMap[normalizeProvinceKey(province.name)]
                    const isHovered = hoveredProvince === province.name
                    const fill = data?.attackMethod ? getProvinceColor(data.attackMethod) : '#20283b'
                    if (!path) return null
                    return (
                      <g
                        key={province.name}
                        onMouseEnter={() => setHoveredProvince(province.name)}
                        onMouseLeave={() => setHoveredProvince(null)}
                        style={{ cursor: 'pointer' }}
                        filter={isHovered ? 'url(#provinceGlow)' : undefined}
                      >
                        <path
                          d={path}
                          fill={fill}
                          fillOpacity={data ? (isHovered ? 0.98 : 0.82) : 0.42}
                          stroke={isHovered ? '#ffffff' : 'rgba(255,255,255,0.2)'}
                          strokeWidth={isHovered ? 2 : 0.9}
                          style={{ transition: 'fill-opacity 120ms ease, stroke 120ms ease' }}
                        />
                        {bbox && data && data.count > 0 && (
                          <circle
                            cx={bbox.cx}
                            cy={bbox.cy}
                            r={Math.min(16, 5 + data.count * 0.55)}
                            fill="#ffffff"
                            fillOpacity={isHovered ? 0.92 : 0.68}
                            stroke={fill}
                            strokeWidth="2"
                          />
                        )}
                      </g>
                    )
                  })}
                </svg>

                <div style={{ position: 'absolute', right: 16, top: 16, background: 'rgba(8,12,20,0.78)', backdropFilter: 'blur(14px)', border: `1px solid ${theme.border}`, borderRadius: theme.radius.md, padding: '12px 14px', minWidth: 210, boxShadow: '0 18px 40px rgba(0,0,0,0.35)' }}>
                  <div style={{ color: theme.textMuted, fontSize: 11, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 6 }}>{hoveredProvince || 'Türkiye'}</div>
                  <div style={{ color: theme.text, fontSize: 18, fontWeight: 800 }}>{hoveredProvince ? `${hoveredCount} vaka` : `${totalCount} toplam vaka`}</div>
                  <div style={{ color: theme.textMuted, fontSize: 12, marginTop: 4 }}>
                    {hoveredProvince ? (hoveredMethod ? hoveredMethod.replace(/_/g, ' ') : 'Yöntem verisi sınırlı') : `${activeRegionCount} ilde canlı dağılım`}
                  </div>
                </div>
              </div>

              {hoveredProvince && hoveredCount > 0 && (
                <div style={{ marginTop: 12, padding: '12px 14px', borderRadius: theme.radius.md, background: theme.primaryDim, border: `1px solid ${theme.primary}33` }}>
                  <div style={{ color: theme.text, fontSize: 14, fontWeight: 800 }}>{hoveredProvince}</div>
                  <div style={{ color: theme.textMuted, fontSize: 12, marginTop: 4 }}>
                    {hoveredCount} vaka · {hoveredMethod || 'Belirsiz yöntem'}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px 12px', marginTop: 14, padding: '10px 12px', borderRadius: theme.radius.md, background: 'rgba(8,12,20,0.42)', border: `1px solid ${theme.border}` }}>
                {Object.entries(ATTACK_METHOD_COLORS).map(([key, color]) => (
                  <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{ width: 10, height: 10, borderRadius: 999, background: color, boxShadow: `0 0 12px ${color}88` }} />
                    <span style={{ color: theme.text, fontSize: 11 }}>{key.replace(/_/g, ' ')}</span>
                  </div>
                ))}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <div style={{ width: 10, height: 10, borderRadius: 999, background: '#262633', border: `1px solid ${theme.border}` }} />
                  <span style={{ color: theme.text, fontSize: 11 }}>Veri yok</span>
                </div>
              </div>
            </div>

            <div style={{ display: 'grid', gap: 18 }}>
              <div style={{ background: theme.surface, border: `1px solid ${theme.border}`, borderRadius: theme.radius.lg, padding: 18 }}>
                <h3 style={{ margin: '0 0 12px', color: theme.text, fontSize: 15, fontWeight: 800 }}>İlk 10 İl</h3>
                <div style={{ display: 'grid', gap: 10 }}>
                  {regionEntries.slice(0, 10).map((item, index) => {
                    const barColor = item.attackMethod ? ATTACK_METHOD_COLORS[item.attackMethod] : '#262633'
                    return (
                      <div key={item.id} style={{ display: 'grid', gridTemplateColumns: '28px 1fr 52px', gap: 10, alignItems: 'center' }}>
                        <span style={{ color: theme.textMuted, fontSize: 12, textAlign: 'right' }}>{index + 1}</span>
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 4 }}>
                            <span style={{ color: theme.text, fontSize: 13, fontWeight: 600 }}>{item.name}</span>
                            <span style={{ color: barColor, fontSize: 12, fontWeight: 800 }}>{item.count}</span>
                          </div>
                          <div style={{ height: 6, borderRadius: 999, background: theme.bgDeep, overflow: 'hidden' }}>
                            <div style={{ width: `${Math.max((item.count / totalCount) * 100, item.count > 0 ? 8 : 0)}%`, height: '100%', background: barColor, borderRadius: 999 }} />
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
                  Bu harita SimpleMaps Türkiye Admin-1 il sınırlarını kullanır; iller dolandırıcılık yöntemlerine göre canlı renklendirilir.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}
    </section>
  )
}