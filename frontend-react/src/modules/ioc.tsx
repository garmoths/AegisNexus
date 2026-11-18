import { apiFetch as fetch } from '../lib/api'
import { useState, useEffect, useRef, type ComponentType } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, ShieldAlert, AlertTriangle, Activity, Globe, Search, Copy, Check, Database, Zap, Bug, Mail, Server, Hash, Radio, Eye, BarChart3, Lock, Download } from 'lucide-react'
import { theme, API, Toast, CountUp, Card } from './shared'
import { emitEvent } from '../stores/eventBus'
import type { ModuleScreenProps } from '../ModulesApp'

/** IOC rows come from several endpoints (honeypot cache, DB search, risk bands) with slightly different keys. */
interface IOCItem {
  id?: number
  value?: string
  ioc_value?: string
  ioc?: string
  indicator?: string
  type?: string
  ioc_type?: string
  threat_type?: string
  risk_score?: number
  confidence?: number
  source?: string
  detection_count?: number | null
  first_seen?: string | null
  last_seen?: string | null
  created_at?: string | null
  date?: string | null
}
interface CountRow { type?: string; threat_type?: string; name?: string; source?: string; range?: string; count?: number; percentage?: number }
interface IOCStatsView {
  stats?: IOCStatsView
  total_iocs?: number
  total_records?: number
  high_risk_count?: number
  medium_risk_count?: number
  risk_distribution?: CountRow[]
  top_threats?: CountRow[]
  source_breakdown?: CountRow[]
}
type ThreatMeta = { color: string; icon: ComponentType<{ size?: number; color?: string; strokeWidth?: number }> }
type ToastState = { message: string; type: 'success' | 'error'; visible: boolean }

const THREAT_META: Record<string, ThreatMeta> = {
  BOTNET:              { color:'#ef4444', icon: Bug },
  MALWARE:             { color:'#ef4444', icon: AlertTriangle },
  PAYLOAD_DELIVERY:    { color:'#f59e0b', icon: Zap },
  PHISHING:            { color:'#eab308', icon: Mail },
  'BOTNET.CC':         { color:'#ec4899', icon: Radio },
  SPAM:                { color:'#8b5cf6', icon: Mail },
  'SPAM SOURCE':       { color:'#a855f7', icon: Server },
  'CREDENTIAL HARVESTING': { color:'#06b6d4', icon: Lock },
}

function ThreatIcon({ type, size=14 }: { type?: string; size?: number }) {
  const meta = THREAT_META[(type || '').toUpperCase()] || { color: theme.primary, icon: Shield }
  const Icon = meta.icon
  return <Icon size={size} color={meta.color} strokeWidth={2} />
}

function CopyBtn({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  function handleCopy() {
    navigator.clipboard?.writeText(value).catch(()=>{})
    setCopied(true); setTimeout(()=>setCopied(false), 1800)
  }
  return (
    <button onClick={e=>{e.stopPropagation();handleCopy()}}
      title="Kopyala"
      style={{ background:'none', border:'none', cursor:'pointer', padding:4, color: copied ? theme.success : theme.textMuted, flexShrink:0, lineHeight:0 }}>
      {copied ? <Check size={12} color={theme.success}/> : <Copy size={12}/>}
    </button>
  )
}

function HoneypotIOC({ initialIocQuery = '', onClearPrefill }: ModuleScreenProps & { onClearPrefill?: () => void }) {
  const [iocStats, setIocStats] = useState<IOCStatsView | null>(null)
  const [iocList, setIocList] = useState<IOCItem[]>([])
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<IOCItem[]>([])
  const [searching, setSearching] = useState(false)
  const [toast, setToast] = useState<ToastState>({ message:'', type:'success', visible:false })
  const [showDropdown, setShowDropdown] = useState(false)
  const [exportingSTIX, setExportingSTIX] = useState(false)
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const iocPrefillRef = useRef('')

  useEffect(() => {
    if (initialIocQuery && initialIocQuery !== iocPrefillRef.current) {
      iocPrefillRef.current = initialIocQuery
      setSearchQuery(initialIocQuery)
      onClearPrefill?.()
      setTimeout(() => {
        fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(initialIocQuery)}`)
          .then(r => r.json())
          .then(d => { setSearchResults(d.results||d.data||d.iocs||[]); setShowDropdown(true) })
          .catch(() => {})
      }, 200)
    }
  }, [initialIocQuery, onClearPrefill])

  async function exportSTIX(minRisk = 0) {
    setExportingSTIX(true)
    try {
      const url = `${API}/ioc/export/stix?min_risk_score=${minRisk}&limit=1000`
      const res = await fetch(url)
      if (!res.ok) throw new Error('Export başarısız')
      const blob = await res.blob()
      const downloadUrl = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = downloadUrl
      a.download = `aegisnexus-ioc-stix-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(downloadUrl)
      showToast('STIX 2.1 dosyası indirildi')
    } catch (e) {
      showToast('STIX export hatası: ' + (e instanceof Error ? e.message : String(e)), 'error')
    }
    setExportingSTIX(false)
  }

  async function handleSearch(){if(!searchQuery)return;setSearching(true);try{const r=await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`);const d=await r.json();if(d.status==='success'||d.results){const list=d.results||d.data||d.iocs||[];setSearchResults(list);setShowDropdown(true);emitEvent({module:'ioc',type:'ioc.search',severity:list.length?'medium':'info',title:list.length?`${list.length} IOC eşleşti: ${searchQuery}`:`IOC bulunamadı: ${searchQuery}`,detail:'Tuzak / IOC veritabanı arandı.',payload:{query:searchQuery,count:list.length}})}else{showToast('Arama sonucu bulunamadi veya hata: '+d.message,'error')}}catch(e){showToast('Arama hatasi: '+(e instanceof Error?e.message:String(e)),'error')};setSearching(false)}
  function showToast(msg: string,t: ToastState['type']='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(v=>({...v,visible:false})),3000)}
  
  // Real-time autocomplete with debouncing
  useEffect(() => {
    if (searchQuery.length < 2) return
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    
    searchTimeoutRef.current = setTimeout(async () => {
      setSearching(true)
      try {
        const r = await fetch(`${API}/honeypot/ioc/search?q=${encodeURIComponent(searchQuery)}`)
        const d = await r.json()
        if (d.status === 'success' || d.results) {
          setSearchResults(d.results || d.data || d.iocs || [])
          setShowDropdown(true)
        } else {
          setSearchResults([])
          setShowDropdown(false)
        }
      } catch {
        setSearchResults([])
        setShowDropdown(false)
      }
      setSearching(false)
    }, 500)
    
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [searchQuery])
  
  useEffect(() => {
    let cancelled = false

    void (async () => {
      try {
        const statsResponse = await fetch(`${API}/honeypot/ioc/stats`)
        const statsData = await statsResponse.json()
        if (!cancelled) setIocStats(statsData)
      } catch {
        if (!cancelled) setIocStats(null)
      }

      try {
        const levels = ['critical', 'high', 'medium', 'low']
        const allIocs: IOCItem[] = []
        for (const level of levels) {
          try {
            const response = await fetch(`${API}/honeypot/ioc/by-risk-score?level=${level}&limit=8`)
            const data = await response.json()
            if (data.iocs) allIocs.push(...data.iocs)
          } catch {
            continue
          }
        }
        if (!cancelled) setIocList(allIocs)
      } catch {
        if (cancelled) return
        try {
          const response = await fetch(`${API}/honeypot/ioc/list?limit=25`)
          const data = await response.json()
          setIocList(data.data || data.iocs || [])
        } catch {
          setIocList([])
        }
      }
    })()

    return () => {
      cancelled = true
    }
  }, [])

  const statsData: IOCStatsView=iocStats?.stats||iocStats||{}
  const riskDist=statsData?.risk_distribution||iocStats?.risk_distribution||[]
  const topThreats=statsData?.top_threats||iocStats?.top_threats||[]
  const sourceBreakdown=statsData?.source_breakdown||iocStats?.source_breakdown||[]
  const totalIocs=statsData?.total_iocs||iocStats?.total_iocs||iocStats?.total_records||0
  const highRisk=statsData?.high_risk_count||iocStats?.high_risk_count||0
  const mediumRisk=statsData?.medium_risk_count||iocStats?.medium_risk_count||0

  const maxThreat = Math.max(...(topThreats.map(t=>t.count||0)), 1)
  const highRiskPct = totalIocs>0 ? ((highRisk/totalIocs)*100).toFixed(1) : '0'

  return <div style={{ animation:'fadeInUp 0.5s ease' }}>
    <Toast {...toast}/>

    {/* ── Hero ── */}
    <div style={{ textAlign:'center', padding:'8px 0 24px' }}>

      {/* Stat sayaçları */}
      <div style={{ display:'flex', justifyContent:'center', gap:40, flexWrap:'wrap', marginBottom:40 }}>
        {[
          { label:'Toplam IOC', value:totalIocs, color:theme.primary, Icon:Database },
          { label:'Yüksek Risk', value:highRisk, color:'#ef4444', Icon:AlertTriangle },
          { label:'Orta Risk', value:mediumRisk, color:theme.warning, Icon:Activity },
          { label:'Kaynak', value:sourceBreakdown.length, color:theme.success, Icon:Globe },
        ].map(s=>(
          <div key={s.label} style={{ textAlign:'center' }}>
            <div style={{ display:'flex', justifyContent:'center', marginBottom:6 }}><s.Icon size={18} color={s.color}/></div>
            <p style={{ fontSize:28, fontWeight:600, color:s.color, margin:'0 0 2px' }}><CountUp end={s.value}/></p>
            <p style={{ fontSize:11, color:theme.textMuted, margin:0 }}>{s.label}</p>
          </div>
        ))}
      </div>

      {/* Arama */}
      <div style={{ maxWidth:680, margin:'0 auto', position:'relative' }}>
        <div style={{ display:'flex', gap:10, background:theme.surface, padding:8, borderRadius:theme.radiusLg, border:`1px solid ${theme.border}` }}>
          <div style={{ display:'flex', alignItems:'center', paddingLeft:12, color:theme.textMuted }}><Search size={16}/></div>
          <input value={searchQuery} onChange={e=>{const value=e.target.value;setSearchQuery(value);if(value.length<2)setShowDropdown(false)}} onKeyDown={e=>e.key==='Enter'&&handleSearch()}
            placeholder="IP adresi, domain, URL veya hash girin..."
            style={{ flex:1, padding:'14px 8px', background:'transparent', border:'none', color:'#fff', fontSize:15, outline:'none', fontFamily:theme.font }}/>
          <button onClick={handleSearch} disabled={searching}
            style={{ padding:'14px 28px', borderRadius:theme.radiusMd, background:searching?'#333':theme.gradientPrimary, color:searching?'#666':'#000', border:'none', cursor:searching?'not-allowed':'pointer', fontWeight:600, fontSize:14, display:'flex', alignItems:'center', gap:8 }}>
            {searching ? <><span style={{ width:14,height:14,border:'2px solid #666',borderTopColor:'transparent',borderRadius:'50%',display:'inline-block',animation:'spin 0.8s linear infinite'}}/> Aranıyor</> : <><Search size={14}/> Sorgula</>}
          </button>
        </div>
        <AnimatePresence>
          {showDropdown && searchResults.length>0 && (
            <motion.div initial={{opacity:0,y:-8}} animate={{opacity:1,y:0}} exit={{opacity:0,y:-8}}
              style={{ position:'absolute', top:'calc(100% + 8px)', left:0, right:0, background:theme.surface, border:`1px solid ${theme.border}`, borderRadius:theme.radiusMd, maxHeight:280, overflowY:'auto', zIndex:100, boxShadow:'0 1px 2px rgba(0,0,0,0.3)' }}>
              {searchResults.slice(0,10).map((item,i)=>(
                <div key={i} onClick={()=>{setSearchQuery(item.value||item.ioc_value||item.ioc||'');setShowDropdown(false);handleSearch()}}
                  style={{ padding:'12px 16px', borderBottom:`1px solid ${theme.border}`, cursor:'pointer', transition:'background 0.15s' }}
                  onMouseEnter={e=>e.currentTarget.style.background=theme.surface2}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:8 }}>
                    <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:12, wordBreak:'break-all', flex:1 }}>{item.value||item.ioc_value||item.ioc||'-'}</span>
                    <span style={{ fontSize:10, padding:'2px 8px', borderRadius:10, background:`${THREAT_META[(item.ioc_type||'').toUpperCase()]?.color||theme.primary}20`, color:THREAT_META[(item.ioc_type||'').toUpperCase()]?.color||theme.primary, whiteSpace:'nowrap' }}>{item.ioc_type||item.type||'-'}</span>
                  </div>
                  <div style={{ display:'flex', gap:12, fontSize:11, color:theme.textMuted, marginTop:4 }}>
                    <span style={{ display:'flex', alignItems:'center', gap:4 }}><Shield size={10}/> Risk: <b style={{ color:(item.risk_score||0)>75?'#ef4444':(item.risk_score||0)>40?theme.warning:theme.success }}>{item.risk_score}</b></span>
                    <span style={{ display:'flex', alignItems:'center', gap:4 }}><Database size={10}/> {item.source}</span>
                  </div>
                </div>
              ))}
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* STIX Export Button */}
      <div style={{ display:'flex', justifyContent:'center', gap:12, marginTop:20 }}>
        <button onClick={()=>exportSTIX(0)} disabled={exportingSTIX}
          style={{ padding:'10px 20px', borderRadius:theme.radiusSm, background:exportingSTIX?'#333':theme.surface, border:`1px solid ${theme.border}`, color:theme.text, cursor:exportingSTIX?'not-allowed':'pointer', fontSize:13, fontWeight:600, display:'flex', alignItems:'center', gap:8 }}>
          <Download size={14}/>
          {exportingSTIX ? 'İndiriliyor...' : 'STIX 2.1 İndir'}
        </button>
        <button onClick={()=>exportSTIX(50)} disabled={exportingSTIX}
          style={{ padding:'10px 20px', borderRadius:theme.radiusSm, background:exportingSTIX?'#333':'rgba(239,68,68,0.1)', border:`1px solid rgba(239,68,68,0.3)`, color:'#ef4444', cursor:exportingSTIX?'not-allowed':'pointer', fontSize:13, fontWeight:600, display:'flex', alignItems:'center', gap:8 }}>
          <ShieldAlert size={14}/>
          {exportingSTIX ? 'İndiriliyor...' : 'Yüksek Risk (50+)'}
        </button>
      </div>
    </div>

    {/* ── Yüksek risk uyarısı ── */}
    {parseFloat(highRiskPct) > 90 && (
      <div style={{ display:'flex', alignItems:'center', gap:12, padding:'12px 20px', background:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.25)', borderRadius:theme.radiusMd, marginBottom:24 }}>
        <AlertTriangle size={18} color='#ef4444'/>
        <p style={{ fontSize:13, color:'#ef4444', fontWeight:600, margin:0 }}>Veritabanındaki IOC'ların <b>%{highRiskPct}'i yüksek risk</b> seviyesindedir. Bu tehditler aktif saldırı altyapılarıyla ilişkilidir.</p>
      </div>
    )}

    {/* ── İkili grid: Risk dağılımı + Tehdit tipi dağılımı ── */}
    <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:20, marginBottom:20 }}>
      {/* Risk dağılımı */}
      <Card>
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:20 }}>
          <BarChart3 size={16} color={theme.primary}/>
          <h3 style={{ fontSize:14, fontWeight:600, color:'#fff', margin:0 }}>Risk Dağılımı</h3>
        </div>
        {riskDist.length>0 ? (
          <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
            {riskDist.map((item,i)=>{
              const rColors=['#22c55e','#84cc16','#f59e0b','#ef4444','#ef4444']
              const c = rColors[i]||theme.primary
              return (
                <div key={i}>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:6 }}>
                    <span style={{ fontSize:12, color:theme.text, display:'flex', alignItems:'center', gap:6 }}>
                      <span style={{ width:8,height:8,borderRadius:'50%',background:c,display:'inline-block',flexShrink:0 }}/>
                      {item.range}
                    </span>
                    <span style={{ fontSize:12, fontWeight:600, color:c }}>{(item.percentage||0).toFixed(1)}%</span>
                  </div>
                  <div style={{ height:8, background:theme.bg, borderRadius:4, overflow:'hidden' }}>
                    <motion.div initial={{width:0}} animate={{width:`${Math.min(item.percentage||0,100)}%`}} transition={{delay:0.3+i*0.1,duration:0.8,ease:theme.ease.out}}
                      style={{ height:'100%', background:c, borderRadius:4 }}/>
                  </div>
                </div>
              )
            })}
          </div>
        ) : <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>}
      </Card>

      {/* Tehdit Tipi Dağılımı — CSS donut + liste */}
      <Card>
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:20 }}>
          <Zap size={16} color='#ef4444'/>
          <h3 style={{ fontSize:14, fontWeight:600, color:'#fff', margin:0 }}>Tehdit Tipi Dağılımı</h3>
        </div>
        {topThreats.length>0 ? (() => {
          const total = topThreats.reduce((s,t)=>s+(t.count||0),0)||1
          const top5 = topThreats.slice(0,5)
          // CSS conic-gradient donut
          let deg = 0
          const segments = top5.map((t)=>{
            const typeName=(t.type||t.threat_type||t.name||'').toUpperCase()
            const meta=THREAT_META[typeName]||{color:theme.primary}
            const pct=((t.count||0)/total)*100
            const from=deg; deg+=pct*3.6
            return {typeName,meta,pct,from,to:deg,count:t.count||0}
          })
          const conicStr = segments.map(s=>`${s.meta.color} ${s.from}deg ${s.to}deg`).join(', ')
          return (
            <div style={{ display:'flex', gap:24, alignItems:'center' }}>
              {/* Donut */}
              <div style={{ position:'relative', flexShrink:0 }}>
                <div style={{ width:140, height:140, borderRadius:'50%', background:`conic-gradient(${conicStr}, ${theme.border} ${deg}deg 360deg)`, position:'relative' }}/>
                <div style={{ position:'absolute', inset:28, borderRadius:'50%', background:theme.surface, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
                  <span style={{ fontSize:18, fontWeight:600, color:'#fff' }}>{top5.length}</span>
                  <span style={{ fontSize:9, color:theme.textMuted }}>Tür</span>
                </div>
              </div>
              {/* Legend */}
              <div style={{ flex:1, display:'flex', flexDirection:'column', gap:8 }}>
                {segments.map((s)=>(
                  <div key={s.typeName} style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <div style={{ width:10,height:10,borderRadius:3,background:s.meta.color,flexShrink:0 }}/>
                    <span style={{ fontSize:12, color:theme.text, flex:1 }}>{s.typeName}</span>
                    <span style={{ fontSize:11, fontWeight:600, color:s.meta.color }}>{s.pct.toFixed(1)}%</span>
                  </div>
                ))}
              </div>
            </div>
          )
        })() : <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>}
      </Card>
    </div>

    {/* ── En Yüksek Riskli Aktif IOC'lar ── */}
    <Card style={{ marginBottom:20 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:18 }}>
        <AlertTriangle size={16} color='#ef4444'/>
        <h3 style={{ fontSize:14, fontWeight:600, color:'#fff', margin:0 }}>En Yüksek Riskli Aktif Tehditler</h3>
        <span style={{ fontSize:11, color:theme.textMuted, marginLeft:'auto' }}>Anlık güncelleniyor</span>
      </div>
      {(() => {
        const hotIocs = [...iocList].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,6)
        if (!hotIocs.length) return <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>
        return (
          <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
            {hotIocs.map((item,i)=>{
              const rs=item.risk_score||0
              const typeName=(item.type||item.ioc_type||'').toUpperCase()
              const meta=THREAT_META[typeName]||{color:'#ef4444',icon:AlertTriangle}
              const Icon=meta.icon
              const val=item.value||item.ioc_value||item.ioc||item.indicator||'-'
              return (
                <motion.div key={i} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{delay:i*0.06}}
                  style={{ padding:'14px 16px', background:theme.bg, borderRadius:theme.radiusSm, border:`1px solid ${meta.color}33`, position:'relative', overflow:'hidden' }}>
                  <div style={{ position:'absolute', top:0, left:0, width:3, bottom:0, background:meta.color }}/>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:8 }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <div style={{ width:22,height:22,borderRadius:6,background:`${meta.color}18`,border:`1px solid ${meta.color}33`,display:'flex',alignItems:'center',justifyContent:'center' }}>
                        <Icon size={12} color={meta.color}/>
                      </div>
                      <span style={{ fontSize:10, fontWeight:600, color:meta.color }}>{typeName||'IOC'}</span>
                    </div>
                    <span style={{ fontSize:13, fontWeight:600, color:'#ef4444' }}>{rs}</span>
                  </div>
                  <div style={{ display:'flex', alignItems:'center', gap:4 }}>
                    <span style={{ fontSize:11, color:theme.primary, fontFamily:theme.mono, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', flex:1 }}>{val}</span>
                    <CopyBtn value={val}/>
                  </div>
                  <p style={{ fontSize:10, color:theme.textMuted, margin:'6px 0 0' }}>{item.source||'-'}</p>
                </motion.div>
              )
            })}
          </div>
        )
      })()}
    </Card>

    {/* ── En çok görülen tehditler (tam liste) ── */}
    <Card style={{ marginBottom:20 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:18 }}>
        <Activity size={16} color={theme.primary}/>
        <h3 style={{ fontSize:14, fontWeight:600, color:'#fff', margin:0 }}>Tehdit Kategorisi Analizi</h3>
      </div>
      {topThreats.length>0 ? topThreats.slice(0,10).map((t,i)=>{
        const typeName=(t.type||t.threat_type||t.name||'').toUpperCase()
        const meta=THREAT_META[typeName]||{color:theme.primary,icon:Shield}
        const Icon=meta.icon
        const barW=((t.count||0)/maxThreat)*100
        return (
          <motion.div key={i} initial={{opacity:0,x:10}} animate={{opacity:1,x:0}} transition={{delay:0.05*i}}
            style={{ display:'flex', alignItems:'center', gap:10, marginBottom:10 }}>
            <span style={{ fontSize:11, color:theme.textMuted, width:16, textAlign:'right', flexShrink:0 }}>{i+1}</span>
            <div style={{ width:22,height:22,borderRadius:6,background:`${meta.color}18`,border:`1px solid ${meta.color}33`,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0 }}>
              <Icon size={12} color={meta.color}/>
            </div>
            <div style={{ flex:1 }}>
              <div style={{ display:'flex', justifyContent:'space-between', marginBottom:4 }}>
                <span style={{ fontSize:11, fontWeight:600, color:meta.color }}>{typeName}</span>
                <span style={{ fontSize:11, fontWeight:600, color:'#fff' }}>{(t.count||0).toLocaleString('tr-TR')}</span>
              </div>
              <div style={{ height:4, background:theme.bg, borderRadius:2, overflow:'hidden' }}>
                <motion.div initial={{width:0}} animate={{width:`${barW}%`}} transition={{delay:0.1+i*0.04,duration:0.6}}
                  style={{ height:'100%', background:meta.color, borderRadius:2 }}/>
              </div>
            </div>
          </motion.div>
        )
      }) : <p style={{ color:theme.textMuted, fontSize:13 }}>Yükleniyor...</p>}
    </Card>

    {/* ── IOC Tablosu ── */}
    <Card style={{ marginBottom:20 }}>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:18 }}>
        <Eye size={16} color={theme.primary}/>
        <h3 style={{ fontSize:14, fontWeight:600, color:'#fff', margin:0 }}>Tüm IOC'lar</h3>
        <span style={{ fontSize:11, color:theme.textMuted, marginLeft:'auto' }}>{iocList.length} kayıt</span>
      </div>
      <div style={{ overflowX:'auto', maxHeight:480, overflowY:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}>
            <tr style={{ color:theme.textMuted, fontSize:10, borderBottom:`2px solid ${theme.border}` }}>
              <th style={{ width:4, padding:0 }}/>
              <th style={{ textAlign:'left', padding:'11px 12px' }}>Gösterge</th>
              <th style={{ textAlign:'center', padding:'11px 8px' }}>Tür</th>
              <th style={{ textAlign:'center', padding:'11px 8px' }}>Risk</th>
              <th style={{ textAlign:'center', padding:'11px 8px' }}>Kaynak</th>
              <th style={{ textAlign:'right', padding:'11px 12px' }}>Tarih</th>
            </tr>
          </thead>
          <tbody>
            {iocList.length===0 && <tr><td colSpan={6} style={{ textAlign:'center', padding:24, color:theme.textMuted }}>Yükleniyor...</td></tr>}
            {iocList.map((item,i)=>{
              const rs = item.risk_score||0
              const sColor = rs>75?'#ef4444':rs>40?theme.warning:theme.success
              const typeName = (item.type||item.ioc_type||'').toUpperCase()
              const meta = THREAT_META[typeName]||{color:theme.primary}
              const val = item.value||item.ioc_value||item.ioc||item.indicator||'-'
              return (
                <tr key={item.id||i} style={{ borderBottom:`1px solid ${theme.border}` }}
                  onMouseEnter={e=>e.currentTarget.style.background=theme.surface2}
                  onMouseLeave={e=>e.currentTarget.style.background='transparent'}>
                  <td style={{ width:3, padding:0, background:sColor }}/>
                  <td style={{ padding:'9px 12px' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:6 }}>
                      <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:11, wordBreak:'break-all' }}>{val}</span>
                      <CopyBtn value={val}/>
                    </div>
                  </td>
                  <td style={{ padding:'9px 8px', textAlign:'center' }}>
                    <span style={{ display:'inline-flex', alignItems:'center', gap:4, padding:'3px 8px', borderRadius:8, background:`${meta.color||theme.primary}18`, color:meta.color||theme.primary, fontSize:10, fontWeight:600 }}>
                      <ThreatIcon type={typeName} size={10}/> {item.type||item.ioc_type||'-'}
                    </span>
                  </td>
                  <td style={{ padding:'9px 8px', textAlign:'center' }}>
                    <span style={{ display:'inline-flex', alignItems:'center', gap:3, padding:'3px 8px', borderRadius:8, background:`${sColor}18`, color:sColor, fontSize:10, fontWeight:600 }}>
                      <Shield size={9}/> {rs||'-'}
                    </span>
                  </td>
                  <td style={{ padding:'9px 8px', textAlign:'center', color:theme.textMuted, fontSize:11 }}>{item.source||'-'}</td>
                  <td style={{ padding:'9px 12px', textAlign:'right', color:theme.textMuted, fontSize:10 }}>{item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):item.date?new Date(item.date).toLocaleDateString('tr-TR'):'-'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Card>

    {/* ── Proje açıklama kartı (yarışma için) ── */}
    <div style={{ padding:24, background:theme.surface, border:`1px solid ${theme.border}`, borderRadius:theme.radiusMd, display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:20 }}>
      {[
        { icon:Shield, color:theme.primary, title:'IOC Nedir?', desc:'Indicator of Compromise — bir sistemin tehlikeye girdiğine işaret eden zararlı IP, domain, URL veya dosya hash değerleridir.' },
        { icon:Hash, color:theme.warning, title:'Nasıl Kullanılır?', desc:'Bir IP veya domain şüpheli geliyorsa arama kutusuna girerek veritabanımızda tehdit kaydı olup olmadığını anlık sorgulayabilirsiniz.' },
        { icon:Lock, color:theme.success, title:'Neden Önemli?', desc:'AegisNexus, açık tehdit istihbaratı kaynaklarını birleştirerek kişisel ve kurumsal kullanıcıları siber saldırılara karşı önceden uyarır.' },
      ].map(({icon, color, title, desc})=>{
        const SectionIcon = icon
        return (
        <div key={title} style={{ display:'flex', gap:14 }}>
          <div style={{ width:36,height:36,borderRadius:10,background:`${color}18`,border:`1px solid ${color}33`,display:'flex',alignItems:'center',justifyContent:'center',flexShrink:0 }}>
            <SectionIcon size={18} color={color}/>
          </div>
          <div>
            <p style={{ fontSize:13, fontWeight:600, color:'#fff', marginBottom:4 }}>{title}</p>
            <p style={{ fontSize:12, color:theme.textMuted, lineHeight:1.6, margin:0 }}>{desc}</p>
          </div>
        </div>
        )
      })}
    </div>
  </div>
}
export default HoneypotIOC
