import { apiFetch as fetch } from '../lib/api'
import { useState, useEffect, useRef, useCallback, type MouseEvent } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { emitEvent } from '../stores/eventBus'
import { IkLink2, IkShieldDoc, IkGlobe2, IkBolt, IkSearch, IkScope, IkCamera, theme, Card, RiskGauge, IkAlert, IkWarn, IkCheck2, IkRadar, IkGrid, IkMonitor, IkClipboard, useWindowWidth, API, Toast, IkChart, CountUp, StatusDot, normalizeStatus } from './shared'

import type { ModuleScreenProps } from '../ModulesApp'
import type { PhishingStats, ScanHistoryRow } from '../lib/types'

/**
 * The scan verdict is produced by the scoring pipeline (threat-intel sources,
 * screenshot analysis, ...); its nested provider payloads are open-ended.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- provider payloads are scorer-defined
type ProviderPayload = Record<string, any>
interface ScanSource { name?: string; status?: string; detail?: string; [key: string]: unknown }
interface ScanView {
  status?: string
  job_id?: string
  url?: string
  domain?: string
  risk_score?: number
  safety_score?: number
  score?: number
  risk_level?: string
  risk?: string
  details?: string[]
  sources?: ScanSource[]
  threat_intel?: ProviderPayload
  message?: string
  error?: string
  [key: string]: unknown
}
interface FeedRow { id?: number; url?: string; domain?: string; target?: string; status?: string; risk_score?: number; risk_level?: string; submission_time?: string | null; created_at?: string | null }
type ToastState = { message: string; type: 'success' | 'error'; visible: boolean }

function PhishingResult({ result, url }: { result: ScanView; url: string }) {
  if (['timeout','failed','error','expired','degraded'].includes(result.status ?? '')) return <Card><h2>Analiz tamamlanamadı</h2><p>Bu sonuç güvenli veya tehlikeli kararı değildir. Yeniden deneyin.</p></Card>
  const ti = result.threat_intel || {}
  const sa = ti.screenshot_analysis || {}
  const screenshotB64 = sa.screenshot_b64 || null
  const indicators = Array.isArray(sa.threat_indicators) ? sa.threat_indicators : []
  const vt = ti.virustotal || {}
  const gsb = ti.google_safe_browsing || {}
  const aipdb = ti.abuseipdb || {}
  const urlhaus = ti.urlhaus || {}
  const shDomain = ti.spamhaus_domain || {}
  const shIp = ti.spamhaus_ip || {}
  const tf = ti.threatfox || {}

  const srcCards = [
    { key:'urlhaus', Icon:IkLink2, name:'URLhaus', data:urlhaus, isBad:urlhaus.listed===true, isClean:urlhaus.listed===false, badLabel:'LISTED', cleanLabel:'CLEAN', detail:urlhaus.listed?`Tehdit: ${urlhaus.threat_type||'unknown'}`:'Kara listede değil', penalty:40 },
    { key:'spamhaus_domain', Icon:IkShieldDoc, name:'Spamhaus Domain', data:shDomain, isBad:shDomain.listed===true, isClean:shDomain.listed===false&&shDomain.available, badLabel:'LISTED', cleanLabel:'CLEAN', detail:shDomain.listed?`Listeler: ${(shDomain.lists||[]).join(', ')||'-'}`:shDomain.zrd?'Sıfır itibar (ZRD)':'Temiz', penalty:35 },
    { key:'spamhaus_ip', Icon:IkGlobe2, name:'Spamhaus IP', data:shIp, isBad:shIp.listed===true, isClean:shIp.listed===false&&shIp.available, badLabel:'LISTED', cleanLabel:'CLEAN', detail:shIp.listed?`Listeler: ${(shIp.lists||[]).join(', ')||'-'}`:'Temiz', penalty:30 },
    { key:'threatfox', Icon:IkBolt, name:'ThreatFox', data:tf, isBad:tf.found===true, isClean:tf.found===false&&tf.available, badLabel:'FOUND', cleanLabel:'NOT FOUND', detail:tf.found?`${tf.malware_family||'unknown'} (conf: ${tf.confidence||0}%)`:'IOC bulunamadı', penalty:25 },
    { key:'virustotal', Icon:IkShieldDoc, name:'VirusTotal', data:vt, isBad:(vt.malicious||0)>=1, isClean:vt.available&&(vt.malicious||0)===0, badLabel:`${vt.malicious||0} MAL`, cleanLabel:'CLEAN', detail:vt.available?(vt.source==='whitelist'?'Whitelist domain (güvenilir)':`${vt.malicious||0} motor tehlikeli`):'Sonuç yok', penalty:40 },
    { key:'gsb', Icon:IkSearch, name:'Google Safe Browsing', data:gsb, isBad:gsb.threat===true, isClean:gsb.available&&!gsb.threat, badLabel:'THREAT', cleanLabel:'SAFE', detail:gsb.threat?gsb.threat_type||'Tehdit':'Güvenli', penalty:50 },
    { key:'abuseipdb', Icon:IkScope, name:'AbuseIPDB (Local)', data:aipdb, isBad:(aipdb.abuse_score||0)>=30, isClean:aipdb.available&&(aipdb.abuse_score||0)<30, badLabel:`${aipdb.abuse_score||0}%`, cleanLabel:'CLEAN', detail:aipdb.available?`Suistimal: %${aipdb.abuse_score||0}`:'Sonuç yok', penalty:25 },
    { key:'screenshot', Icon:IkCamera, name:'Screenshot Analyzer', data:sa, isBad:(sa.risk_score||0)>50, isClean:sa.available&&(sa.risk_score||0)<=30, badLabel:sa.risk_level||'HIGH', cleanLabel:'SAFE', detail:(!sa.available&&screenshotB64)?'Screenshot alındı (AI analizi devre dışı)':(sa.verdict||'Analiz yok'), penalty:sa.available?Math.round((sa.risk_score||50)*0.6):0, hasDataOverride: !!screenshotB64 || !!sa.verdict, badgeOverride: (!sa.available&&screenshotB64)?'CAPTURED':null },
  ]

  const openScreenshot = () => {
    if (!screenshotB64) return
    const w = window.open('','_blank')
    if(w){w.document.write(`<html><head><title>Screenshot</title><style>body{margin:0;background:#111;display:flex;align-items:center;justify-content:center;min-height:100vh}img{max-width:100%;height:auto}</style></head><body><img src="data:image/png;base64,${screenshotB64}"/></body></html>`);w.document.close()}
  }

  return (
  <motion.div initial={{opacity:0,y:30}} animate={{opacity:1,y:0}} transition={{duration:0.6,ease:theme.ease.out}} style={{marginBottom:48}}>
    {/* Hero Result Card */}
    {(() => { const safetyScore = result.safety_score ?? result.score ?? 0; return (
    <Card style={{background:'rgba(255,255,255,0.03)',border:`1px solid ${safetyScore<50?theme.accent+'40':theme.primary+'40'}`,marginBottom:24}}>
      <div style={{display:'flex',gap:32,alignItems:'flex-start',flexWrap:'wrap'}}>
        {/* Left: Gauge + Screenshot */}
        <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:16,minWidth:200}}>
          <RiskGauge score={safetyScore} label="Güvenilirlik Skoru" size="lg" safetyMode={true}/>
          <span style={{padding:'8px 20px',borderRadius:'24px',fontSize:14,fontWeight:600,background:safetyScore<50?theme.accentDim:theme.primaryDim,color:safetyScore<50?theme.accent:theme.primary}}>{result.risk_level||'Bilinmiyor'}</span>
          {screenshotB64&&(
            <motion.div initial={{opacity:0,scale:0.9}} animate={{opacity:1,scale:1}} transition={{delay:0.3,duration:0.4}} style={{position:'relative',cursor:'pointer'}} onClick={openScreenshot}>
              <img src={`data:image/png;base64,${screenshotB64}`} alt="Site screenshot" style={{width:200,height:'auto',maxHeight:150,objectFit:'cover',borderRadius:theme.radiusMd,border:`1px solid ${theme.border}`,boxShadow:'0 1px 2px rgba(0,0,0,0.3)',opacity:0.9,transition:'opacity 0.3s ease'}} onMouseEnter={e=>{e.currentTarget.style.opacity='1'}} onMouseLeave={e=>{e.currentTarget.style.opacity='0.9'}}/>
              <span style={{position:'absolute',bottom:6,right:6,padding:'3px 8px',borderRadius:6,fontSize:9,fontWeight:600,background:'rgba(0,0,0,0.7)',color:theme.primary,display:'flex',alignItems:'center',gap:4}}><IkSearch size={9} color={theme.primary}/> BÜYÜT</span>
            </motion.div>
          )}
        </div>
        {/* Right: Details */}
        <div style={{flex:1,minWidth:300}}>
          <p style={{fontSize:14,color:theme.textMuted,wordBreak:'break-all',marginBottom:16,fontFamily:theme.mono,lineHeight:1.6}}>{url}</p>
          {result.details&&Array.isArray(result.details)&&result.details.length>0&&(
            <div style={{marginBottom:16}}>
              <p style={{fontSize:12,fontWeight:600,color:theme.textMuted,marginBottom:10,display:'flex',alignItems:'center',gap:6}}><IkShieldDoc size={12} color={theme.textMuted}/> Tespitler</p>
              <div style={{display:'flex',flexDirection:'column',gap:5,maxHeight:220,overflowY:'auto'}}>
                {(result.details ?? []).slice(0,12).map((d,i)=>{
                  const isDanger=d.includes('🚨')||d.includes('❌')||/tehlike|kritik|phishing|malware/i.test(d)
                  const isWarn=d.includes('⚠️')||/uyar|şüpheli|dikkat/i.test(d)
                  const isSafe=d.includes('✅')||/temiz|güvenli/i.test(d)
                  const isScreen=d.includes('📸')||/screenshot/i.test(d)
                  const DetailIcon=isScreen?IkCamera:isDanger?IkAlert:isWarn?IkWarn:isSafe?IkCheck2:IkShieldDoc
                  const iconColor=isDanger?theme.accent:isWarn?theme.warning:isSafe?theme.success:theme.primary
                  const stripped=d.replace(/[\p{Extended_Pictographic}\uFE0F]/gu,'').trim()
                  const techMatch=stripped.match(/^(.+?)\s*(\([^)]*(?:risk|ceza|penalty|conf|score|ağırlık)[^)]*\))(.*)$/i)
                  const mainText=techMatch?techMatch[1].trim()+techMatch[3]:stripped
                  const techNote=techMatch?techMatch[2]:null
                  return (
                    <motion.div key={i} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.08+i*0.03,duration:0.28}}
                      style={{padding:'9px 12px',background:isDanger?'rgba(255,0,64,0.08)':isWarn?'rgba(255,193,7,0.06)':isSafe?'rgba(34,197,94,0.05)':theme.primaryDim,borderRadius:8,borderLeft:isDanger?`3px solid ${theme.accent}`:isWarn?`3px solid ${theme.warning}`:isSafe?`3px solid ${theme.success}`:`3px solid ${theme.primary}`,display:'flex',alignItems:'flex-start',gap:9}}
                    >
                      <span style={{flexShrink:0,marginTop:2}}><DetailIcon size={13} color={iconColor}/></span>
                      <span style={{flex:1,minWidth:0}}>
                        <span style={{fontSize:13,color:theme.text,lineHeight:1.55,fontWeight:isDanger||isWarn?600:400}}>{mainText}</span>
                        {techNote&&<span style={{fontSize:10,color:theme.textMuted,marginLeft:6,opacity:0.65,fontFamily:theme.mono}}>{techNote}</span>}
                      </span>
                    </motion.div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </Card>
    )})()}

    {/* Threat Intel Source Cards */}
    <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{delay:0.2,duration:0.5}} style={{marginBottom:24}}>
      <p style={{fontSize:13,fontWeight:600,color:theme.textMuted,marginBottom:16,display:'flex',alignItems:'center',gap:7}}><IkRadar size={13} color={theme.textMuted}/> Tehdit İstihbaratı Kaynakları</p>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill, minmax(220px, 1fr))',gap:12}}>
        {srcCards.map((src,i)=>{
          const hasData=src.hasDataOverride||(src.data&&(src.data.available!==false||src.isBad||src.isClean))
          const statusColor=src.isBad?theme.accent:src.isClean?theme.success:theme.textMuted
          const bgColor=src.isBad?'rgba(255,0,64,0.06)':src.isClean?'rgba(34,197,94,0.06)':'rgba(255,255,255,0.02)'
          const borderColor=src.isBad?theme.accent+'40':src.isClean?theme.success+'40':theme.border
          return (
            <motion.div key={src.key} initial={{opacity:0,y:15}} animate={{opacity:1,y:0}} transition={{delay:0.3+i*0.05,duration:0.35}} style={{padding:'16px 18px',background:bgColor,border:`1px solid ${borderColor}`,borderRadius:theme.radiusMd,position:'relative',overflow:'hidden'}}>
              <div style={{position:'absolute',top:0,left:0,right:0,height:2,background:statusColor}}/>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
                <span style={{fontSize:14,fontWeight:600,color:'#fff',display:'flex',alignItems:'center',gap:6}}><src.Icon size={13} color={statusColor}/> {src.name}</span>
                {src.isBad&&<span style={{padding:'3px 8px',borderRadius:6,fontSize:9,fontWeight:600,background:theme.accentDim,color:theme.accent}}>-{src.penalty}</span>}
              </div>
              <div style={{marginBottom:8}}>
                <span style={{display:'inline-block',padding:'4px 10px',borderRadius:8,fontSize:11,fontWeight:600,background:src.isBad?theme.accentDim:src.isClean?'rgba(34,197,94,0.15)':'rgba(255,255,255,0.05)',color:statusColor}}>
                  {hasData?(src.badgeOverride||(src.isBad?src.badLabel:src.isClean?src.cleanLabel:'N/A')):'—'}
                </span>
              </div>
              <p style={{fontSize:12,color:theme.textMuted,lineHeight:1.4,margin:0}}>{hasData?src.detail:'Veri yok'}</p>
            </motion.div>
          )
        })}
      </div>
    </motion.div>

    {/* Screenshot Threat Indicators */}
    {indicators.length>0&&(
      <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{delay:0.5,duration:0.4}} style={{marginBottom:24}}>
        <p style={{fontSize:13,fontWeight:600,color:theme.textMuted,marginBottom:16,display:'flex',alignItems:'center',gap:7}}><IkGrid size={13} color={theme.textMuted}/> Görsel Tehdit İndikatörleri</p>
        <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill, minmax(280px, 1fr))',gap:10}}>
          {indicators.map((ind: ProviderPayload,j: number)=>{
            const t=ind.type||'visual'
            const IcComp=t==='url'?IkLink2:t==='domain'?IkGlobe2:t==='ip'?IkMonitor:IkScope
            return (
              <motion.div key={j} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.6+j*0.05,duration:0.3}} style={{padding:'12px 16px',background:'rgba(239,68,68,0.06)',border:`1px solid ${theme.accent}30`,borderRadius:theme.radiusMd,borderLeft:`3px solid ${theme.accent}`}}>
                <div style={{display:'flex',alignItems:'center',gap:8,marginBottom:6}}>
                  <IcComp size={14} color={theme.accent}/>
                  <span style={{fontSize:12,fontWeight:600,color:theme.accent}}>{t}</span>
                </div>
                <p style={{fontSize:13,color:theme.text,fontFamily:theme.mono,margin:'0 0 4px 0',wordBreak:'break-all'}}>{ind.value||'—'}</p>
                {ind.reason&&<p style={{fontSize:11,color:theme.textMuted,margin:0,lineHeight:1.4}}>{ind.reason}</p>}
              </motion.div>
            )
          })}
        </div>
      </motion.div>
    )}

    {/* Sources Summary */}
    {result.sources&&Array.isArray(result.sources)&&result.sources.length>0&&(
      <motion.div initial={{opacity:0,y:20}} animate={{opacity:1,y:0}} transition={{delay:0.6,duration:0.4}}>
        <p style={{fontSize:13,fontWeight:600,color:theme.textMuted,marginBottom:16,display:'flex',alignItems:'center',gap:7}}><IkClipboard size={13} color={theme.textMuted}/> Taranan Kaynaklar</p>
        <div style={{display:'flex',flexDirection:'column',gap:6}}>
          {result.sources.map((s: ScanSource,i: number)=>{
            const isFail=typeof s.status==='string'&&(s.status.includes('Başarısız')||s.status.includes('timeout')||s.status.includes('error'))
            const isOk=typeof s.status==='string'&&(s.status.includes('CLEAN')||s.status.includes('SAFE')||s.status.includes('Tamamlandı')||s.status.includes('Ulaşılabilir')||s.status.includes('temiz'))
            return (
              <motion.div key={i} initial={{opacity:0,x:-10}} animate={{opacity:1,x:0}} transition={{delay:0.7+i*0.03,duration:0.3}} style={{padding:'10px 16px',background:isFail?'rgba(255,0,64,0.06)':isOk?'rgba(34,197,94,0.04)':'rgba(255,255,255,0.03)',borderRadius:10,fontSize:13,display:'flex',gap:10,alignItems:'center',borderLeft:isFail?`3px solid ${theme.accent}`:isOk?`3px solid ${theme.success}`:`3px solid ${theme.border}`}}>
                <span style={{color:theme.textMuted}}>Kaynak:</span>
                <span style={{color:'#fff',fontWeight:600}}>{s.name}</span>
                <span style={{marginLeft:'auto',color:isFail?theme.danger:isOk?theme.success:theme.textMuted,fontSize:12}}>{s.status}</span>
              </motion.div>
            )
          })}
        </div>
      </motion.div>
    )}
  </motion.div>
  )
}

function PhishingDetector({ initialUrl = '', onClearPrefill }: ModuleScreenProps & { onClearPrefill?: () => void }) {
  const isMobile = useWindowWidth() < 768
  const [url, setUrl] = useState(initialUrl)
  const [checking, setChecking] = useState(false)
  const [result, setResult] = useState<ScanView | null>(null)
  const [latestFeeds, setLatestFeeds] = useState<FeedRow[]>([])
  const [scanHistory, setScanHistory] = useState<(ScanHistoryRow & { domain?: string; risk?: string })[]>([])
  const [stats, setStats] = useState<PhishingStats | null>(null)
  const [pageNum, setPageNum] = useState(1)
  const [totalPages, setTotalPages] = useState(1)
  const [latestTotal, setLatestTotal] = useState(0)
  const [loadingLatest, setLoadingLatest] = useState(false)
  const [toast, setToast] = useState<ToastState>({ message:'', type:'success', visible:false })
  const [searchResults, setSearchResults] = useState<FeedRow[]>([])
  const [showDropdown, setShowDropdown] = useState(false)
  const searchTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [pollCount, setPollCount] = useState(0)
  const MAX_POLLS = 310
  const [showRetryButton, setShowRetryButton] = useState(false)
  const prefillProcessed = useRef('')

  useEffect(() => {
    if (initialUrl && initialUrl !== prefillProcessed.current) {
      prefillProcessed.current = initialUrl
      setUrl(initialUrl)
      onClearPrefill?.()
      setTimeout(() => handleCheck(false, initialUrl), 150)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialUrl])

  function showToast(msg: string,t: ToastState['type']='success'){setToast({message:msg,type:t,visible:true});setTimeout(()=>setToast(t=>({...t,visible:false})),3000)}

  // Tarama bir sonuca ulaştığında canlı olay veriyoluna yayınla; diğer modüller
  // ve olaylar paneli anında tepki verir. Ara "analyzing" durumları atlanır.
  const emittedResult = useRef<ScanView | null>(null)
  useEffect(() => {
    if (!result || result === emittedResult.current) return
    if (result.status === 'analyzing') return
    if (['timeout','failed','error','expired','degraded'].includes(result.status ?? '')) return
    const score = result.safety_score ?? result.score
    if (score == null && !result.risk_level) return
    emittedResult.current = result
    const target = url || result.url || result.domain || 'adres'
    const bad = (typeof score === 'number' && score < 50) || ['phishing','high'].includes(String(result.risk_level||'').toLowerCase())
    emitEvent({
      module: 'phishing', type: 'scan.completed',
      severity: bad ? 'high' : 'low',
      title: bad ? `Şüpheli: ${target}` : `Temiz: ${target}`,
      detail: `Güvenilirlik ${score ?? '—'}/100 · ${result.risk_level || 'bilinmiyor'}`,
      payload: { url: target, score, risk_level: result.risk_level },
    })
  }, [result, url])

  const loadLatest = useCallback(async (p=1) => {
    try{
      setLoadingLatest(true)
      const r=await fetch(`${API}/phishing/latest-paged?limit=20&page=${p}`)
      if(!r.ok) throw new Error('Son veriler alınamadı')
      const d=await r.json()
      setLatestFeeds(d.data||d.latest||[])
      setTotalPages(d.total_pages||Math.ceil((d.total||0)/20)||1)
      setPageNum(d.page||p)
      setLatestTotal(d.total||0)
    }catch(e){
      showToast('Son phishing verileri yüklenemedi: '+(e instanceof Error?e.message:String(e)),'error')
    } finally {
      setLoadingLatest(false)
    }
  }, [])

  const loadScanHistory = useCallback(async (p=1) => {
    try {
      const r = await fetch(`${API}/phishing/scan-history?limit=30&page=${p}`)
      if(!r.ok) throw new Error('Tarama gecmisi alınamadı')
      const d = await r.json()
      const items = d.data || d.history || []
      const seen = new Set()
      const deduped = items.filter((item: ScanHistoryRow) => {
        if (!item?.url) return false
        if (seen.has(item.url)) return false
        seen.add(item.url)
        return true
      })
      setScanHistory(deduped)
    } catch {
      setScanHistory([])
    }
  }, [])

  const loadStats = useCallback(async () => {
    try{
      const r=await fetch(`${API}/phishing/stats`)
      if(!r.ok) throw new Error('Istatistik endpoint hatasi')
      const d=await r.json()
      setStats(d)
    }catch(e){
      showToast('Istatistikler yüklenemedi: '+(e instanceof Error?e.message:String(e)),'error')
    }
  }, [])

  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(()=>{loadLatest(1);loadScanHistory(1);loadStats()},[loadLatest, loadScanHistory, loadStats])

  // Real-time autocomplete with debouncing
  useEffect(() => {
    if (url.length < 1) return
    
    if (searchTimeoutRef.current) {
      clearTimeout(searchTimeoutRef.current)
    }
    
    searchTimeoutRef.current = setTimeout(async () => {
      try {
        const r = await fetch(`${API}/phishing/search?url=${encodeURIComponent(url)}`)
        const d = await r.json()
        if (d.status === 'success' || d.results || d.data) {
          setSearchResults(d.results || d.data || [])
          setShowDropdown(true)
        } else {
          setSearchResults([])
          setShowDropdown(false)
        }
      } catch {
        setSearchResults([])
        setShowDropdown(false)
      }
    }, 150)
    
    return () => {
      if (searchTimeoutRef.current) {
        clearTimeout(searchTimeoutRef.current)
      }
    }
  }, [url])

  const submitCheckRequest = useCallback(async (normalizedInput: string, forceFresh = false) => {
    const r = await fetch(`${API}/phishing/check-url`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: normalizedInput, force_fresh: forceFresh }),
    })
    if(!r.ok) throw new Error(`URL kontrol hatasi (${r.status})`)
    return r.json()
  }, [])

  async function handleCheck(forceFreshOrEvent: boolean | MouseEvent = false, urlOverride: string | null = null) {
    // Event handler olarak kullanıldığında (onClick), React event object gelir - ignore et
    const forceFresh = typeof forceFreshOrEvent === 'boolean' ? forceFreshOrEvent : false
    const urlToCheck = urlOverride || url
    if(!urlToCheck){showToast('Lutfen bir URL girin','error');return}
    setChecking(true);setResult(null);setJobId(null);setAnalyzing(false);setPollCount(0);setShowRetryButton(false)
    try{
      const normalizedInput = /^https?:\/\//i.test(urlToCheck) ? urlToCheck : `https://${urlToCheck}`
      new URL(normalizedInput)
      const d = await submitCheckRequest(normalizedInput, forceFresh)
      if(d.status==='analyzing' && d.job_id){
        setResult(d)
        setJobId(d.job_id)
        setAnalyzing(true)
      } else {
        setResult(d)
        setShowRetryButton(false)
      }
      loadScanHistory(1)
    }catch(e){
      const errMsg = (e instanceof Error && e.message) || (typeof e === 'string' ? e : 'Bilinmeyen hata')
      showToast('URL kontrol hatasi: '+errMsg,'error')
    }
    setChecking(false)
  }

  useEffect(()=>{
    if(!jobId||!analyzing) return
    if(pollCount>=MAX_POLLS){
      const tryRecoverFromCache = async () => {
        setAnalyzing(false)
        setJobId(null)
        try {
          const normalizedInput = /^https?:\/\//i.test(url) ? url : `https://${url}`
          const d = await submitCheckRequest(normalizedInput, false)
          if(d.status==='complete'){
            setResult(d)
            setShowRetryButton(false)
            loadScanHistory(1)
            return
          } else if(d.status==='analyzing') {
            setShowRetryButton(true)
            return
          }
        } catch (err) {
          void err
        }
        setShowRetryButton(true)
        showToast('Analiz zaman asimi. "Yeniden Tara" ile tekrar deneyin.','error')
      }
      void tryRecoverFromCache()
      return
    }
    const timer=setTimeout(async()=>{
      try{
        const r=await fetch(`${API}/phishing/result/${jobId}`)
        const d=await r.json()
        if(d.status==='complete'){
          setResult(d)
          setAnalyzing(false)
          setJobId(null)
          setShowRetryButton(false)
          loadScanHistory(1)
        } else if(['timeout','error','failed','expired'].includes(d.status)){
          setResult(d)
          setAnalyzing(false)
          setJobId(null)
          setShowRetryButton(true)
        } else {
          setPollCount(c=>c+1)
        }
      }catch{
        setPollCount(c=>c+1)
      }
    },3000)
    return ()=>clearTimeout(timer)
  },[jobId,analyzing,pollCount,url,loadScanHistory,submitCheckRequest])

  const totalUrls=stats?.stats?.total_urls||0
  const phCount=stats?.stats?.phishing_count||0
  const safeCount=stats?.stats?.safe_count||0

  return <div>
    <Toast {...toast}/>
    
    {/* Hero Section - Main Site Style */}
    <motion.div 
      initial={{ opacity:0, y:30 }}
      animate={{ opacity:1, y:0 }}
      transition={{ duration:0.8, ease:theme.ease.out }}
      style={{ 
        position:'relative',
        padding:'0 0 8px',
        marginBottom:24
      }}
    >
      <div style={{ position:'relative', zIndex:1, maxWidth:1200, margin:'0 auto' }}>

        {/* Search Section - Glassmorphism */}
        <motion.div 
          initial={{ opacity:0, y:30 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.4, duration:0.6, ease:theme.ease.out }}
          style={{ maxWidth:800, margin:'0 auto', position:'relative', zIndex:200 }}
        >
          <div style={{ 
            background:'rgba(255,255,255,0.05)', 
            border:`1px solid ${theme.primary}33`,
            borderRadius:theme.radiusLg,
            padding:8,
            boxShadow:'0 1px 2px rgba(0,0,0,0.3)',
            position:'relative'
          }}>
            <div style={{ display:'flex', gap:12, flexDirection: isMobile ? 'column' : 'row' }}>
              <input 
                value={url} 
                onChange={e=>setUrl(e.target.value)} 
                placeholder="https://ornek.com/supheli-link" 
                style={{ 
                  flex:1, 
                  padding:'20px 28px', 
                  borderRadius:theme.radiusMd,
                  background:'rgba(255,255,255,0.05)',
                  border:'none',
                  color:'#fff', 
                  fontSize:17, 
                  outline:'none',
                  fontFamily:theme.font
                }} 
                onKeyDown={e=>e.key==='Enter'&&handleCheck()}
              />
              <motion.button 
                onClick={handleCheck}
                disabled={checking}
                style={{
                  padding:'20px 40px',
                  borderRadius:theme.radiusMd,
                  cursor:checking?'not-allowed':'pointer',
                  fontSize:16,
                  fontWeight:600,
                  background:checking?'#444':theme.gradientPrimary,
                  color:checking?'#888':'#000',
                  border:'none',
                  display:'inline-flex',
                  alignItems:'center',
                  gap:10,
                  opacity:checking?0.5:1,
                  boxShadow:checking?'none':'0 1px 2px rgba(0,0,0,0.3)',
                  transition:'all 0.3s ease'
                }}
              >
                {checking ? (
                  <><motion.span animate={{rotate:360}} transition={{repeat:Infinity,duration:1,ease:'linear'}} style={{display:'inline-flex'}}><IkSearch size={16} color="#888"/></motion.span> Taranıyor...</>
                ) : (
                  <><IkSearch size={16} color="#000"/> Tara</>
                )}
              </motion.button>
            </div>
          </div>

          {/* Autocomplete Dropdown — outside overflow:hidden parent */}
          <AnimatePresence>
            {showDropdown && searchResults.length > 0 && (
              <motion.div
                initial={{ opacity:0, y:-6 }}
                animate={{ opacity:1, y:0 }}
                exit={{ opacity:0, y:-6 }}
                transition={{ duration:0.15, ease:theme.ease.out }}
                style={{
                  position:'absolute',
                  top:'calc(100% + 8px)',
                  left:0,
                  right:0,
                  background:'rgba(8,12,20,0.98)',
                  borderRadius:theme.radiusMd,
                  border:`1px solid ${theme.border}`,
                  maxHeight:320,
                  overflowY:'auto',
                  zIndex:9999,
                  boxShadow:'0 1px 2px rgba(0,0,0,0.3)'
                }}
              >
                {searchResults.slice(0, 10).map((item, i) => (
                  <div
                    key={i}
                    onClick={() => {
                      setUrl(item.url || '')
                      setShowDropdown(false)
                      handleCheck(false, item.url)
                    }}
                    style={{
                      padding:'12px 20px',
                      borderBottom:`1px solid ${theme.border}`,
                      cursor:'pointer',
                      transition:'background 0.15s ease'
                    }}
                    onMouseEnter={e=>e.currentTarget.style.background='rgba(250,250,250,0.04)'}
                    onMouseLeave={e=>e.currentTarget.style.background='transparent'}
                  >
                    <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                      <span style={{ color:theme.primary, fontFamily:theme.mono, fontSize:12, wordBreak:'break-all', flex:1, marginRight:12 }}>{item.url||'-'}</span>
                      <span style={{ padding:'3px 10px', borderRadius:10, fontSize:10, flexShrink:0, background:(item.risk_score||0)<50?theme.accentDim:theme.primaryDim, color:(item.risk_score||0)<50?theme.accent:theme.primary }}>{item.risk_level||'Bilinmiyor'}</span>
                    </div>
                    <div style={{ display:'flex', gap:16, fontSize:11, color:theme.textMuted }}>
                      <span>Risk: <b style={{ color:item.risk_score==null?theme.textMuted:item.risk_score>=80?theme.danger:item.risk_score>=50?theme.warning:theme.success }}>{item.risk_score??'—'}/100</b></span>
                      <span>Domain: {item.domain||'-'}</span>
                    </div>
                  </div>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </motion.div>

        {/* Scan History Preview */}
        {scanHistory.length > 0 && (
          <motion.div
            initial={{ opacity:0, y:20 }}
            animate={{ opacity:1, y:0 }}
            transition={{ delay:0.6, duration:0.6, ease:theme.ease.out }}
            style={{ 
              maxWidth:900, 
              margin:'32px auto 0',
              background:'rgba(255,255,255,0.03)',
              borderRadius:theme.radiusLg,
              border:`1px solid ${theme.border}`,
              overflow:'hidden'
            }}
          >
            <div style={{ padding:'14px 20px', borderBottom:`1px solid ${theme.border}`, display:'flex', alignItems:'center', justifyContent:'space-between' }}>
              <span style={{ fontSize:13, fontWeight:600, color:'#fff', display:'flex', alignItems:'center', gap:6 }}><IkClipboard size={13} color={theme.textMuted}/> Son Taranan URL'ler</span>
              <span style={{ fontSize:11, color:theme.textMuted }}>{scanHistory.length} tarama</span>
            </div>
            <div style={{ maxHeight:280, overflowY:'auto', overflowX:'hidden' }}>
              {scanHistory.slice(0, 10).map((item, i) => {
                const risk = item.risk_level || item.risk || ''
                const isPhishing = risk === 'phishing' || risk === 'high'
                const isSafe = risk === 'safe' || risk === 'low'
                const riskColor = isPhishing ? '#f87171' : isSafe ? '#34d399' : theme.textMuted
                const dotColor = isPhishing ? '#f87171' : isSafe ? '#34d399' : theme.textMuted
                return (
                  <div
                    key={i}
                    onClick={() => { setUrl(item.url); handleCheck(false, item.url) }}
                    style={{ 
                      display:'flex', 
                      alignItems:'center', 
                      gap:10, 
                      padding:'10px 20px',
                      borderBottom: i < Math.min(scanHistory.length, 10) - 1 ? `1px solid ${theme.border}33` : 'none',
                      cursor:'pointer',
                      transition:'background 0.15s ease'
                    }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(250,250,250,0.035)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                  >
                    <span style={{ width:7, height:7, borderRadius:'50%', background:dotColor, flexShrink:0, display:'inline-block', marginTop:1 }}/>
                    <span style={{ 
                      flex:1, 
                      fontFamily:theme.mono, 
                      fontSize:12, 
                      color:theme.textMuted || '#ccc',
                      overflow:'hidden',
                      textOverflow:'ellipsis',
                      whiteSpace:'nowrap'
                    }}>{item.url}</span>
                    {risk && <span style={{ fontSize:10, color:riskColor, flexShrink:0, fontWeight:600 }}>{risk}</span>}
                  </div>
                )
              })}
            </div>
          </motion.div>
        )}
      </div>
    </motion.div>

    {/* C1: Derin Analiz Progress Bar */}
    <AnimatePresence>
      {analyzing && (() => {
        const elapsed = Math.round(pollCount * 3)
        const pct = Math.min((pollCount / MAX_POLLS) * 100, 95)
        const STEPS = [
          { at:0,  label:'Siteye bağlanılıyor...',           icon:IkGlobe2 },
          { at:5,  label:'Screenshot alınıyor...',            icon:IkCamera },
          { at:15, label:'VirusTotal sorgulanıyor...',        icon:IkShieldDoc },
          { at:22, label:'AbuseIPDB kontrol ediliyor...',     icon:IkScope },
          { at:30, label:'Spamhaus / URLhaus taranıyor...',   icon:IkRadar },
          { at:40, label:'AI içerik analizi yapılıyor...',    icon:IkSearch },
          { at:55, label:'ML sınıflandırması tamamlanıyor...', icon:IkChart },
          { at:70, label:'Risk skoru hesaplanıyor...',        icon:IkWarn },
        ]
        const activeStep = [...STEPS].reverse().find(s => pct >= s.at) || STEPS[0]
        const StepIcon = activeStep.icon
        return (
          <motion.div
            initial={{ opacity:0, y:-10 }}
            animate={{ opacity:1, y:0 }}
            exit={{ opacity:0, y:-10 }}
            transition={{ duration:0.3, ease:theme.ease.out }}
            style={{
              maxWidth:900,
              margin:'0 auto 24px',
              padding:'20px 24px',
              background:'rgba(250,250,250,0.025)',
              border:`1px solid ${theme.primary}33`,
              borderRadius:theme.radiusMd,
              display:'flex',
              alignItems:'center',
              gap:20
            }}
          >
            {/* Radar pulse icon */}
            <div style={{ position:'relative', width:44, height:44, flexShrink:0 }}>
              {[0,1,2].map(ring => (
                <motion.div
                  key={ring}
                  animate={{ scale:[1, 2.6], opacity:[0.55, 0] }}
                  transition={{ repeat:Infinity, duration:2.2, delay:ring * 0.7, ease:'easeOut' }}
                  style={{ position:'absolute', inset:0, borderRadius:'50%', border:`1.5px solid ${theme.primary}` }}
                />
              ))}
              <div style={{ position:'absolute', inset:0, display:'flex', alignItems:'center', justifyContent:'center', background:`${theme.primary}18`, borderRadius:'50%', border:`1px solid ${theme.primary}44` }}>
                <StepIcon size={18} color={theme.primary}/>
              </div>
            </div>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:4 }}>
                <p style={{ margin:0, fontSize:14, fontWeight:600, color:theme.primary }}>Derin Analiz Devam Ediyor</p>
                <span style={{ fontSize:11, color:theme.textMuted, fontFamily:theme.mono }}>{elapsed}s</span>
              </div>
              <AnimatePresence mode="wait">
                <motion.p
                  key={activeStep.label}
                  initial={{ opacity:0, y:4 }}
                  animate={{ opacity:1, y:0 }}
                  exit={{ opacity:0, y:-4 }}
                  transition={{ duration:0.25 }}
                  style={{ margin:'0 0 10px', fontSize:12, color:theme.textMuted }}
                >
                  {activeStep.label}
                </motion.p>
              </AnimatePresence>
              <div style={{ position:'relative', height:4, background:theme.border, borderRadius:2, overflow:'hidden' }}>
                <motion.div
                  animate={{ width:`${pct}%` }}
                  transition={{ duration:0.5 }}
                  style={{ height:'100%', background:theme.gradientPrimary, borderRadius:2 }}
                />
                <motion.div
                  animate={{ x:['-100%', '200%'] }}
                  transition={{ repeat:Infinity, duration:1.6, ease:'easeInOut' }}
                  style={{ position:'absolute', top:0, left:0, height:'100%', width:'40%', background:'linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent)', borderRadius:2 }}
                />
              </div>
            </div>
          </motion.div>
        )
      })()}
    </AnimatePresence>

    {showRetryButton && !analyzing && (
      <div style={{ display:'flex', justifyContent:'center', margin:'0 auto 20px' }}>
        <motion.button
          onClick={() => handleCheck(true)}
          style={{
            padding:'10px 18px',
            borderRadius:theme.radiusMd,
            border:`1px solid ${theme.warning}`,
            background:'rgba(245,158,11,0.12)',
            color:theme.warning,
            fontWeight:600,
            cursor:'pointer'
          }}
        >
          Yeniden Tara
        </motion.button>
      </div>
    )}

    {/* Result Display — show immediately even during deep analysis */}
    {result && <PhishingResult result={result} url={url} />}

    {/* Stats Grid */}
    <motion.div 
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.5, duration:0.6, ease:theme.ease.out }}
      style={{ display:'grid', gridTemplateColumns:'repeat(4, 1fr)', gap:20, marginBottom:48 }}
    >
      {[
        { label:'Toplam URL', value:totalUrls, color:theme.primary },
        { label:'Phishing', value:phCount, color:theme.danger },
        { label:'Guvenli', value:safeCount, color:theme.success },
        { label:'Bugun Taranan', value:stats?.stats?.today_scans||0, color:theme.warning }
      ].map((stat, i) => (
        <motion.div
          key={i}
          initial={{ opacity:0, y:20 }}
          animate={{ opacity:1, y:0 }}
          transition={{ delay:0.6 + i * 0.1, duration:0.5, ease:theme.ease.spring }}
        >
          <Card style={{ 
            textAlign:'center', 
            padding:'32px 20px',
            background:'rgba(255,255,255,0.03)',
            border:`1px solid ${theme.border}`
          }}>
            <p style={{ fontSize:11, color:theme.textMuted, fontWeight:600, marginBottom:12 }}>{stat.label}</p>
            <p style={{ fontSize:30, fontWeight:600, color:stat.color }}><CountUp end={stat.value}/></p>
          </Card>
        </motion.div>
      ))}
    </motion.div>
    {/* Latest Phishing Data Table */}
    <motion.div
      initial={{ opacity:0, y:20 }}
      animate={{ opacity:1, y:0 }}
      transition={{ delay:0.7, duration:0.5, ease:theme.ease.out }}
    >
      <Card>
        <h3 style={{ fontSize:15, fontWeight:600, color:'#fff', marginBottom:16, display:'flex', gap:8, alignItems:'center' }}>
           Son Phishing Verileri
          <span style={{ fontSize:11, color:theme.textMuted, fontWeight:400, marginLeft:'auto' }}>{latestTotal.toLocaleString('tr-TR')} kayıt • {totalPages} sayfa</span>
        </h3>
        <div style={{ overflowX:'auto', maxHeight:500, overflowY:'auto' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead style={{ position:'sticky', top:0, background:theme.surface2, zIndex:1 }}>
              <tr style={{ borderBottom:`2px solid ${theme.border}`, color:theme.textMuted, fontSize:10 }}>
                <th style={{ textAlign:'left', padding:'12px 8px' }}>URL</th>
                <th style={{ textAlign:'left', padding:'12px 8px' }}>Domain</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Hedef</th>
                <th style={{ textAlign:'center', padding:'12px 8px' }}>Durum</th>
                <th style={{ textAlign:'right', padding:'12px 8px' }}>Tarih</th>
              </tr>
            </thead>
            <tbody>
              {latestFeeds.length===0&&<tr><td colSpan={5} style={{ textAlign:'center', padding:24, color:theme.textMuted }}>{loadingLatest?'Veri yukleniyor...':'Kayit bulunamadi'}</td></tr>}
              {latestFeeds.map((item,i)=>(
                <motion.tr 
                  key={item.id||i}
                  initial={{ opacity:0, y:10 }}
                  animate={{ opacity:1, y:0 }}
                  transition={{ delay:0.8 + i * 0.02, duration:0.3, ease:theme.ease.out }}
                  style={{ borderBottom:`1px solid ${theme.border}`, cursor:'pointer' }}
                  onClick={()=>{setUrl(item.url ?? '');handleCheck(false, item.url ?? null)}}
                >
                  <td style={{ padding:'10px 8px', maxWidth:300, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}><span style={{ color:theme.text, fontSize:12, fontFamily:theme.mono }}>{item.url}</span></td>
                  <td style={{ padding:'10px 8px' }}><span style={{ color:theme.primary, fontSize:12 }}>{item.domain||'-'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ padding:'4px 10px', borderRadius:'10px', fontSize:10, background:theme.accentDim, color:theme.accent }}>{item.target||'Phishing'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'center' }}><span style={{ display:'flex', alignItems:'center', justifyContent:'center', gap:4, fontSize:12 }}><StatusDot active={normalizeStatus(item.status)}/>{item.status||'Bilinmiyor'}</span></td>
                  <td style={{ padding:'10px 8px', textAlign:'right', color:theme.textMuted, fontSize:10 }}>{item.submission_time?new Date(item.submission_time).toLocaleDateString('tr-TR'):item.created_at?new Date(item.created_at).toLocaleDateString('tr-TR'):'-'}</td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages>1&&<div style={{ display:'flex', justifyContent:'center', gap:8, marginTop:20 }}>
          <motion.button 
            onClick={()=>loadLatest(pageNum-1)} 
            disabled={pageNum<=1||loadingLatest}
            style={{ 
              padding:'8px 16px', 
              borderRadius:theme.radiusSm, 
              border:`1px solid ${theme.border}`, 
              background:theme.surface, 
              color:pageNum<=1?theme.textMuted:'#fff', 
              cursor:pageNum<=1?'not-allowed':'pointer', 
              fontSize:13, 
              fontWeight:600,
              opacity:pageNum<=1?0.5:1
            }}
          >
            ← Onceki
          </motion.button>
          <span style={{ padding:'8px 16px', color:theme.textMuted, fontSize:13 }}>Sayfa {pageNum} / {totalPages}</span>
          <motion.button 
            onClick={()=>loadLatest(pageNum+1)} 
            disabled={pageNum>=totalPages||loadingLatest}
            style={{ 
              padding:'8px 16px', 
              borderRadius:theme.radiusSm, 
              border:`1px solid ${theme.border}`, 
              background:theme.surface, 
              color:pageNum>=totalPages?theme.textMuted:'#fff', 
              cursor:pageNum>=totalPages?'not-allowed':'pointer', 
              fontSize:13, 
              fontWeight:600,
              opacity:pageNum>=totalPages?0.5:1
            }}
          >
            Sonraki →
          </motion.button>
        </div>}
      </Card>
    </motion.div>
  </div>
}
export default PhishingDetector
