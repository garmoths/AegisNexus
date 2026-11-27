import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Link, useParams } from 'react-router-dom'
import api from '../lib/api'
import useAuthStore from '../stores/authStore'

type Mode = 'auto' | 'url' | 'sms' | 'email' | 'incident'

/** Union of the result shapes this page renders (URL scan, SMS, e-mail AI, incident report). */
interface AnalysisResult {
  id?: number
  status?: string
  job_id?: string
  risk_score?: number | null
  risk_level?: string
  category?: string
  attack_type?: string | null
  explanation?: string
  summary?: string
  protection_plan?: string | null
  details?: string[]
  indicators?: string[]
  security_assessment?: { score?: number; overall_risk_score?: number; threat_level?: string }
}

function errorText(error: unknown): string {
  const detail = (error as { response?: { data?: { detail?: unknown } } }).response?.data?.detail
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((item: { msg?: string }) => item.msg || 'Geçersiz alan').join(' · ')
  return (error instanceof Error && error.message) || 'İşlem tamamlanamadı.'
}

function detect(text: string): Exclude<Mode, 'auto'> {
  if (/^(https?:\/\/|www\.)\S+$/i.test(text.trim()) || /^[\w.-]+\.[a-z]{2,}(\/\S*)?$/i.test(text.trim())) return 'url'
  if (/^(from|subject|to):/im.test(text)) return 'email'
  return text.length<=1600?'sms':'incident'
}
export default function AnalyzePage({ onNavigate }: { onNavigate?: (module: string) => void } = {}){
  // Modül kabuğunun içinde (onNavigate verilir) başlığı kabuk gösterir.
  const embedded = typeof onNavigate === 'function'
  const {module}=useParams()
  const [mode,setMode]=useState<Mode>(module==='sms'?'sms':'auto')
  const [text,setText]=useState('')
  const [result,setResult]=useState<AnalysisResult | null>(null)
  const [error,setError]=useState('')
  const [busy,setBusy]=useState(false)
  const [job,setJob]=useState<string | null>(null)
  const [reason,setReason]=useState('')
  const [feedback,setFeedback]=useState('')
  const generation=useRef(0)
  const email=useAuthStore(s=>s.email)
  const resetAnalysis=()=>{
    generation.current+=1
    setResult(null);setError('');setJob(null);setBusy(false);setFeedback('');setReason('')
  }
  useEffect(()=>()=>{generation.current+=1},[])

  useEffect(()=>{
    if(!job)return
    let cancelled=false
    const current=generation.current
    const started=Date.now()
    let timer: ReturnType<typeof setTimeout> | undefined
    const poll=async()=>{
      try{
        const {data}=await api.get<AnalysisResult>('/phishing/result/'+job)
        if(cancelled||current!==generation.current)return
        if(data.status==='complete'){setResult(data);setJob(null);setBusy(false);return}
        if(['failed','error','timeout','expired'].includes(data.status ?? ''))throw new Error('Analiz tamamlanamadı. Bu bir güvenlik kararı değildir.')
        if(Date.now()-started>930000)throw new Error('Analiz bekleme süresi doldu.')
        timer=setTimeout(poll,3000)
      }catch(e){if(!cancelled&&current===generation.current){setError(errorText(e));setBusy(false);setJob(null)}}
    }
    timer=setTimeout(poll,1500)
    return ()=>{cancelled=true;clearTimeout(timer)}
  },[job])
  const analyze=async (e: FormEvent) => {
    e.preventDefault()
    const current=++generation.current
    setBusy(true);setError('');setResult(null);setFeedback('');setJob(null)
    const selected=mode==='auto'?detect(text):mode
    try{
      let data: AnalysisResult
      if(selected==='url')({data}=await api.post('/phishing/check-url',{url:text.trim()}))
      else if(selected==='sms')({data}=await api.post('/sms/analyze',{text}))
      else if(selected==='email')({data}=await api.post('/ai-analyzer/analyze',{message:text,message_type:'email'}))
      else ({data}=await api.post('/reports/analyze',{description:text}))
      if(current!==generation.current)return
      if(data.status==='analyzing'){setJob(data.job_id ?? null);return}
      setResult(data)
    }catch(e){if(current===generation.current)setError(errorText(e))}
    if(current===generation.current)setBusy(false)
  }
  const risk=result?.risk_score ?? result?.security_assessment?.score ?? result?.security_assessment?.overall_risk_score
  const uncertain=result && (result.status==='degraded'||result.status==='unknown')
  const save=async()=>{
    try{const {data}=await api.post<{ id: number }>('/reports/analyze',{description:text});setFeedback('Vaka kaydedildi: #'+data.id)}catch(e){setFeedback(errorText(e))}
  }
  const sendFeedback=async()=>{
    try{await api.post('/feedback',{report_id:result?.id||null,url:detect(text)==='url'?text.trim():null,expected_verdict:'uncertain',reason});setFeedback('Geri bildiriminiz inceleme kuyruğuna alındı.')}
    catch(e){setFeedback(errorText(e))}
  }
  return <section style={{maxWidth:850,margin:embedded?'0':'auto',padding:embedded?0:24}}>
    {!embedded && <><h1>Şüpheli içeriği kontrol et</h1><p style={{margin:'12px 0',color:'#a39a8f'}}>URL, SMS veya e-posta yapıştırın. Kararı, gerekçeyi ve sonraki adımı görün.</p></>}
    <form className="workspace-card" onSubmit={analyze}>
      <label>İçerik türü <select aria-label="İçerik türü" value={mode} onChange={e=>{resetAnalysis();setMode(e.target.value as Mode)}}><option value="auto">Otomatik algıla</option><option value="url">URL</option><option value="sms">SMS</option><option value="email">E-posta</option><option value="incident">Yaşadığım olay</option></select></label>
      <label htmlFor="analysis-input">İncelenecek içerik</label>
      <textarea id="analysis-input" rows={7} maxLength={20000} required value={text} onChange={e=>{resetAnalysis();setText(e.target.value)}} placeholder="Şüpheli bağlantı veya mesajı buraya yapıştırın…" style={{width:'100%'}}/>
      <p style={{margin:'12px 0',fontSize:13,color:'#a39a8f'}}>Parola, kart numarası ve doğrulama kodlarını paylaşmayın. Olay raporları için giriş gerekir.</p>
      <button disabled={busy||!text.trim()}>{busy?'Analiz sürüyor…':'Analiz et'}</button>
      {job&&<p role="status" style={{marginTop:12}}>Derin analiz kuyruğunda; sonucu bekliyoruz. Yeniden denemeler otomatik takip edilir.</p>}
      {error&&<p role="alert" className="error-message">{error}</p>}
    </form>
    {result&&<article className="workspace-card" aria-live="polite">
      <h2>{uncertain?'Kesin karar verilemiyor':result.risk_level||result.category||result.attack_type||result.security_assessment?.threat_level||'Analiz sonucu'}</h2>
      {risk!=null&&<p style={{margin:'12px 0'}}>Risk: <strong>{risk}/100</strong> · Yüksek puan daha yüksek risk demektir.</p>}
      <p>{result.explanation||result.summary||result.protection_plan}</p>
      {(result.details||result.indicators||[]).length>0&&<ul style={{paddingLeft:24,marginTop:12}}>{(result.details||result.indicators||[]).slice(0,5).map((d,i)=><li key={i}>{d}</li>)}</ul>}
      <h3 style={{marginTop:20}}>Şimdi ne yapmalıyım?</h3>
      <ol style={{paddingLeft:24,lineHeight:1.8}}><li>Kaynağı kurumun resmî uygulamasından veya bilinen numarasından doğrulayın.</li><li>Doğrulamadan bağlantıya bilgi girmeyin; mevcut oturumlarınızı kontrol edin.</li><li>Bilgi paylaştıysanız ilgili hesabı güvene alın ve olay kaydı oluşturun.</li></ol>
      {email?<div style={{marginTop:20}}><button onClick={save}>Vakalarıma kaydet</button>
        <label>Sonuçta hata mı var?<textarea value={reason} onChange={e=>setReason(e.target.value)} maxLength={2000} placeholder="Neden yanlış olduğunu açıklayın…"/></label>
        <button disabled={reason.length<5||(!result.id&&detect(text)!=='url')} onClick={sendFeedback}>İncelemeye gönder</button>
      </div>:<p style={{marginTop:20}}><Link to="/login">Giriş yaparak</Link> vaka oluşturabilir ve sonucu takip edebilirsiniz.</p>}
      {feedback&&<p role="status" style={{marginTop:12}}>{feedback}</p>}
    </article>}
  </section>
}
