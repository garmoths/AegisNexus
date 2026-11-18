import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../lib/api'
import { Skeleton } from '../components/ui/skeleton'

export default function WorkspacePage(){
  const [reports,setReports]=useState([])
  const [selected,setSelected]=useState(null)
  const [error,setError]=useState('')
  const [loading,setLoading]=useState(true)
  const [notifications,setNotifications]=useState([])
  const load=useCallback(()=>Promise.all([api.get('/reports/'),api.get('/notifications')])
    .then(([a,b])=>{setReports(a.data.data);setNotifications(b.data.data)})
    .catch(e=>setError(e.response?.data?.detail||'Kayıtlar yüklenemedi.'))
    .finally(()=>setLoading(false)),[])
  useEffect(()=>{void load()},[load])
  const update=async(patch)=>{
    try{const {data}=await api.patch('/reports/'+selected.id,patch);setSelected(data);setReports(v=>v.map(r=>r.id===data.id?data:r))}
    catch(e){setError(e.response?.data?.detail||'Güncelleme başarısız.')}
  }
  const download=async(id)=>{
    try{const response=await api.get('/reports/'+id+'/pdf',{responseType:'blob'});const url=URL.createObjectURL(response.data);const a=document.createElement('a');a.href=url;a.download='rapor_'+id+'.pdf';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
    catch(e){const payload=e.response?.data instanceof Blob?await e.response.data.text():'';try{setError(JSON.parse(payload).detail)}catch{setError('PDF indirilemedi.')}}
  }
  return <section><div className="workspace-row"><h1>Vakalarım ve aksiyonlarım</h1><Link to="/analyze">Yeni analiz →</Link></div>
    {error&&<p role="alert" className="error-message">{error}</p>}
    {notifications.filter(n=>!n.read_at).map(n=><article className="workspace-card" key={n.id}><h3>{n.title}</h3><p>{n.detail?.value} · Risk: {n.detail?.risk_score}</p><button onClick={async()=>{await api.patch('/notifications/'+n.id);void load()}}>Okundu</button></article>)}
    {loading?<div role="status" aria-label="Vakalar yükleniyor" className="workspace-card"><Skeleton className="h-5 w-1/3"/><Skeleton className="mt-3 h-4 w-full"/><Skeleton className="mt-2 h-4 w-2/3"/></div>:(reports.length===0&&!error)?<div className="workspace-card"><h2>Henüz bir vakanız yok</h2><p>Bir şüpheli içeriği analiz ederek kişisel aksiyon listenizi oluşturun.</p><Link to="/analyze">Analize başla</Link></div>:null}
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(min(100%,300px),1fr))',gap:18}}>
      <div>{reports.map(r=><article key={r.id} className="workspace-card"><p>#{r.id} · {r.status} · {r.created_at?new Date(r.created_at).toLocaleDateString('tr-TR'):''}</p><h2 style={{margin:'12px 0'}}>{r.attack_type||'Olay analizi'}</h2><p>{r.user_description.slice(0,180)}</p><button style={{marginTop:12}} onClick={()=>setSelected(r)}>Aksiyonları aç</button></article>)}</div>
      {selected&&<article className="workspace-card"><h2>Vaka #{selected.id}</h2><p style={{margin:'12px 0',whiteSpace:'pre-wrap'}}>{selected.user_description}</p>
        <label>Durum <select value={selected.status} onChange={e=>update({status:e.target.value,completed_steps:selected.action_steps.map((s,i)=>s.done?i:-1).filter(i=>i>=0)})}><option value="open">Açık</option><option value="in_progress">Üzerinde çalışılıyor</option><option value="resolved">Tamamlandı</option></select></label>
        {(selected.action_steps||[]).map((s,i)=><label key={i} style={{display:'flex',gap:12,alignItems:'start'}}><input type="checkbox" checked={s.done} onChange={e=>update({status:selected.status,completed_steps:selected.action_steps.map((step,j)=>(j===i?e.target.checked:step.done)?j:-1).filter(j=>j>=0)})}/>{s.text}</label>)}
        <button onClick={()=>download(selected.id)}>PDF indir</button><p style={{fontSize:13,marginTop:12}}>Ücretsiz planda ayda 3 farklı PDF. Aynı PDF’yi yeniden indirmek ek kota tüketmez.</p>
      </article>}
    </div>
  </section>
}
