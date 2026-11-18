import { useCallback, useEffect, useState } from 'react'
import api from '../lib/api'

export default function OperationsPanel(){
  const [data,setData]=useState(null),[feedback,setFeedback]=useState([]),[error,setError]=useState('')
  const load=useCallback(()=>Promise.all([api.get('/system/operations'),api.get('/admin/feedback')]).then(([a,b])=>{setData(a.data);setFeedback(b.data.data);setError('')}).catch(()=>setError('Operasyon verileri alınamadı.')),[])
  useEffect(()=>{void load();const timer=setInterval(load,30000);return()=>clearInterval(timer)},[load])
  const review=async(id,status)=>{const note=window.prompt('İnceleme gerekçesi (en az 5 karakter)');if(!note||note.length<5)return;try{await api.patch('/admin/feedback/'+id,{status,note});await load()}catch{setError('İnceleme kaydedilemedi.')}}
  return <section><article className="workspace-card"><h2>Sistem ve kaynak sağlığı</h2>{error&&<p role="alert">{error}</p>}
    {!data?(error?null:<p>Yükleniyor…</p>):<><p>Broker: {data.broker.available?'Bağlı':'Kullanılamıyor'} · Canlı worker: {data.workers.length} · Bekleyen kalıcı olay: {data.outbox_pending}</p>
      <div className="workspace-row" style={{marginTop:16}}>{Object.entries(data.broker.queues||{}).map(([queue,value])=><div key={queue}><strong>{queue}</strong><p>{value.waiting} bekleyen · {value.consumers} tüketici</p></div>)}</div>
      <p style={{marginTop:16}}>Son IOC gözlemi: {data.ioc_last_seen?new Date(data.ioc_last_seen).toLocaleString('tr-TR'):'Veri yok'}</p>
      <div style={{overflowX:'auto'}}><table style={{width:'100%',marginTop:16,textAlign:'left'}}><thead><tr><th>Görev</th><th>Durum</th><th>Son başarı</th></tr></thead><tbody>{Object.entries(data.tasks).map(([name,task])=><tr key={name}><td style={{padding:8,overflowWrap:'anywhere'}}>{name.replace('task:','')}</td><td>{task.state}</td><td>{task.last_success_at?new Date(task.last_success_at).toLocaleString('tr-TR'):'—'}</td></tr>)}</tbody></table></div>
    </>}
  </article><article className="workspace-card"><h2>Yanlış sonuç inceleme kuyruğu</h2>{feedback.length===0?<p>Bekleyen geri bildirim yok.</p>:feedback.map(r=><div key={r.id} style={{padding:'16px 0',borderBottom:'1px solid #3a342e'}}><strong>#{r.id} · {r.expected_verdict}</strong><p>{r.url||'Rapor #'+r.report_id}</p><p>{r.reason}</p><div className="workspace-row"><button onClick={()=>review(r.id,'resolved')}>İncelendi</button><button onClick={()=>review(r.id,'rejected')}>Reddet</button></div></div>)}</article></section>
}
