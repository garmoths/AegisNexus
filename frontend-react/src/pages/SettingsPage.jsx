import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import api from '../lib/api'
import useAuthStore from '../stores/authStore'

export default function SettingsPage(){
  const [items,setItems]=useState([])
  const kind='domain'
  const [value,setValue]=useState('')
  const [message,setMessage]=useState('')
  const [newKey,setNewKey]=useState('')
  const {email}=useAuthStore()
  const load=useCallback(()=>api.get('/watchlist').then(r=>setItems(r.data.data)).catch(()=>setMessage('Takip listesi yüklenemedi.')),[])
  useEffect(()=>{void load()},[load])
  const add=async(e)=>{e.preventDefault();try{await api.post('/watchlist',{kind,value});setValue('');await load();setMessage('Takibe eklendi. İlk kontrol bir sonraki saatlik çalışmada yapılır.')}catch(e){setMessage(e.response?.data?.detail||'Takip eklenemedi.')}}
  const rotate=async()=>{try{const {data}=await api.post('/auth/rotate-key');setNewKey(data.new_api_key)}catch(e){setMessage(e.response?.data?.detail||'Anahtar yenilenemedi.')}}
  return <section><h1>Hesap ve takip ayarları</h1><p>{email}</p>
    <form className="workspace-card" onSubmit={add}><h2>Takip listesi</h2><p>Yalnızca yeni veya değişen sonuçlarda panel bildirimi oluşturulur. Kaynak kullanılamıyorsa güvenli sonucu üretilmez.</p>
      <div className="workspace-row" style={{marginTop:16}}><input aria-label="Takip edilecek gösterge" value={value} onChange={e=>setValue(e.target.value)} required maxLength={255}/><button>Takibe ekle</button></div>
      {items.map(item=><article key={item.id} style={{marginTop:16,padding:12,border:'1px solid #3a342e',borderRadius:8}}><strong>{item.value}</strong><p>{item.last_error?'Kaynak kullanılamıyor':item.last_result?'Risk: '+item.last_result.risk_score+'/100':'İlk kontrol bekleniyor'}</p><p>{item.last_checked_at?'Son kontrol: '+new Date(item.last_checked_at).toLocaleString('tr-TR'):''}</p><button type="button" onClick={async()=>{await api.delete('/watchlist/'+item.id);await load()}}>Takibi kaldır</button></article>)}
    </form>
    <article className="workspace-card"><h2>API anahtarı</h2><p>Tarayıcı oturumu HttpOnly çerez kullanır. API anahtarınız tarayıcı depolamasında saklanmaz.</p><p style={{margin:'12px 0'}}>Yenileme eski anahtarı ve ona bağlı oturumları iptal eder. Yeni anahtarı bir kez kopyalayıp güvenli yerde saklayın.</p><button onClick={rotate}>Anahtarı yenile</button>{newKey&&<><pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',marginTop:16}}>{newKey}</pre><Link to="/login">Yeni anahtarla giriş yap</Link></>}</article>
    {message&&<p role="status">{message}</p>}
  </section>
}
