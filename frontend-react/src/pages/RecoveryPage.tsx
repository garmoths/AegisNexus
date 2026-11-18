import { useState, type FormEvent } from 'react'
import { Link } from 'react-router-dom'
import api, { errorMessage } from '../lib/api'
export default function RecoveryPage(){
  const [email,setEmail]=useState(''),[token,setToken]=useState(''),[message,setMessage]=useState(''),[key,setKey]=useState('')
  const request=async (e: FormEvent) => {e.preventDefault();try{const {data}=await api.post('/auth/recovery/request',{email});setMessage(data.message)}catch (e) {setMessage(errorMessage(e, 'İstek tamamlanamadı.'))}}
  const complete=async (e: FormEvent) => {e.preventDefault();try{const {data}=await api.post('/auth/recovery/complete',{token});setKey(data.api_key);setToken('');setMessage(data.message)}catch (e) {setMessage(errorMessage(e, 'Kod doğrulanamadı.'))}}
  return <section><h1>Hesap kurtarma</h1><form className="workspace-card" onSubmit={request}><label>Kayıtlı e-posta <input type="email" required value={email} onChange={e=>setEmail(e.target.value)}/></label><button>Kurtarma kodu gönder</button></form><form className="workspace-card" onSubmit={complete}><label>E-postadaki kod <input required minLength={32} value={token} onChange={e=>setToken(e.target.value)}/></label><button>Kodu doğrula</button></form>{message&&<p role="status">{message}</p>}{key&&<pre style={{overflowWrap:'anywhere',whiteSpace:'pre-wrap'}}>{key}</pre>}<Link to="/login">Girişe dön</Link></section>
}
