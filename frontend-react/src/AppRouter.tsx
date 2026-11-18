import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Navigate, Routes, Route, Outlet, NavLink, useNavigate } from 'react-router-dom'
import api from './lib/api'
import useAuthStore from './stores/authStore'
import PrivateRoute from './components/PrivateRoute'

const Modules=lazy(()=>import('./ModulesApp'))
const Analyze=lazy(()=>import('./pages/AnalyzePage'))
const Login=lazy(()=>import('./pages/LoginPage'))
const Dashboard=lazy(()=>import('./pages/WorkspacePage'))
const Admin=lazy(()=>import('./pages/AdminPage'))
const Settings=lazy(()=>import('./pages/SettingsPage'))
const Crawler=lazy(()=>import('./pages/CrawlerPage'))
const Recovery=lazy(()=>import('./pages/RecoveryPage'))

function SessionBootstrap() {
  useEffect(()=>{
    localStorage.removeItem('aegis-auth')
    api.get('/auth/me').then(r=>useAuthStore.getState().setAuth(r.data)).catch(()=>useAuthStore.getState().logout())
  },[])
  return null
}
function AccountLayout(){
  const nav=useNavigate()
  const {email,role}=useAuthStore()
  const logout=async()=>{try{await api.post('/auth/logout')}finally{useAuthStore.getState().logout();nav('/login')}}
  return <div className="account-layout"><nav className="account-nav" aria-label="Hesap gezinmesi">
    <NavLink to="/">Ana Sayfa</NavLink><NavLink to="/analyze">Analiz</NavLink><NavLink to="/modules">Modüller</NavLink>
    <NavLink to="/dashboard">Vakalarım</NavLink><NavLink to="/settings">Ayarlar</NavLink>
    {role==='admin'&&<><NavLink to="/crawler">Keşif</NavLink><NavLink to="/admin">Yönetim</NavLink></>}
    {email?<button className="action-button" onClick={logout}>Çıkış</button>:<NavLink to="/login">Giriş</NavLink>}
  </nav><Outlet/></div>
}
export default function AppRouter(){ return <BrowserRouter><SessionBootstrap/>
  <Suspense fallback={<p role="status" style={{padding:40}}>Yükleniyor…</p>}><Routes>
    {/* Tek arayüz: uygulama doğrudan modül çalışma alanına açılır. */}
    <Route path="/" element={<Navigate to="/modules/phishing" replace/>}/>
    <Route path="/crawler" element={<PrivateRoute roles={['admin']}><Crawler/></PrivateRoute>}/>
    <Route path="/modules/:module?" element={<Modules/>}/>
    <Route element={<AccountLayout/>}>
      <Route path="/login" element={<Login/>}/><Route path="/recovery" element={<Recovery/>}/>
      <Route path="/analyze" element={<Analyze/>}/>
            <Route path="/dashboard" element={<PrivateRoute><Dashboard/></PrivateRoute>}/>
      <Route path="/settings" element={<PrivateRoute><Settings/></PrivateRoute>}/>
      <Route path="/admin" element={<PrivateRoute roles={['admin']}><Admin/></PrivateRoute>}/>
    </Route>
    <Route path="*" element={<div className="account-layout"><h1>Sayfa bulunamadı</h1><NavLink to="/">Ana sayfaya dön</NavLink></div>}/>
  </Routes></Suspense></BrowserRouter> }
