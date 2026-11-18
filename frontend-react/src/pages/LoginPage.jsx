import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { theme } from '../theme'
import { ShieldCheck } from 'lucide-react'
import { BorderBeam } from '../components/ui/border-beam'
import { authAPI } from '../lib/endpoints'
import useAuthStore from '../stores/authStore'

export default function LoginPage() {
  const nav = useNavigate()
  const setAuth = useAuthStore(s => s.setAuth)
  const [mode, setMode] = useState('login') // login | register
  const [email, setEmail] = useState('')
  const [apiKey, setApiKey] = useState('')
  const [fullName, setFullName] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [busy, setBusy] = useState(false)

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setBusy(true)
    try {
      const res = await authAPI.register(email, fullName)
      const data = res.data
      if (data.api_key) {
        setSuccess(`API key oluşturuldu: ${data.api_key} — Bu anahtarı kaydedin!`)
        setApiKey(data.api_key)
        setMode('login')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Kayıt sırasında hata oluştu.')
    } finally {
      setBusy(false)
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    setBusy(true)
    try {
      const res = await authAPI.login(email, apiKey)
      const data = res.data
      setAuth({
        role: data.role,
        email: data.email || email,
        fullName: data.full_name || '',
      })
      setApiKey('')
      nav('/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Giriş sırasında hata oluştu.')
      setBusy(false)
    }
  }

  return (
    <div style={{
      minHeight: 'calc(100vh - 120px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24,
    }}>
      <motion.div
        initial={{ opacity: 0, y: 16, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
        className="panel panel-corners"
        style={{
          width: '100%', maxWidth: 440,
          borderRadius: theme.radius.lg,
          padding: 36,
          boxShadow: '0 40px 120px -50px rgba(92,225,230,0.45)',
        }}
      >
        <BorderBeam size={140} duration={10} colorFrom="#5ce1e6" colorTo="#2563eb" />
        <div style={{ display: 'grid', placeItems: 'center', width: 52, height: 52, margin: '0 auto 18px', borderRadius: 14,
          border: `1px solid ${theme.primary}55`, background: theme.primaryDim, boxShadow: theme.glow }}>
          <ShieldCheck size={24} color={theme.primary} />
        </div>
        <p className="eyebrow" style={{ textAlign: 'center' }}>Güvenli erişim</p>
        <h1 style={{ fontSize: 28, fontWeight: 600, color: theme.text, margin: '10px 0 8px', textAlign: 'center' }}>
          AegisNexus
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 14, margin: '0 0 28px', textAlign: 'center' }}>
          Phishing keşif ve analiz platformu
        </p>

        {/* Mode toggle */}
        <div style={{
          display: 'flex', marginBottom: 24,
          background: theme.surface, borderRadius: theme.radius.sm,
          padding: 3,
        }}>
          {['login', 'register'].map(m => (
            <button
              key={m}
              type="button"
              onClick={() => { setMode(m); setError(''); setSuccess('') }}
              style={{
                flex: 1, padding: '8px 0', position: 'relative',
                background: 'transparent',
                color: mode === m ? theme.bgDeep : theme.textMuted,
                border: 'none', borderRadius: theme.radius.sm,
                fontWeight: 600, fontSize: 13, cursor: 'pointer',
                transition: 'color 0.2s',
              }}
            >
              {mode === m && <motion.span layoutId="login-mode-pill" transition={{ type: 'spring', stiffness: 500, damping: 38 }} style={{ position: 'absolute', inset: 0, background: theme.gradientPrimary, borderRadius: theme.radius.sm }} />}
              <span style={{ position: 'relative' }}>{m === 'login' ? 'Giriş' : 'Kayıt'}</span>
            </button>
          ))}
        </div>

        <AnimatePresence initial={false}>
        {error && (
          <motion.div key="err" role="alert" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}><div style={{
            padding: 12, marginBottom: 16,
            background: `${theme.danger}12`, border: `1px solid ${theme.danger}30`,
            borderRadius: theme.radius.sm, color: theme.danger, fontSize: 13,
          }}>{error}</div></motion.div>
        )}

        {success && (
          <motion.div key="ok" role="status" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ overflow: 'hidden' }}><div style={{
            padding: 12, marginBottom: 16,
            background: `${theme.success}12`, border: `1px solid ${theme.success}30`,
            borderRadius: theme.radius.sm, color: theme.success, fontSize: 13,
            wordBreak: 'break-all',
          }}>{success}</div></motion.div>
        )}
        </AnimatePresence>

        {mode === 'register' ? (
          <form onSubmit={handleRegister}>
            <label style={{ display: 'block', marginBottom: 16 }}>
              <span style={{ color: theme.textMuted, fontSize: 10.5, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.16em', fontFamily: theme.mono }}>Email</span>
              <input
                type="email" value={email} onChange={e => setEmail(e.target.value)} required
                placeholder="ornek@email.com"
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: 'rgba(5,7,10,0.6)', border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.sm, color: theme.text, fontSize: 14, outline: 'none',
                }}
              />
            </label>
            <label style={{ display: 'block', marginBottom: 20 }}>
              <span style={{ color: theme.textMuted, fontSize: 10.5, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.16em', fontFamily: theme.mono }}>Ad Soyad</span>
              <input
                type="text" value={fullName} onChange={e => setFullName(e.target.value)}
                placeholder="Ad Soyad"
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: 'rgba(5,7,10,0.6)', border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.sm, color: theme.text, fontSize: 14, outline: 'none',
                }}
              />
            </label>
            <button type="submit" disabled={busy} className="press" style={{
              width: '100%', padding: '12px',
              background: theme.gradientPrimary, color: theme.bgDeep,
              fontWeight: 700, border: 'none', borderRadius: theme.radius.sm,
              cursor: 'pointer', fontSize: 14,
            }}>
              {busy ? 'Kaydediliyor…' : 'Kayıt Ol & API Key Al'}
            </button>
          </form>
        ) : (
          <form onSubmit={handleLogin}>
            <label style={{ display: 'block', marginBottom: 16 }}>
              <span style={{ color: theme.textMuted, fontSize: 10.5, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.16em', fontFamily: theme.mono }}>Email</span>
              <input
                type="email" value={email} onChange={e => setEmail(e.target.value)} required
                placeholder="ornek@email.com"
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: 'rgba(5,7,10,0.6)', border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.sm, color: theme.text, fontSize: 14, outline: 'none',
                }}
              />
            </label>
            <label style={{ display: 'block', marginBottom: 20 }}>
              <span style={{ color: theme.textMuted, fontSize: 10.5, fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.16em', fontFamily: theme.mono }}>API Key</span>
              <input
                type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} required
                placeholder="aeg_..."
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: 'rgba(5,7,10,0.6)', border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.sm, color: theme.text, fontSize: 14, outline: 'none',
                  fontFamily: 'monospace',
                }}
              />
            </label>
            <button type="submit" disabled={busy} className="press" style={{
              width: '100%', padding: '12px',
              background: theme.gradientPrimary, color: theme.bgDeep,
              fontWeight: 700, border: 'none', borderRadius: theme.radius.sm,
              cursor: 'pointer', fontSize: 14,
            }}>
              {busy ? 'Giriş yapılıyor…' : 'Giriş Yap'}
            </button>
          </form>
        )}
        <p style={{marginTop:22,textAlign:'center',fontSize:13}}><Link to="/recovery" style={{color:theme.primary,textDecoration:'none'}}>Anahtarımı kaybettim →</Link></p>
      </motion.div>
    </div>
  )
}
