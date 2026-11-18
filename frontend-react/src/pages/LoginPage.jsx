import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import { theme } from '../theme'
import { Shield } from 'lucide-react'
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
      minHeight: '100vh', background: theme.bg,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24,
    }}>
      <motion.div
        initial={{ opacity: 0, y: 16, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
        style={{
          width: '100%', maxWidth: 420,
          background: theme.gradientSurface,
          border: `1px solid ${theme.border}`,
          borderRadius: theme.radius.lg,
          padding: 32,
        }}
      >
        <h1 style={{ fontSize: 24, fontWeight: 700, color: theme.text, margin: '0 0 8px', textAlign: 'center' }}>
          <Shield size={20} style={{marginRight:6}}/> AegisNexus
        </h1>
        <p style={{ color: theme.textMuted, fontSize: 14, margin: '0 0 24px', textAlign: 'center' }}>
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
              <span style={{ color: theme.textMuted, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Email</span>
              <input
                type="email" value={email} onChange={e => setEmail(e.target.value)} required
                placeholder="ornek@email.com"
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: theme.surface, border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.sm, color: theme.text, fontSize: 14, outline: 'none',
                }}
              />
            </label>
            <label style={{ display: 'block', marginBottom: 20 }}>
              <span style={{ color: theme.textMuted, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Ad Soyad</span>
              <input
                type="text" value={fullName} onChange={e => setFullName(e.target.value)}
                placeholder="Ad Soyad"
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: theme.surface, border: `1px solid ${theme.border}`,
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
              <span style={{ color: theme.textMuted, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Email</span>
              <input
                type="email" value={email} onChange={e => setEmail(e.target.value)} required
                placeholder="ornek@email.com"
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: theme.surface, border: `1px solid ${theme.border}`,
                  borderRadius: theme.radius.sm, color: theme.text, fontSize: 14, outline: 'none',
                }}
              />
            </label>
            <label style={{ display: 'block', marginBottom: 20 }}>
              <span style={{ color: theme.textMuted, fontSize: 12, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>API Key</span>
              <input
                type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} required
                placeholder="aeg_..."
                style={{
                  width: '100%', padding: '10px 14px', marginTop: 6,
                  background: theme.surface, border: `1px solid ${theme.border}`,
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
        <p style={{marginTop:20}}><Link to="/recovery" style={{color:theme.primary}}>Anahtarımı kaybettim</Link></p>
      </motion.div>
    </div>
  )
}
