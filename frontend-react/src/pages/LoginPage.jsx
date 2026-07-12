import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
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

  const handleRegister = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')
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
    }
  }

  const handleLogin = async (e) => {
    e.preventDefault()
    setError('')
    try {
      const res = await authAPI.login(email, apiKey)
      const data = res.data
      setAuth({
        apiKey,
        role: data.role,
        email: data.email || email,
        fullName: data.full_name || '',
      })
      nav('/dashboard')
    } catch (err) {
      setError(err.response?.data?.detail || 'Giriş sırasında hata oluştu.')
    }
  }

  return (
    <div style={{
      minHeight: '100vh', background: theme.bg,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: 24,
    }}>
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
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
          Siber Mağduriyet Atlası
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
              onClick={() => { setMode(m); setError(''); setSuccess('') }}
              style={{
                flex: 1, padding: '8px 0',
                background: mode === m ? theme.gradientPrimary : 'transparent',
                color: mode === m ? theme.bgDeep : theme.textMuted,
                border: 'none', borderRadius: theme.radius.sm,
                fontWeight: 600, fontSize: 13, cursor: 'pointer',
                transition: 'all 0.2s',
              }}
            >
              {m === 'login' ? 'Giriş' : 'Kayıt'}
            </button>
          ))}
        </div>

        {error && (
          <div style={{
            padding: 12, marginBottom: 16,
            background: `${theme.danger}12`, border: `1px solid ${theme.danger}30`,
            borderRadius: theme.radius.sm, color: theme.danger, fontSize: 13,
          }}>{error}</div>
        )}

        {success && (
          <div style={{
            padding: 12, marginBottom: 16,
            background: `${theme.success}12`, border: `1px solid ${theme.success}30`,
            borderRadius: theme.radius.sm, color: theme.success, fontSize: 13,
            wordBreak: 'break-all',
          }}>{success}</div>
        )}

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
            <button type="submit" style={{
              width: '100%', padding: '12px',
              background: theme.gradientPrimary, color: theme.bgDeep,
              fontWeight: 700, border: 'none', borderRadius: theme.radius.sm,
              cursor: 'pointer', fontSize: 14,
            }}>
              Kayıt Ol & API Key Al
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
            <button type="submit" style={{
              width: '100%', padding: '12px',
              background: theme.gradientPrimary, color: theme.bgDeep,
              fontWeight: 700, border: 'none', borderRadius: theme.radius.sm,
              cursor: 'pointer', fontSize: 14,
            }}>
              Giriş Yap
            </button>
          </form>
        )}
      </motion.div>
    </div>
  )
}
