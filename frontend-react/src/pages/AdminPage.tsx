import { useEffect, useState } from 'react'
import { theme } from '../theme'
import { Settings, Users } from 'lucide-react'
import { adminAPI } from '../lib/endpoints'
import useAuthStore from '../stores/authStore'
import PrivateRoute from '../components/PrivateRoute'
import type { AdminUser, Role } from '../lib/types'
import OperationsPanel from '../components/OperationsPanel'

export default function AdminPage() {
  const [users, setUsers] = useState<AdminUser[]>([])
  const [error, setError] = useState('')
  const isAdmin = useAuthStore(s => s.isAdmin)

  useEffect(() => {
    if (isAdmin()) {
      adminAPI.users().then(r => setUsers(r.data?.data || [])).catch(() => setError('Kullanıcılar yüklenemedi.'))
    }
  }, [isAdmin])

  const handleRoleChange = async (userId: number, newRole: Role) => {
    try {
      await adminAPI.changeRole(userId, newRole)
      setUsers(prev => prev.map(u => u.id === userId ? { ...u, role: newRole } : u))
    } catch {
      setError('Rol değiştirilemedi.')
    }
  }

  return (
    <PrivateRoute roles={['admin']}>
      <div style={{ minHeight: '100vh', background: theme.bg }}>
        <section style={{
          background: theme.gradientHero,
          padding: '60px 24px 30px',
          textAlign: 'center',
        }}>
          <h1 style={{ fontSize: 36, fontWeight: 800, color: theme.text, margin: '0 0 8px' }}>
            <Settings size={28} style={{marginBottom:4}}/> Admin Paneli
          </h1>
          <p style={{ color: theme.textMuted, fontSize: 15, margin: 0 }}>
            Kullanıcı yönetimi ve sistem durumu
          </p>
        </section>

        <section style={{ maxWidth: 1000, margin: '0 auto', padding: '30px 24px' }}>
          <OperationsPanel/>
          {error&&<p role="alert" className="error-message">{error}</p>}
          {/* Users */}
          <div style={{
            background: theme.gradientSurface,
            border: `1px solid ${theme.border}`,
            borderRadius: theme.radius.lg, padding: 24,
          }}>
            <h2 style={{ color: theme.primary, fontSize: 18, fontWeight: 600, margin: '0 0 16px' }}>
              <span style={{display:'flex',alignItems:'center',gap:7}}><Users size={16}/> Kullanıcılar ({users.length})</span>
            </h2>

            <div style={{ overflowX: 'auto' }}>
              <table style={{
                width: '100%', borderCollapse: 'collapse',
                fontSize: 14,
              }}>
                <thead>
                  <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
                    {['ID', 'Email', 'Ad', 'Rol', 'Durum', 'İşlem'].map(h => (
                      <th key={h} style={{
                        padding: '10px 12px', textAlign: 'left',
                        color: theme.textMuted, fontWeight: 600,
                        fontSize: 12, textTransform: 'uppercase',
                        letterSpacing: '0.5px',
                      }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {users.map(u => (
                    <tr key={u.id} style={{ borderBottom: `1px solid ${theme.borderSoft}` }}>
                      <td style={{ padding: '10px 12px', color: theme.textSubtle, fontFamily: 'monospace' }}>{u.id}</td>
                      <td style={{ padding: '10px 12px', color: theme.text }}>{u.email}</td>
                      <td style={{ padding: '10px 12px', color: theme.text }}>{u.full_name}</td>
                      <td style={{ padding: '10px 12px' }}>
                        <select
                          value={u.role}
                          onChange={e => handleRoleChange(u.id, e.target.value as Role)}
                          style={{
                            padding: '4px 8px', background: theme.surface,
                            border: `1px solid ${theme.border}`, borderRadius: 4,
                            color: theme.text, fontSize: 13,
                          }}
                        >
                          {['free', 'premium', 'corporate', 'admin'].map(r => (
                            <option key={r} value={r}>{r}</option>
                          ))}
                        </select>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{
                          padding: '2px 8px', borderRadius: 4, fontSize: 12, fontWeight: 600,
                          color: u.is_active ? theme.success : theme.danger,
                          background: u.is_active ? `${theme.success}18` : `${theme.danger}18`,
                        }}>
                          {u.is_active ? 'Aktif' : 'Pasif'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span style={{ color: theme.textSubtle, fontSize: 12 }}>
                          {u.created_at ? new Date(u.created_at).toLocaleDateString('tr-TR') : '-'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      </div>
    </PrivateRoute>
  )
}
