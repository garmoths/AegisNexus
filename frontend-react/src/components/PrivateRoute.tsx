import type { ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import type { Role } from '../lib/types'
import useAuthStore from '../stores/authStore'

export default function PrivateRoute({ children, roles }: { children: ReactNode; roles?: Role[] }) {
  const { isAuthenticated, role, ready } = useAuthStore()
  if (!ready) return <p role="status">Oturum kontrol ediliyor…</p>

  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />
  }

  if (roles && (!role || !roles.includes(role))) {
    return <Navigate to="/" replace />
  }

  return children
}
