import { Navigate } from 'react-router-dom'
import useAuthStore from '../stores/authStore'

export default function PrivateRoute({ children, roles }) {
  const { isAuthenticated, role } = useAuthStore()

  if (!isAuthenticated()) {
    return <Navigate to="/login" replace />
  }

  if (roles && !roles.includes(role)) {
    return <Navigate to="/" replace />
  }

  return children
}
