import { create } from 'zustand'
import type { Role } from '../lib/types'

interface AuthPayload {
  role: Role | null
  email: string | null
  fullName?: string | null
  full_name?: string | null
}

interface AuthState {
  role: Role | null
  email: string | null
  fullName: string | null
  ready: boolean
  setAuth: (payload: AuthPayload) => void
  logout: () => void
  isAuthenticated: () => boolean
  isAdmin: () => boolean
}

// Credentials live only in the server's HttpOnly cookie, never in browser storage.
const useAuthStore = create<AuthState>((set, get) => ({
  role: null, email: null, fullName: null, ready: false,
  setAuth: ({ role, email, fullName, full_name }) => set({ role, email, fullName: fullName || full_name || '', ready: true }),
  logout: () => set({ role: null, email: null, fullName: null, ready: true }),
  isAuthenticated: () => !!get().email,
  isAdmin: () => get().role === 'admin',
}))
export default useAuthStore
