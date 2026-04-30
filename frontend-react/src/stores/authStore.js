import { create } from 'zustand'
import { persist } from 'zustand/middleware'

const useAuthStore = create(
  persist(
    (set, get) => ({
      apiKey: null,
      role: null,
      email: null,
      fullName: null,

      setAuth: ({ apiKey, role, email, fullName }) =>
        set({ apiKey, role, email, fullName }),

      logout: () =>
        set({ apiKey: null, role: null, email: null, fullName: null }),

      isAuthenticated: () => !!get().apiKey,

      isPremium: () => ['premium', 'corporate', 'admin'].includes(get().role),
      isCorporate: () => ['corporate', 'admin'].includes(get().role),
      isAdmin: () => get().role === 'admin',
    }),
    { name: 'aegis-auth' }
  )
)

export default useAuthStore
