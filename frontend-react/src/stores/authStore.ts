import { create } from 'zustand'

// Credentials live only in the server's HttpOnly cookie, never in browser storage.
const useAuthStore = create((set, get) => ({
  role: null, email: null, fullName: null, ready: false,
  setAuth: ({role,email,fullName,full_name}) => set({role,email,fullName:fullName || full_name || '',ready:true}),
  logout: () => set({role:null,email:null,fullName:null,ready:true}),
  isAuthenticated: () => !!get().email,
  isAdmin: () => get().role === 'admin',
}))
export default useAuthStore
