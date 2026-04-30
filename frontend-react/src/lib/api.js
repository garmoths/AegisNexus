import axios from 'axios'
import useAuthStore from '../stores/authStore'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '/api/v2',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// Request interceptor — API key ekle
api.interceptors.request.use((config) => {
  const { apiKey } = useAuthStore.getState()
  if (apiKey) {
    config.headers['X-API-Key'] = apiKey
  }
  return config
})

// Response interceptor — 401'de logout
api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.status === 401) {
      useAuthStore.getState().logout()
    }
    return Promise.reject(err)
  }
)

export default api
