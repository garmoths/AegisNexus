import axios from 'axios'
import useAuthStore from '../stores/authStore'

export const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v2'
const api = axios.create({baseURL:API_BASE,withCredentials:true,timeout:30000,headers:{'Content-Type':'application/json'}})
api.interceptors.response.use(response=>response, error=>{
  if (error.response?.status===401) useAuthStore.getState().logout()
  return Promise.reject(error)
})
export default api

export async function apiFetch(input, options={}) {
  const response = await fetch(input, {...options, credentials:'include'})
  if (response.status === 401) useAuthStore.getState().logout()
  if (!response.ok) {
    const payload = await response.clone().json().catch(()=>({}))
    const error = new Error(typeof payload.detail==='string'?payload.detail:'İstek tamamlanamadı.')
    error.response={status:response.status,data:payload}
    throw error
  }
  return response
}
