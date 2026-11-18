import axios, { AxiosError } from 'axios'
import useAuthStore from '../stores/authStore'
import type { ApiErrorBody } from './types'

export const API_BASE: string = import.meta.env.VITE_API_BASE_URL || '/api/v2'

const api = axios.create({ baseURL: API_BASE, withCredentials: true, timeout: 30000, headers: { 'Content-Type': 'application/json' } })
api.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) useAuthStore.getState().logout()
    return Promise.reject(error)
  },
)
export default api

/** Error thrown by {@link apiFetch}; mirrors the shape axios errors expose. */
export class ApiError extends Error {
  response: { status: number; data: Partial<ApiErrorBody> }
  constructor(message: string, status: number, data: Partial<ApiErrorBody>) {
    super(message)
    this.name = 'ApiError'
    this.response = { status, data }
  }
  get requestId(): string | undefined {
    return this.response.data.error?.request_id
  }
}

/** Human-readable message from an axios/ApiError/unknown failure. */
export function errorMessage(error: unknown, fallback = 'İstek tamamlanamadı.'): string {
  const detail = (error as { response?: { data?: Partial<ApiErrorBody> } })?.response?.data?.detail
  return typeof detail === 'string' ? detail : fallback
}

export async function apiFetch(input: RequestInfo | URL, options: RequestInit = {}): Promise<Response> {
  const response = await fetch(input, { ...options, credentials: 'include' })
  if (response.status === 401) useAuthStore.getState().logout()
  if (!response.ok) {
    const payload: Partial<ApiErrorBody> = await response.clone().json().catch(() => ({}))
    throw new ApiError(typeof payload.detail === 'string' ? payload.detail : 'İstek tamamlanamadı.', response.status, payload)
  }
  return response
}
