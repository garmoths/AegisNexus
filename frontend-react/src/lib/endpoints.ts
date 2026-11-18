import api from '../lib/api'
import type { AdminUser, LoginResponse, Paged, RegisterResponse, Report, Role, SmsAnalysis } from './types'

export const authAPI = {
  register: (email: string, fullName: string) =>
    api.post<RegisterResponse>('/auth/register', { email, full_name: fullName }),

  login: (email: string, apiKey: string) =>
    api.post<LoginResponse>('/auth/login', { email, api_key: apiKey }),

  rotateKey: () =>
    api.post<{ new_api_key: string; message: string }>('/auth/rotate-key'),

  logout: () =>
    api.post('/auth/logout'),
}

export const reportsAPI = {
  analyze: (description: string) =>
    api.post<Report>('/reports/analyze', { description }),

  list: (page = 1) =>
    api.get<Paged<Report>>('/reports/', { params: { page } }),

  pdf: (id: number) =>
    api.get(`/reports/${id}/pdf`, { responseType: 'blob' }),
}

export const adminAPI = {
  users: (page = 1) =>
    api.get<{ data: AdminUser[]; page: number; total: number }>('/admin/users', { params: { page } }),

  changeRole: (userId: number, role: Role) =>
    api.patch(`/admin/users/${userId}`, { role }),
}

export const smsGuardAPI = {
  analyze: (text: string, sender?: string) =>
    api.post<SmsAnalysis>('/sms/analyze', { text, sender }),

  info: () =>
    api.get('/sms/info'),
}
