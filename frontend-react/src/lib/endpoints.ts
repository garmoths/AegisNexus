import api from '../lib/api'

export const authAPI = {
  register: (email, fullName) =>
    api.post('/auth/register', { email, full_name: fullName }),

  login: (email, apiKey) =>
    api.post('/auth/login', { email, api_key: apiKey }),

  rotateKey: () =>
    api.post('/auth/rotate-key'),

  logout: () =>
    api.post('/auth/logout'),
}

export const reportsAPI = {
  analyze: (description) =>
    api.post('/reports/analyze', { description }),

  list: (page = 1) =>
    api.get('/reports/', { params: { page } }),

  pdf: (id) =>
    api.get(`/reports/${id}/pdf`, { responseType: 'blob' }),
}

export const adminAPI = {
  users: (page = 1) =>
    api.get('/admin/users', { params: { page } }),

  changeRole: (userId, role) =>
    api.patch(`/admin/users/${userId}`, { role }),
}

export const smsGuardAPI = {
  analyze: (text, sender) =>
    api.post('/sms/analyze', { text, sender }),

  info: () =>
    api.get('/sms/info'),
}
