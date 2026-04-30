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

export const casesAPI = {
  list: (params) =>
    api.get('/victim-atlas/cases', { params }),

  get: (id) =>
    api.get(`/victim-atlas/cases/${id}`),

  protectionCard: (id) =>
    api.get(`/victim-atlas/cases/${id}/protection-card`),

  create: (data) =>
    api.post('/victim-atlas/cases', data),

  patch: (id, data) =>
    api.patch(`/victim-atlas/cases/${id}`, data),
}

export const statsAPI = {
  basic: () =>
    api.get('/victim-atlas/stats'),

  overview: () =>
    api.get('/victim-atlas/stats/overview'),

  heatmap: () =>
    api.get('/victim-atlas/stats/heatmap'),

  weeklyDigest: () =>
    api.get('/victim-atlas/stats/weekly-digest'),
}

export const reportsAPI = {
  analyze: (description) =>
    api.post('/reports/analyze', { description }),

  list: (page = 1) =>
    api.get('/reports/', { params: { page } }),

  pdf: (id) =>
    api.get(`/reports/${id}/pdf`, { responseType: 'blob' }),
}

export const subscriptionAPI = {
  me: () =>
    api.get('/subscription/me'),

  upgrade: (plan) =>
    api.post('/subscription/upgrade', { plan }),
}

export const corporateAPI = {
  cases: (params) =>
    api.get('/corporate/cases', { params }),

  stats: () =>
    api.get('/corporate/stats'),
}

export const adminAPI = {
  classify: () =>
    api.post('/admin/classify'),

  users: (page = 1) =>
    api.get('/admin/users', { params: { page } }),

  changeRole: (userId, role) =>
    api.patch(`/admin/users/${userId}`, { role }),
}
