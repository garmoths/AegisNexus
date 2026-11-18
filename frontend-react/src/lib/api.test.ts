import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiFetch, errorMessage } from './api'
import useAuthStore from '../stores/authStore'

const envelope = { detail: 'Endpoint bulunamadı.', error: { code: 'not_found', status: 404, request_id: 'abc123' } }

describe('errorMessage', () => {
  it('uses a string detail from the error envelope', () => {
    expect(errorMessage({ response: { data: envelope } })).toBe('Endpoint bulunamadı.')
  })
  it('falls back for validation lists and unknown errors', () => {
    expect(errorMessage({ response: { data: { detail: [{ loc: ['body'], msg: 'x', type: 't' }] } } }, 'fallback')).toBe('fallback')
    expect(errorMessage(new Error('boom'), 'fallback')).toBe('fallback')
  })
})

describe('apiFetch', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('throws ApiError carrying status, detail and request id', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(envelope), { status: 404 })))
    const failure = await apiFetch('/api/v2/missing').catch((e: unknown) => e)
    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).message).toBe('Endpoint bulunamadı.')
    expect((failure as ApiError).response.status).toBe(404)
    expect((failure as ApiError).requestId).toBe('abc123')
  })

  it('logs the user out on 401 and always sends credentials', async () => {
    const fetchMock = vi.fn(async () => new Response('{}', { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)
    useAuthStore.getState().setAuth({ role: 'free', email: 'a@example.com' })
    await apiFetch('/api/v2/auth/me').catch(() => undefined)
    expect(useAuthStore.getState().isAuthenticated()).toBe(false)
    expect(fetchMock).toHaveBeenCalledWith('/api/v2/auth/me', expect.objectContaining({ credentials: 'include' }))
  })
})
