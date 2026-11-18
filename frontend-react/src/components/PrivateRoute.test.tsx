import { describe, expect, it } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import PrivateRoute from './PrivateRoute'
import useAuthStore from '../stores/authStore'
import type { Role } from '../lib/types'

function renderAt(roles?: Role[]) {
  return render(
    <MemoryRouter initialEntries={['/admin']}>
      <Routes>
        <Route path="/admin" element={<PrivateRoute roles={roles}><p>secret panel</p></PrivateRoute>} />
        <Route path="/login" element={<p>login page</p>} />
        <Route path="/" element={<p>home page</p>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('PrivateRoute', () => {
  it('redirects anonymous users to login', () => {
    useAuthStore.getState().logout()
    renderAt()
    expect(screen.getByText('login page')).toBeTruthy()
  })

  it('redirects users without the required role home', () => {
    useAuthStore.getState().setAuth({ role: 'free', email: 'u@example.com' })
    renderAt(['admin'])
    expect(screen.getByText('home page')).toBeTruthy()
  })

  it('renders children for an allowed role', () => {
    useAuthStore.getState().setAuth({ role: 'admin', email: 'a@example.com' })
    renderAt(['admin'])
    expect(screen.getByText('secret panel')).toBeTruthy()
  })
})
