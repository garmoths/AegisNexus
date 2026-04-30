import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import ModulesApp from './ModulesApp.jsx'

// Victim Atlas pages
import HomePage from './pages/HomePage.jsx'
import AtlasPage from './pages/AtlasPage.jsx'
import CaseDetailPage from './pages/CaseDetailPage.jsx'
import AnalyzePage from './pages/AnalyzePage.jsx'
import HaritaPage from './pages/HaritaPage.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import AdminPage from './pages/AdminPage.jsx'
import LoginPage from './pages/LoginPage.jsx'

// Route based on hostname
const host = window.location.hostname.toLowerCase()
const isModules = host === 'modules.aegisnexus.dev' || host.startsWith('modules.')

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {isModules ? (
      <ModulesApp />
    ) : (
      <BrowserRouter>
        <Routes>
          {/* Victim Atlas SPA */}
          <Route path="/" element={<HomePage />} />
          <Route path="/atlas" element={<AtlasPage />} />
          <Route path="/atlas/:id" element={<CaseDetailPage />} />
          <Route path="/analyze" element={<AnalyzePage />} />
          <Route path="/harita" element={<HaritaPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/admin" element={<AdminPage />} />
          <Route path="/login" element={<LoginPage />} />
          {/* Legacy landing */}
          <Route path="/landing" element={<App />} />
        </Routes>
      </BrowserRouter>
    )}
  </StrictMode>,
)
