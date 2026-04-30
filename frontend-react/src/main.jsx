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
          {/* Original landing page — default */}
          <Route path="/" element={<App />} />
          {/* Victim Atlas SPA */}
          <Route path="/atlas" element={<HomePage />} />
          <Route path="/atlas/cases" element={<AtlasPage />} />
          <Route path="/atlas/cases/:id" element={<CaseDetailPage />} />
          <Route path="/atlas/analyze" element={<AnalyzePage />} />
          <Route path="/atlas/harita" element={<HaritaPage />} />
          <Route path="/atlas/dashboard" element={<DashboardPage />} />
          <Route path="/atlas/admin" element={<AdminPage />} />
          <Route path="/atlas/login" element={<LoginPage />} />
        </Routes>
      </BrowserRouter>
    )}
  </StrictMode>,
)
