import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Navigate, Routes, Route } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import ModulesApp from './ModulesApp.jsx'
import AnalyzePage from './pages/AnalyzePage.jsx'

// Route based on hostname
const host = window.location.hostname.toLowerCase()
const isModules = host === 'modules.your-domain.com' || host.startsWith('modules.')

createRoot(document.getElementById('root')).render(
  <StrictMode>
    {isModules ? (
      <ModulesApp />
    ) : (
      <BrowserRouter>
        <Routes>
          {/* Original landing page — default */}
          <Route path="/" element={<App />} />
          <Route path="/analyze" element={<AnalyzePage />} />
          {/* Local dev shortcut: localhost:5173/modules */}
          <Route path="/modules" element={<ModulesApp />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    )}
  </StrictMode>,
)
