import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import './index.css'
import App from './App.jsx'
import ModulesApp from './ModulesApp.jsx'

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
        </Routes>
      </BrowserRouter>
    )}
  </StrictMode>,
)
