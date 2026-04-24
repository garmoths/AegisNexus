import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import ModulesApp from './ModulesApp.jsx'

// Route based on hostname
const host = window.location.hostname.toLowerCase()
const isModules = host === 'modules.aegisnexus.dev' || host.startsWith('modules.')
const Component = isModules ? ModulesApp : App

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Component />
  </StrictMode>,
)
