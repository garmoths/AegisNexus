import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import ModulesApp from './ModulesApp.jsx'

// Route based on hostname
const isModules = window.location.hostname === 'modules.aegisnexus.dev'
const Component = isModules ? ModulesApp : App

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <Component />
  </StrictMode>,
)
