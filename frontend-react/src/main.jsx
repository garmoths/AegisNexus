import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { MotionGlobalConfig } from 'framer-motion'
import RuntimeApp from './RuntimeApp.jsx'
import AppErrorBoundary from './components/AppErrorBoundary.jsx'
import './index.css'

// Sade arayüz: tüm framer-motion animasyonları anında son haline geçer.
MotionGlobalConfig.skipAnimations = true

createRoot(document.getElementById('root')).render(<StrictMode><AppErrorBoundary><RuntimeApp/></AppErrorBoundary></StrictMode>)
