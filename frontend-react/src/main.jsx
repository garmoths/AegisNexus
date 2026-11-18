import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { MotionConfig } from 'framer-motion'
import RuntimeApp from './RuntimeApp.jsx'
import AppErrorBoundary from './components/AppErrorBoundary.jsx'
import ConsoleBackdrop from './components/ConsoleBackdrop.jsx'
import './index.css'
import './console.css'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <AppErrorBoundary>
      <MotionConfig reducedMotion="user">
        <ConsoleBackdrop/>
        <div className="console-layer"><RuntimeApp/></div>
      </MotionConfig>
    </AppErrorBoundary>
  </StrictMode>
)
