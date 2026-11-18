import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { MotionConfig } from 'framer-motion'
import RuntimeApp from './RuntimeApp.jsx'
import AppErrorBoundary from './components/AppErrorBoundary.jsx'
import './index.css'

createRoot(document.getElementById('root')).render(<StrictMode><AppErrorBoundary><MotionConfig reducedMotion="user"><RuntimeApp/></MotionConfig></AppErrorBoundary></StrictMode>)
