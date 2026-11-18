import { lazy, Suspense } from 'react'

const MainApp = lazy(() => import('./AppRouter.jsx'))
const CrawlerApp = import.meta.env.VITE_CRAWLER_MODE === 'true' ? lazy(() => import('./pages/CrawlerPage.jsx')) : null

export default function RuntimeApp() {
  const App = CrawlerApp || MainApp
  return <Suspense fallback={<p role="status">Yükleniyor…</p>}><App/></Suspense>
}
