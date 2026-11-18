import { lazy, Suspense } from 'react'

const MainApp = lazy(() => import('./AppRouter'))
const CrawlerApp = import.meta.env.VITE_CRAWLER_MODE === 'true' ? lazy(() => import('./pages/CrawlerPage')) : null

export default function RuntimeApp() {
  const App = CrawlerApp || MainApp
  return <Suspense fallback={<p role="status">Yükleniyor…</p>}><App/></Suspense>
}
