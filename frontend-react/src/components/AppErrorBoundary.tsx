import { Component, type ErrorInfo, type ReactNode } from 'react'

export default class AppErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('UI error', error, info.componentStack) }
  render() {
    if (this.state.failed) return <main className="account-layout" role="alert">
      <h1>Ekran yüklenemedi</h1><p>Sayfayı yenileyerek tekrar deneyin. Analiz sonucu oluşmadı.</p>
      <button onClick={() => window.location.reload()}>Yeniden yükle</button>
    </main>
    return this.props.children
  }
}
