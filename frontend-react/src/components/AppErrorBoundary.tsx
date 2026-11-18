import { Component } from 'react'

export default class AppErrorBoundary extends Component {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  render() {
    if (this.state.failed) return <main className="account-layout" role="alert">
      <h1>Ekran yüklenemedi</h1><p>Sayfayı yenileyerek tekrar deneyin. Analiz sonucu oluşmadı.</p>
      <button onClick={() => window.location.reload()}>Yeniden yükle</button>
    </main>
    return this.props.children
  }
}
