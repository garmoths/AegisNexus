import { useEffect, useRef, useState } from 'react'
import { motion, useReducedMotion } from 'framer-motion'
import { theme } from '../theme'
import { threatLast24h, threatSparks } from '../data/landing'
import { useInViewOnce } from '../hooks/useInViewOnce'

// Chart.js dinamik olarak yalnızca section görünür olduğunda yüklenir
async function loadChart() {
  const [{ Chart, registerables }] = await Promise.all([import('chart.js')])
  Chart.register(...registerables)
  return Chart
}

const BASE_VALS = [412, 87, 1200, 318]
function fmtSpark(n) { return n >= 1000 ? `+${(n/1000).toFixed(1)}K` : `+${n}` }
function jitter(b) { return Math.max(1, Math.round(b + b * 0.12 * (Math.random() - 0.5))) }

function SparkCard({ spark, index, liveValue, reducedMotion }) {
  const isUp = !spark.delta.startsWith('−')
  return (
    <motion.div
      initial={reducedMotion ? false : { opacity: 0, y: 12 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: '-60px' }}
      transition={{ duration: 0.4, delay: index * 0.05 }}
      style={{
        padding: 18,
        borderRadius: theme.radius.md,
        background: theme.surface,
        border: `1px solid ${theme.border}`,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ color: theme.textMuted, fontSize: 12, letterSpacing: '0.4px', textTransform: 'uppercase', fontWeight: 700 }}>{spark.label}</span>
        <span
          style={{
            fontSize: 11,
            fontWeight: 700,
            padding: '3px 8px',
            borderRadius: 999,
            color: isUp ? theme.danger : theme.success,
            background: `${isUp ? theme.danger : theme.success}1c`,
            border: `1px solid ${isUp ? theme.danger : theme.success}55`,
          }}
        >
          {spark.delta}
        </span>
      </div>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8 }}>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 26, fontWeight: 800, color: '#fff', transition: 'all 600ms ease' }}>
          {fmtSpark(liveValue ?? BASE_VALS[index])}
        </span>
        <span style={{ fontSize: 12, color: theme.textMuted }}>son 1s</span>
      </div>
      <div aria-hidden style={{ height: 2, background: `linear-gradient(90deg, ${spark.color}aa, transparent)`, animation: 'barShimmer 3s ease-in-out infinite', animationDelay: `${index * 0.7}s` }} />
    </motion.div>
  )
}

export default function ThreatLandscapeLive() {
  const reducedMotion = useReducedMotion()
  const [containerRef, inView] = useInViewOnce({ threshold: 0.2 })
  const canvasRef = useRef(null)
  const chartRef = useRef(null)
  const [error, setError] = useState(null)
  const [sparkValues, setSparkValues] = useState([...BASE_VALS])
  const liveDataRef = useRef({
    blocked: threatLast24h.map(p => p.blocked),
    flagged: threatLast24h.map(p => p.flagged),
    labels:  threatLast24h.map(p => p.hour),
  })

  useEffect(() => {
    if (!inView) return
    let disposed = false
    loadChart()
      .then((Chart) => {
        if (disposed || !canvasRef.current) return
        const ctx = canvasRef.current.getContext('2d')
        const gradientBlocked = ctx.createLinearGradient(0, 0, 0, 240)
        gradientBlocked.addColorStop(0, 'rgba(0,212,255,0.45)')
        gradientBlocked.addColorStop(1, 'rgba(0,212,255,0)')
        const gradientFlagged = ctx.createLinearGradient(0, 0, 0, 240)
        gradientFlagged.addColorStop(0, 'rgba(255,107,53,0.4)')
        gradientFlagged.addColorStop(1, 'rgba(255,107,53,0)')

        chartRef.current = new Chart(ctx, {
          type: 'line',
          data: {
            labels: threatLast24h.map((p) => p.hour),
            datasets: [
              {
                label: 'Engellenen',
                data: threatLast24h.map((p) => p.blocked),
                borderColor: '#00d4ff',
                backgroundColor: gradientBlocked,
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.35,
                fill: true,
              },
              {
                label: 'İşaretlenen',
                data: threatLast24h.map((p) => p.flagged),
                borderColor: '#ff6b35',
                backgroundColor: gradientFlagged,
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.35,
                fill: true,
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            animation: reducedMotion ? false : { duration: 800, easing: 'easeOutCubic' },
            plugins: {
              legend: {
                display: true,
                position: 'top',
                align: 'end',
                labels: { color: '#94a3b8', boxWidth: 10, boxHeight: 10, usePointStyle: true, font: { size: 12 } },
              },
              tooltip: {
                backgroundColor: 'rgba(15,22,41,0.95)',
                borderColor: 'rgba(0,212,255,0.4)',
                borderWidth: 1,
                titleColor: '#fff',
                bodyColor: '#cbd5e1',
                padding: 10,
              },
            },
            scales: {
              x: {
                ticks: { color: '#475569', maxRotation: 0, autoSkip: true, maxTicksLimit: 8, font: { size: 11 } },
                grid: { color: 'rgba(30,42,74,0.4)' },
              },
              y: {
                ticks: { color: '#475569', font: { size: 11 } },
                grid: { color: 'rgba(30,42,74,0.4)' },
                beginAtZero: true,
              },
            },
          },
        })
      })
      .catch((err) => setError(err?.message || 'Chart load error'))

    return () => {
      disposed = true
      if (chartRef.current) {
        chartRef.current.destroy()
        chartRef.current = null
      }
    }
  }, [inView, reducedMotion])

  // Simüle canlı veri güncelleme
  useEffect(() => {
    if (!inView || reducedMotion) return

    const chartInterval = setInterval(() => {
      const d = liveDataRef.current
      const now = new Date()
      const label = `${String(now.getHours()).padStart(2,'0')}:${String(now.getMinutes()).padStart(2,'0')}`
      d.blocked.push(Math.round(60 + Math.random() * 80))
      d.blocked.shift()
      d.flagged.push(Math.round(30 + Math.random() * 30))
      d.flagged.shift()
      d.labels.push(label)
      d.labels.shift()

      if (chartRef.current) {
        chartRef.current.data.labels = [...d.labels]
        chartRef.current.data.datasets[0].data = [...d.blocked]
        chartRef.current.data.datasets[1].data = [...d.flagged]
        chartRef.current.update('none')
      }
    }, 3000)

    const sparkInterval = setInterval(() => {
      setSparkValues(BASE_VALS.map(b => jitter(b)))
    }, 4000)

    return () => {
      clearInterval(chartInterval)
      clearInterval(sparkInterval)
    }
  }, [inView, reducedMotion])

  return (
    <section id="threat-live" ref={containerRef} style={{ padding: '70px 24px', position: 'relative', overflow: 'hidden' }}>
      {/* Isı haritası arka plan */}
      <div
        aria-hidden
        style={{
          position: 'absolute',
          inset: 0,
          background: 'radial-gradient(ellipse 60% 40% at 30% 80%, rgba(255,51,102,0.04) 0%, transparent 70%), radial-gradient(ellipse 40% 30% at 70% 30%, rgba(0,212,255,0.03) 0%, transparent 60%)',
          animation: 'bgShift 12s ease-in-out infinite alternate',
          pointerEvents: 'none',
          zIndex: 0,
        }}
      />
      <style>{`
        @keyframes bgShift { from { opacity: 0.7; } to { opacity: 1.0; } }
        @keyframes barShimmer { 0%, 100% { opacity: 0.7; } 50% { opacity: 1.0; } }
      `}</style>
      <div style={{ maxWidth: 1220, margin: '0 auto', position: 'relative', zIndex: 1 }}>
        <div style={{ textAlign: 'center', marginBottom: 36 }}>
          <span
            style={{
              display: 'inline-block',
              padding: '6px 14px',
              borderRadius: 999,
              fontSize: 11,
              fontWeight: 700,
              color: theme.accent,
              background: theme.accentSoft,
              border: `1px solid ${theme.accent}55`,
              letterSpacing: '1.6px',
              textTransform: 'uppercase',
              marginBottom: 18,
            }}
          >
            Tehdit Manzarası · Son 24 Saat
          </span>
          <h2 style={{ fontSize: 'clamp(30px, 3.8vw, 42px)', fontWeight: 820, color: '#fff', letterSpacing: '-1px' }}>
            Tehditler <span style={{ color: theme.primary }}>uyumadığı</span> için biz de uyumayız
          </h2>
          <p style={{ color: theme.textMuted, maxWidth: 720, margin: '12px auto 0', lineHeight: 1.7 }}>
            Telemetri panelimiz ham sinyalleri normalize edip her saatin engellenen ve işaretlenen tehdit hacmini görselleştirir.
          </p>
        </div>

        <div
          style={{
            background: theme.gradientSurface,
            border: `1px solid ${theme.border}`,
            borderRadius: theme.radius.xl,
            padding: 22,
            display: 'grid',
            gap: 18,
            gridTemplateColumns: 'minmax(0, 2fr) minmax(220px, 1fr)',
          }}
        >
          <div style={{ minHeight: 280 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: theme.success, boxShadow: `0 0 10px ${theme.success}` }} />
              <span style={{ fontSize: 12, color: theme.textMuted, letterSpacing: '0.5px', textTransform: 'uppercase', fontWeight: 700 }}>
                Canlı feed · saatlik bucket
              </span>
            </div>
            <div style={{ position: 'relative', height: 280 }}>
              {error ? (
                <p style={{ color: theme.danger, fontSize: 13 }}>Grafik yüklenemedi: {error}</p>
              ) : (
                <canvas ref={canvasRef} aria-label="Son 24 saat tehdit grafiği" />
              )}
            </div>
          </div>
          <div style={{ display: 'grid', gap: 12, alignContent: 'start' }}>
            {threatSparks.map((spark, index) => (
              <SparkCard key={spark.label} spark={spark} index={index} liveValue={sparkValues[index]} reducedMotion={reducedMotion} />
            ))}
          </div>
        </div>

        <style>{`
          @media (max-width: 900px) {
            #threat-live > div > div:last-of-type {
              grid-template-columns: 1fr !important;
            }
          }
        `}</style>
      </div>
    </section>
  )
}
