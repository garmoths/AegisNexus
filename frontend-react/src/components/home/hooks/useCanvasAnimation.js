import { useEffect, useRef } from 'react'

const GRID_SPACING = 60
const PULSE_INTERVAL = 8000
const PULSE_SPEED = 1.8
const THREAT_SPAWN_MIN = 2200
const THREAT_SPAWN_MAX = 4200
const SCAN_PLANE_RATIO = 0.45
const BEAM_PERIOD = 6000
const MOUSE_RADIUS = 150
const MAX_DATA_PARTICLES = 50
const MAX_THREATS = 6

export function useCanvasAnimation(canvasRef, reducedMotion) {
  const mouseRef = useRef({ x: -9999, y: -9999 })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    let rafId
    let width = 0
    let height = 0
    let dpr = 1

    const particles = []
    const threats = []
    const pulses = []
    let nextPulse = performance.now() + PULSE_INTERVAL
    let nextThreat = performance.now() + THREAT_SPAWN_MIN + Math.random() * (THREAT_SPAWN_MAX - THREAT_SPAWN_MIN)
    let beamStart = performance.now()

    function resize() {
      dpr = window.devicePixelRatio || 1
      width = canvas.offsetWidth
      height = canvas.offsetHeight
      canvas.width = Math.round(width * dpr)
      canvas.height = Math.round(height * dpr)
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }

    function drawGrid() {
      ctx.strokeStyle = 'rgba(0, 153, 187, 0.12)'
      ctx.lineWidth = 0.5
      for (let x = 0; x <= width; x += GRID_SPACING) {
        ctx.beginPath()
        ctx.moveTo(x, 0)
        ctx.lineTo(x, height)
        ctx.stroke()
      }
      for (let y = 0; y <= height; y += GRID_SPACING) {
        ctx.beginPath()
        ctx.moveTo(0, y)
        ctx.lineTo(width, y)
        ctx.stroke()
      }
    }

    function drawMouseGlow() {
      const mx = mouseRef.current.x
      const my = mouseRef.current.y
      for (let x = 0; x <= width; x += GRID_SPACING) {
        for (let y = 0; y <= height; y += GRID_SPACING) {
          const dist = Math.hypot(x - mx, y - my)
          if (dist < MOUSE_RADIUS) {
            const alpha = (1 - dist / MOUSE_RADIUS) * 0.55
            ctx.beginPath()
            ctx.arc(x, y, 2.5, 0, Math.PI * 2)
            ctx.fillStyle = `rgba(0, 212, 255, ${alpha})`
            ctx.fill()
          }
        }
      }
    }

    function spawnPulse() {
      pulses.push({ x: width * 0.35, y: height * 0.5, r: 0, alpha: 0.07 })
    }

    function updatePulses() {
      for (let i = pulses.length - 1; i >= 0; i--) {
        const p = pulses[i]
        p.r += PULSE_SPEED
        p.alpha *= 0.994
        ctx.beginPath()
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2)
        ctx.strokeStyle = `rgba(0, 212, 255, ${p.alpha})`
        ctx.lineWidth = 1.2
        ctx.stroke()
        if (p.alpha < 0.002 || p.r > Math.max(width, height) * 1.2) {
          pulses.splice(i, 1)
        }
      }
    }

    function spawnDataParticle() {
      const cols = Math.floor(width / GRID_SPACING)
      const rows = Math.floor(height / GRID_SPACING)
      const horizontal = Math.random() > 0.5
      const gx = Math.floor(Math.random() * cols) * GRID_SPACING
      const gy = Math.floor(Math.random() * rows) * GRID_SPACING
      particles.push({
        x: gx,
        y: gy,
        dx: horizontal ? (Math.random() > 0.5 ? 1 : -1) : 0,
        dy: horizontal ? 0 : (Math.random() > 0.5 ? 1 : -1),
        speed: 0.8 + Math.random() * 0.7,
        alpha: 0.25 + Math.random() * 0.4,
      })
    }

    function updateDataParticles() {
      while (particles.length < MAX_DATA_PARTICLES) spawnDataParticle()

      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i]
        p.x += p.dx * p.speed
        p.y += p.dy * p.speed

        const snapX = Math.round(p.x / GRID_SPACING) * GRID_SPACING
        const snapY = Math.round(p.y / GRID_SPACING) * GRID_SPACING
        if (Math.abs(p.x - snapX) < p.speed * 1.5 && Math.abs(p.y - snapY) < p.speed * 1.5 && Math.random() < 0.03) {
          const h = Math.random() > 0.5
          p.dx = h ? (Math.random() > 0.5 ? 1 : -1) : 0
          p.dy = h ? 0 : (Math.random() > 0.5 ? 1 : -1)
        }

        if (p.x < -8 || p.x > width + 8 || p.y < -8 || p.y > height + 8) {
          particles.splice(i, 1)
          continue
        }

        ctx.beginPath()
        ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(0, 212, 255, ${p.alpha})`
        ctx.fill()
      }
    }

    function spawnThreat() {
      const y = 60 + Math.random() * (height - 120)
      threats.push({
        x: width + 12,
        y,
        speed: 1.1 + Math.random() * 0.7,
        state: 'moving',
        detectStart: 0,
        explodeR: 0,
        explodeAlpha: 0,
        cr: 255, cg: 51, cb: 102,
      })
    }

    function updateThreats(now) {
      const planeX = width * SCAN_PLANE_RATIO

      for (let i = threats.length - 1; i >= 0; i--) {
        const t = threats[i]

        if (t.state === 'moving') {
          t.x -= t.speed
          if (t.x <= planeX) {
            t.state = 'detecting'
            t.detectStart = now
          }
        } else if (t.state === 'detecting') {
          const prog = Math.min(1, (now - t.detectStart) / 320)
          t.cr = Math.round(255 * (1 - prog))
          t.cg = Math.round(51 + (136 - 51) * prog)
          t.cb = Math.round(102 * (1 - prog))
          if (prog >= 1) { t.state = 'exploding'; t.explodeR = 0; t.explodeAlpha = 0.65 }
        } else if (t.state === 'exploding') {
          t.explodeR += 2.5
          t.explodeAlpha -= 0.018
          if (t.explodeAlpha <= 0) { t.state = 'dead' }
        }

        if (t.state === 'dead' || t.x < -25) { threats.splice(i, 1); continue }

        if (t.state === 'exploding') {
          ctx.beginPath()
          ctx.arc(t.x, t.y, t.explodeR, 0, Math.PI * 2)
          ctx.strokeStyle = `rgba(0, 255, 136, ${t.explodeAlpha})`
          ctx.lineWidth = 1.8
          ctx.stroke()
        }

        if (t.state !== 'dead') {
          const r = t.state === 'exploding' ? 2 : 2.5
          ctx.beginPath()
          ctx.arc(t.x, t.y, r, 0, Math.PI * 2)
          ctx.fillStyle = `rgba(${t.cr}, ${t.cg}, ${t.cb}, 0.85)`
          ctx.fill()
          const grd = ctx.createRadialGradient(t.x, t.y, r, t.x, t.y, r * 3)
          grd.addColorStop(0, `rgba(${t.cr}, ${t.cg}, ${t.cb}, 0.22)`)
          grd.addColorStop(1, 'transparent')
          ctx.beginPath()
          ctx.arc(t.x, t.y, r * 3, 0, Math.PI * 2)
          ctx.fillStyle = grd
          ctx.fill()
        }
      }
    }

    function drawScanBeam(now) {
      const elapsed = (now - beamStart) % BEAM_PERIOD
      const bx = (elapsed / BEAM_PERIOD) * (width + 60) - 30
      const grd = ctx.createLinearGradient(bx - 25, 0, bx + 25, 0)
      grd.addColorStop(0, 'transparent')
      grd.addColorStop(0.5, 'rgba(0, 212, 255, 0.07)')
      grd.addColorStop(1, 'transparent')
      ctx.fillStyle = grd
      ctx.fillRect(bx - 25, 0, 50, height)
    }

    function loop(now) {
      ctx.clearRect(0, 0, width, height)
      drawGrid()
      drawScanBeam(now)
      updatePulses()
      drawMouseGlow()
      updateDataParticles()
      updateThreats(now)

      if (now >= nextPulse) {
        spawnPulse()
        nextPulse = now + PULSE_INTERVAL
      }

      if (now >= nextThreat && threats.length < MAX_THREATS) {
        spawnThreat()
        nextThreat = now + THREAT_SPAWN_MIN + Math.random() * (THREAT_SPAWN_MAX - THREAT_SPAWN_MIN)
      }

      rafId = requestAnimationFrame(loop)
    }

    const onMouseMove = (e) => {
      const rect = canvas.getBoundingClientRect()
      mouseRef.current = { x: e.clientX - rect.left, y: e.clientY - rect.top }
    }
    const onMouseLeave = () => { mouseRef.current = { x: -9999, y: -9999 } }

    const onScroll = () => {
      const prog = window.scrollY / window.innerHeight
      canvas.style.opacity = String(Math.max(0.08, 1 - prog * 0.65))
    }
    window.addEventListener('scroll', onScroll, { passive: true })

    window.addEventListener('mousemove', onMouseMove, { passive: true })
    canvas.addEventListener('mouseleave', onMouseLeave)

    const ro = new ResizeObserver(() => resize())
    ro.observe(canvas)
    resize()

    if (reducedMotion) {
      drawGrid()
    } else {
      spawnPulse()
      rafId = requestAnimationFrame(loop)
    }

    return () => {
      cancelAnimationFrame(rafId)
      ro.disconnect()
      window.removeEventListener('scroll', onScroll)
      window.removeEventListener('mousemove', onMouseMove)
      canvas.removeEventListener('mouseleave', onMouseLeave)
    }
  }, [canvasRef, reducedMotion])
}
