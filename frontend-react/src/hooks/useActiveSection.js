import { useEffect, useRef, useState } from 'react'

// Scroll ile aktif section'ı scroll pozisyonuna göre izler.
// GSAP pin'li section'lar için gsap-section-enter / gsap-section-leave event'leri
// ile override edilir; pin süresince o section aktif kalır, leave sonrası scroll-scan devreye girer.
export default function useActiveSection(ids) {
  const [active, setActive] = useState(ids[0] ?? null)
  const gsapPinnedRef = useRef(null) // GSAP tarafından pin'lenen section id
  const idsRef = useRef(ids)
  idsRef.current = ids

  const scan = useRef(() => {
    if (gsapPinnedRef.current) return // GSAP yönetiyor, müdahale etme

    const viewH = window.innerHeight
    const targetY = viewH * 0.42

    let bestId = null
    let bestDist = Infinity

    for (const id of idsRef.current) {
      const el = document.getElementById(id)
      if (!el) continue
      if (window.getComputedStyle(el).position === 'fixed') continue // GSAP pin

      const rect = el.getBoundingClientRect()
      if (rect.bottom < 60 || rect.top > viewH - 60) continue

      const center = (rect.top + rect.bottom) / 2
      const dist = Math.abs(center - targetY)
      if (dist < bestDist) {
        bestDist = dist
        bestId = id
      }
    }

    if (bestId) setActive((prev) => (prev !== bestId ? bestId : prev))
  }).current

  useEffect(() => {
    const onGsapEnter = (e) => {
      gsapPinnedRef.current = e.detail
      setActive(e.detail)
    }
    const onGsapLeave = () => {
      gsapPinnedRef.current = null
      setTimeout(scan, 80)
    }
    window.addEventListener('gsap-section-enter', onGsapEnter)
    window.addEventListener('gsap-section-leave', onGsapLeave)
    return () => {
      window.removeEventListener('gsap-section-enter', onGsapEnter)
      window.removeEventListener('gsap-section-leave', onGsapLeave)
    }
  }, [scan])

  useEffect(() => {
    window.addEventListener('scroll', scan, { passive: true })
    scan()
    return () => window.removeEventListener('scroll', scan)
  }, [scan])

  return active
}
