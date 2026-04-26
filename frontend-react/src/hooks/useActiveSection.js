import { useEffect, useState } from 'react'

// Scroll ile viewport'un üst orta kuşağında olan section'un id'sini izler.
// Navbar scrollspy highlight'ı için kullanılır.
//
// Notlar:
//  - IntersectionObserver desteği yoksa (eski tarayıcılar) ilk id ile sessizce kalır.
//  - setState, react-hooks/set-state-in-effect kuralından kaçınmak için
//    requestAnimationFrame ile bir tick sonraya itilir.
export default function useActiveSection(ids) {
  const [active, setActive] = useState(ids[0] ?? null)

  useEffect(() => {
    if (typeof window === 'undefined' || !('IntersectionObserver' in window)) {
      return undefined
    }

    let rafId = 0
    const ratios = new Map()

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          ratios.set(entry.target.id, entry.isIntersecting ? entry.intersectionRatio : 0)
        })
        let bestId = null
        let bestRatio = 0
        for (const id of ids) {
          const ratio = ratios.get(id) ?? 0
          if (ratio > bestRatio) {
            bestRatio = ratio
            bestId = id
          }
        }
        if (bestId) {
          cancelAnimationFrame(rafId)
          rafId = requestAnimationFrame(() => setActive(bestId))
        }
      },
      {
        // Üst %35 ile alt %55 arasındaki kuşağı "aktif" kabul ederiz.
        rootMargin: '-35% 0px -55% 0px',
        threshold: [0, 0.25, 0.5, 0.75, 1],
      }
    )

    const targets = ids
      .map((id) => document.getElementById(id))
      .filter((el) => el !== null)

    targets.forEach((el) => observer.observe(el))

    return () => {
      cancelAnimationFrame(rafId)
      observer.disconnect()
    }
  }, [ids])

  return active
}
