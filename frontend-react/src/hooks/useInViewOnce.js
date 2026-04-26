import { useEffect, useRef, useState } from 'react'

const supportsIO = typeof window !== 'undefined' && typeof window.IntersectionObserver !== 'undefined'

// Element görünür olduğunda bir kez true döner; sonra observer'ı söker.
// IntersectionObserver desteklenmeyen ortamlarda baştan true ile başlar.
export function useInViewOnce({ threshold = 0.2, rootMargin = '0px 0px -10% 0px' } = {}) {
  const ref = useRef(null)
  const [inView, setInView] = useState(!supportsIO)

  useEffect(() => {
    if (!supportsIO || inView) return undefined
    const node = ref.current
    if (!node) return undefined

    const obs = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setInView(true)
            obs.disconnect()
            break
          }
        }
      },
      { threshold, rootMargin },
    )
    obs.observe(node)
    return () => obs.disconnect()
  }, [threshold, rootMargin, inView])

  return [ref, inView]
}
