import { useEffect, useRef, useState } from 'react'
import { THREAT_URLS, SAFE_URLS } from '../../../data/scanSimulation'

const MAX_LOGS = 8
const CHAR_DELAY = 28
const ENTRY_PAUSE = 320
const NEXT_DELAY = 1400

const ALL_ITEMS = [
  ...THREAT_URLS.map((u) => ({ url: u.url, resultType: 'BLOCK', threat: u.type, conf: u.confidence })),
  ...SAFE_URLS.map((u) => ({ url: u.url, resultType: 'CLEAN' })),
]

export function useLiveScan() {
  const [logs, setLogs] = useState([
    { id: 0, type: 'SYSTEM', text: 'AegisNexus Threat Scanner v2.1 · başlatılıyor...', done: true },
  ])
  const [counter, setCounter] = useState(1_724_831)
  const mountedRef = useRef(true)
  const timersRef = useRef([])
  const urlIndexRef = useRef(0)
  const logIdRef = useRef(1)

  function addTimer(fn, ms) {
    const id = setTimeout(fn, ms)
    timersRef.current.push(id)
    return id
  }

  useEffect(() => {
    mountedRef.current = true

    function pushLog(entry) {
      if (!mountedRef.current) return
      setLogs((prev) => {
        const next = [...prev, entry]
        return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next
      })
    }

    function updateLog(id, patch) {
      if (!mountedRef.current) return
      setLogs((prev) => prev.map((l) => (l.id === id ? { ...l, ...patch } : l)))
    }

    function typeEntry(fullText, type, id, onDone) {
      setLogs((prev) => {
        const next = [...prev, { id, type, text: '', done: false }]
        return next.length > MAX_LOGS ? next.slice(next.length - MAX_LOGS) : next
      })

      let charIdx = 0
      function typeNext() {
        if (!mountedRef.current) return
        charIdx++
        updateLog(id, { text: fullText.slice(0, charIdx) })
        if (charIdx < fullText.length) {
          addTimer(typeNext, CHAR_DELAY)
        } else {
          updateLog(id, { done: true })
          onDone()
        }
      }
      addTimer(typeNext, 80)
    }

    function runNext() {
      if (!mountedRef.current) return
      const item = ALL_ITEMS[urlIndexRef.current % ALL_ITEMS.length]
      urlIndexRef.current++

      const scanId = logIdRef.current++
      const resultId = logIdRef.current++

      typeEntry(`→ ${item.url}`, 'SCAN', scanId, () => {
        addTimer(() => {
          if (!mountedRef.current) return
          const text =
            item.resultType === 'BLOCK'
              ? `✗ ${item.threat} — ${item.conf}% confidence`
              : '✓ SAFE'
          pushLog({ id: resultId, type: item.resultType, text, done: true })
          addTimer(runNext, NEXT_DELAY)
        }, ENTRY_PAUSE)
      })
    }

    addTimer(runNext, 900)

    const counterInterval = setInterval(() => {
      if (mountedRef.current) setCounter((prev) => prev + Math.floor(Math.random() * 3) + 1)
    }, 2000)

    return () => {
      mountedRef.current = false
      timersRef.current.forEach(clearTimeout)
      timersRef.current = []
      clearInterval(counterInterval)
    }
  }, [])

  return { logs, counter }
}
