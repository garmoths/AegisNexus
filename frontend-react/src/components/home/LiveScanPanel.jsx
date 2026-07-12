import { useEffect, useRef } from 'react'
import { useLiveScan } from './hooks/useLiveScan'
import { theme } from '../../theme'

const TYPE_COLOR = {
  SYSTEM: theme.textMuted,
  SCAN: theme.primary,
  BLOCK: '#ff3366',
  CLEAN: '#00ff88',
}

const TYPE_LABEL = {
  SYSTEM: '',
  SCAN: '[SCAN] ',
  BLOCK: '[BLOCK]',
  CLEAN: '[CLEAN]',
}

function formatCounter(n) {
  return n.toLocaleString('tr-TR')
}

export default function LiveScanPanel() {
  const { logs, counter } = useLiveScan()
  const containerRef = useRef(null)

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [logs])

  return (
    <div
      style={{
        background: 'rgba(0, 8, 20, 0.75)',
        border: '1px solid rgba(0, 212, 255, 0.2)',
        borderRadius: 14,
        backdropFilter: 'blur(14px)',
        WebkitBackdropFilter: 'blur(14px)',
        overflow: 'hidden',
        boxShadow: '0 8px 40px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(0,212,255,0.08) inset',
        fontFamily: "'JetBrains Mono', 'Fira Code', 'Courier New', monospace",
        fontSize: 12,
      }}
    >
      {/* Header bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          borderBottom: '1px solid rgba(0, 212, 255, 0.12)',
          background: 'rgba(0, 212, 255, 0.04)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: '#00ff88',
              boxShadow: '0 0 8px #00ff88',
              animation: 'livePulse 1.6s ease-in-out infinite',
              display: 'inline-block',
            }}
          />
          <span style={{ color: theme.primary, fontWeight: 700, fontSize: 11, letterSpacing: '1.5px' }}>
            LIVE SCAN
          </span>
        </div>
        <span style={{ color: theme.textMuted, fontSize: 10, letterSpacing: '0.5px' }}>
          {formatCounter(counter)} URLs Scanned
        </span>
      </div>

      {/* Log area */}
      <div
        style={{
          padding: '12px 16px',
          height: 280,
          overflowY: 'auto',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
          scrollbarWidth: 'thin',
          scrollbarColor: 'rgba(0,212,255,0.15) transparent',
        }}
        ref={containerRef}
      >
        {logs.map((log) => (
          <div
            key={log.id}
            style={{
              display: 'flex',
              gap: 8,
              lineHeight: 1.6,
              color: TYPE_COLOR[log.type] || theme.text,
              opacity: log.done ? 1 : 0.8,
            }}
          >
            {TYPE_LABEL[log.type] && (
              <span
                style={{
                  color: TYPE_COLOR[log.type],
                  fontWeight: 700,
                  flexShrink: 0,
                  fontSize: 11,
                  opacity: 0.9,
                }}
              >
                {TYPE_LABEL[log.type]}
              </span>
            )}
            <span style={{ wordBreak: 'break-all', color: log.type === 'SCAN' ? theme.text : TYPE_COLOR[log.type] }}>
              {log.text}
              {!log.done && (
                <span
                  style={{
                    display: 'inline-block',
                    width: 7,
                    height: 13,
                    background: theme.primary,
                    marginLeft: 2,
                    verticalAlign: 'middle',
                    animation: 'cursorBlink 0.7s step-end infinite',
                  }}
                />
              )}
            </span>
          </div>
        ))}
      </div>

      <style>{`
        @keyframes livePulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(0.85); }
        }
        @keyframes cursorBlink {
          0%, 100% { opacity: 1; }
          50% { opacity: 0; }
        }
      `}</style>
    </div>
  )
}
