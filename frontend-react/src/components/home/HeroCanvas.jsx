import { useRef } from 'react'
import { useCanvasAnimation } from './hooks/useCanvasAnimation'

export default function HeroCanvas({ reducedMotion }) {
  const canvasRef = useRef(null)
  useCanvasAnimation(canvasRef, reducedMotion)

  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        pointerEvents: 'none',
        display: 'block',
      }}
    />
  )
}
