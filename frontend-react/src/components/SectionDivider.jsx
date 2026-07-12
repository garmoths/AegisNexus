export default function SectionDivider({ height = 100, toColor = '#080c14' }) {
  return (
    <div
      aria-hidden
      style={{
        height,
        background: `linear-gradient(to bottom, transparent 0%, ${toColor} 100%)`,
        marginTop: -height,
        position: 'relative',
        zIndex: 10,
        pointerEvents: 'none',
      }}
    />
  )
}
