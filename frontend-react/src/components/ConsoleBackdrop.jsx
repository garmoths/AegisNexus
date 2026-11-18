// Sabit, dekoratif arka plan: ızgara + üst ışıma + yavaş tarama çizgisi + film grenı.
// Tamamen CSS; etkileşim almaz, ekran okuyuculardan gizlidir.
export default function ConsoleBackdrop() {
  return (
    <div className="console-backdrop" aria-hidden="true">
      <div className="glow" />
      <div className="grid" />
      <div className="scan" />
      <div className="grain" />
    </div>
  )
}
