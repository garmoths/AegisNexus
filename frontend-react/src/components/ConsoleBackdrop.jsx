import { lazy, Suspense } from 'react'

// WebGL arka plan ayrı parçada yüklenir; ilk boyamayı geciktirmez.
const Aurora = lazy(() => import('./Aurora.jsx'))

// Turuncu/amber tonlarında sakin aurora. Mavi yok.
const STOPS = ['#f26a2e', '#ff9a3c', '#e2531f']

/**
 * Sabit, dekoratif arka plan: üstte akan aurora + yumuşak ışıma + film greni.
 * - WebGL yoksa ya da yüklenirken CSS ışıması görünür (yedek).
 * - Aurora sekme gizlenince/ekran dışındayken durur, "hareketi azalt"ta donar.
 * - Tam ekran olduğu için piksel yoğunluğu 1x: yumuşak efekt, düşük GPU yükü.
 * Etkileşim almaz, ekran okuyuculardan gizlidir.
 */
export default function ConsoleBackdrop() {
  return (
    <div className="console-backdrop" aria-hidden="true">
      <div className="glow" />
      <div className="aurora">
        <Suspense fallback={null}>
          <Aurora colorStops={STOPS} amplitude={0.9} blend={0.6} speed={0.5} height={0.36} glow={0.45}
            brightness={0.7} opacity={0.42} layers={2} dpr={1} />
        </Suspense>
      </div>
      <div className="fade" />
      <div className="grain" />
    </div>
  )
}
