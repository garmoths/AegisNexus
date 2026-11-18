import { Trash2, Radio } from 'lucide-react'
import useEventBus, { type BusEvent, type Severity } from '@/stores/eventBus'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

const moduleMeta: Record<string, { label: string; short: string }> = {
  phishing: { label: 'Phishing', short: 'PH' },
  analiz: { label: 'İçerik Analizi', short: 'AN' },
  ioc: { label: 'IOC / Tuzak', short: 'IOC' },
  system: { label: 'Sistem', short: 'SYS' },
}

const severityVariant: Record<Severity, 'destructive' | 'warning' | 'default' | 'muted'> = { critical: 'destructive', high: 'destructive', medium: 'warning', low: 'default', info: 'muted' }
const severityDot: Record<Severity, string> = { critical: 'bg-destructive', high: 'bg-destructive', medium: 'bg-[color:var(--warning)]', low: 'bg-primary', info: 'bg-muted-foreground' }

function clock(ts: number) {
  return new Date(ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export default function LiveEventsPanel({ className, onJump }: { className?: string; onJump?: (module: string, event: BusEvent) => void }) {
  const events = useEventBus(s => s.events)
  const clear = useEventBus(s => s.clear)
  const highCount = events.filter(e => e.severity === 'high' || e.severity === 'critical').length

  return (
    <aside className={cn('flex h-full flex-col rounded-xl border border-border bg-card', className)}>
      <div className="flex items-center justify-between gap-2 border-b border-border p-4">
        <div className="flex items-center gap-2">
          <span className="relative flex size-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-primary opacity-60" />
            <span className="relative inline-flex size-2.5 rounded-full bg-primary" />
          </span>
          <h2 className="text-sm font-semibold">Canlı Olaylar</h2>
          <Badge variant="muted">{events.length}</Badge>
          {highCount > 0 && <Badge variant="destructive">{highCount} yüksek</Badge>}
        </div>
        {events.length > 0 && (
          <Button variant="ghost" size="icon" className="size-8 text-muted-foreground" onClick={clear} title="Temizle">
            <Trash2 className="size-4" />
          </Button>
        )}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {events.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-2 px-4 py-10 text-center text-muted-foreground">
            <Radio className="size-7 text-primary/70" />
            <p className="text-sm">Henüz olay yok.</p>
            <p className="text-xs">Bir modülü çalıştırın; bulgular burada canlı akar ve diğer modüllere iletilir.</p>
          </div>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {events.map(e => {
              const meta = moduleMeta[e.module] || moduleMeta.system
              return (
                <li key={e.id}>
                  <button
                    type="button"
                    onClick={() => onJump?.(e.module, e)}
                    className="group w-full rounded-lg border border-transparent p-2.5 text-left transition-colors hover:border-border hover:bg-muted/50"
                  >
                    <div className="flex items-center gap-2">
                      <span className={cn('size-2 shrink-0 rounded-full', severityDot[e.severity] || severityDot.info)} />
                      <Badge variant={severityVariant[e.severity] || 'muted'} className="px-1.5 py-0 text-[10px]">{meta.short}</Badge>
                      <span className="truncate text-xs font-medium text-foreground">{e.title}</span>
                      <span className="ml-auto shrink-0 font-mono text-[10px] text-muted-foreground">{clock(e.ts)}</span>
                    </div>
                    {e.detail && <p className="mt-1 line-clamp-2 pl-4 text-[11px] text-muted-foreground">{e.detail}</p>}
                  </button>
                </li>
              )
            })}
          </ul>
        )}
      </div>
    </aside>
  )
}
