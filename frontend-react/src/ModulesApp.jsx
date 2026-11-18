import { lazy, Suspense, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Link, Navigate, useLocation, useNavigate, useParams } from 'react-router-dom'
import { Menu, X, Activity, ScanLine, FileSearch, Crosshair, ArrowUpRight } from 'lucide-react'
import logo from './assets/logo.png'
import useEventBus from './stores/eventBus'
import LiveEventsPanel from './components/LiveEventsPanel'
import DecryptedText from './components/DecryptedText'
import { Button } from './components/ui/button'
import { Badge } from './components/ui/badge'
import { Skeleton } from './components/ui/skeleton'
import { cn } from './lib/utils'

const EASE = [0.16, 1, 0.3, 1]

// Modül başlıkları ve açıklamaları tek yerde; her modül aynı başlık şablonuyla açılır.
const entries = {
  phishing: {label:'Phishing Tarayıcı', code:'PHISH', Icon:ScanLine, description:'Bir URL’yi tarayın; tehdit istihbaratı, ekran görüntüsü ve güvenilirlik puanını görün.', Component:lazy(()=>import('./modules/phishing.jsx'))},
  analiz: {label:'İçerik Analizi', code:'INTEL', Icon:FileSearch, description:'URL, SMS veya e-posta içeriğini yapıştırın; kararı ve gerekçesini görün.', Component:lazy(()=>import('./pages/AnalyzePage.jsx'))},
  ioc: {label:'IOC / Tuzak', code:'IOC', Icon:Crosshair, description:'Zararlı IP, alan adı ve URL göstergelerini sorgulayın.', Component:lazy(()=>import('./modules/ioc.jsx'))},
}
const aliases={'phishing-detector':'phishing',honeypot:'ioc',sms:'analiz','ai-analyzer':'analiz'}
const order = Object.keys(entries)

function ModuleNav({ module, counts, onPick, layoutGroup = 'desktop' }) {
  return (
    <nav aria-label="Güvenlik modülleri" className="flex flex-col gap-1">
      <p className="mono-label mb-2 px-3">Modüller</p>
      {Object.entries(entries).map(([id, item], index) => {
        const active = id === module
        const n = counts[id] || 0
        return (
          <Link
            key={id}
            to={'/modules/' + id}
            aria-current={active ? 'page' : undefined}
            onClick={onPick}
            className={cn(
              'press group relative flex items-center gap-3 rounded-xl px-3 py-2.5 text-sm transition-colors',
              active ? 'text-foreground' : 'text-muted-foreground hover:text-foreground',
            )}
          >
            {active && (
              <motion.span layoutId={'module-nav-pill-' + layoutGroup}
                className="absolute inset-0 rounded-xl border border-primary/30 bg-primary/[0.08] shadow-[0_0_24px_-10px_var(--signal)]"
                transition={{ type: 'spring', stiffness: 520, damping: 40 }} />
            )}
            {active && <motion.span layoutId={'module-nav-bar-' + layoutGroup} className="absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-full bg-primary" transition={{ type: 'spring', stiffness: 520, damping: 40 }} />}
            <span className={cn('relative grid size-8 shrink-0 place-items-center rounded-lg border transition-colors',
              active ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border bg-card/60 group-hover:border-primary/25 group-hover:text-primary')}>
              <item.Icon className="size-4" />
            </span>
            <span className="relative flex min-w-0 flex-1 flex-col">
              <span className="truncate font-medium">{item.label}</span>
              <span className="font-mono text-[10px] tracking-[0.14em] text-muted-foreground/70">{String(index + 1).padStart(2, '0')} · {item.code}</span>
            </span>
            {n > 0 && <Badge variant="muted" className="relative shrink-0 font-mono">{n}</Badge>}
          </Link>
        )
      })}
    </nav>
  )
}

export default function ModulesApp() {
  const {module='phishing'}=useParams()
  const nav=useNavigate()
  const location=useLocation()
  const [menuOpen,setMenuOpen]=useState(false)
  const [eventsOpen,setEventsOpen]=useState(false)
  useEffect(()=>{
    const onKey=e=>{if(e.key==='Escape'){setMenuOpen(false);setEventsOpen(false)}}
    window.addEventListener('keydown',onKey)
    return ()=>window.removeEventListener('keydown',onKey)
  },[])
  const events=useEventBus(s=>s.events)
  const counts=events.reduce((acc,e)=>{acc[e.module]=(acc[e.module]||0)+1;return acc},{})
  const entry=Object.hasOwn(entries,module)?entries[module]:null
  if (!entry) return <Navigate to={'/modules/'+(entries[aliases[module]]?aliases[module]:'phishing')} replace />
  const Module=entry.Component
  const index=order.indexOf(module)+1
  const go=(target,value='',profile=null)=>{
    nav('/modules/'+(aliases[target]||target),{state:{value,profile}})
    window.scrollTo({top:0,behavior:'instant'})
  }
  const jump=(target)=>{ const t=aliases[target]||target; if(entries[t]){go(t)}; setEventsOpen(false) }

  return <div className="flex min-h-screen flex-col text-foreground">
    <header className="sticky top-0 z-40 border-b border-border/80 bg-background/85 backdrop-blur-md">
      <div className="mx-auto flex w-full max-w-[1600px] items-center gap-3 px-4 py-3 md:px-6">
        <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Modül menüsü" aria-expanded={menuOpen} onClick={()=>setMenuOpen(v=>!v)}>{menuOpen?<X/>:<Menu/>}</Button>
        <Link to="/" className="group flex items-center gap-2.5 text-foreground no-underline">
          <span className="relative grid size-9 place-items-center rounded-xl border border-primary/30 bg-primary/[0.06] shadow-[0_0_20px_-8px_var(--signal)] transition-shadow group-hover:shadow-[0_0_28px_-6px_var(--signal)]">
            <img src={logo} alt="" width="22" height="22" style={{ filter:"grayscale(1) brightness(1.4)" }}/>
          </span>
          <span className="flex flex-col leading-none">
            <span className="font-display text-[15px] font-semibold tracking-tight">AegisNexus</span>
            <span className="mt-1 font-mono text-[9.5px] tracking-[0.2em] text-muted-foreground">THREAT CONSOLE</span>
          </span>
        </Link>
        <nav className="ml-auto hidden items-center gap-1 sm:flex">
          <Link to="/dashboard" className="press rounded-lg px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground">Hesabım</Link>
          <Link to="/analyze" className="press inline-flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-sm text-foreground transition-colors hover:border-primary/40 hover:text-primary">Tek Analiz <ArrowUpRight className="size-3.5"/></Link>
        </nav>
        <Button variant="outline" size="sm" className="lg:hidden" onClick={()=>setEventsOpen(v=>!v)}>
          <Activity className="size-4"/> Olaylar {events.length>0 && <Badge variant="muted">{events.length}</Badge>}
        </Button>
      </div>
    </header>

    <AnimatePresence initial={false}>
      {menuOpen && (
        <motion.div key="mobile-menu" initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}}
          transition={{duration:0.25,ease:EASE}} className="overflow-hidden border-b border-border bg-card lg:hidden">
          <div className="p-3"><ModuleNav module={module} counts={counts} layoutGroup="mobile" onPick={()=>setMenuOpen(false)}/></div>
        </motion.div>
      )}
    </AnimatePresence>

    <div className="mx-auto grid w-full max-w-[1600px] flex-1 grid-cols-1 gap-6 p-4 md:p-6 lg:grid-cols-[236px_minmax(0,1fr)_340px]">
      <aside className="hidden lg:block">
        <div className="sticky top-[92px]">
          <ModuleNav module={module} counts={counts}/>
        </div>
      </aside>

      <main className="min-w-0">
        <motion.div key={'head-'+module} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{duration:0.4,ease:EASE}} className="relative mb-7 pb-6">
          <p className="eyebrow">Modül {String(index).padStart(2,'0')} · {entry.code}</p>
          <h1 className="mt-3 text-3xl font-semibold md:text-[40px] md:leading-[1.05]">
            <DecryptedText key={module} text={entry.label} animateOn="view" sequential revealDirection="start" speed={28}
              characters="ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789#%&@$" encryptedClassName="text-primary/70" />
          </h1>
          <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-muted-foreground">{entry.description}</p>
          <motion.span aria-hidden="true" className="absolute bottom-0 left-0 h-px w-full origin-left bg-gradient-to-r from-primary/60 via-border to-transparent"
            initial={{scaleX:0}} animate={{scaleX:1}} transition={{duration:0.9,ease:EASE,delay:0.1}} />
        </motion.div>
        <Suspense fallback={<div role="status" aria-label="Modül yükleniyor" className="flex flex-col gap-4"><Skeleton className="h-16 w-full"/><div className="grid grid-cols-2 gap-3 sm:grid-cols-4"><Skeleton className="h-24"/><Skeleton className="h-24"/><Skeleton className="h-24"/><Skeleton className="h-24"/></div><Skeleton className="h-56 w-full"/></div>}>
          <motion.div key={module+location.key} initial={{opacity:0,y:8}} animate={{opacity:1,y:0}} transition={{duration:0.3,ease:EASE}}>
            <Module initialUrl={location.state?.value||''} initialIocQuery={location.state?.value||''}
              initialProfile={location.state?.profile||null} onNavigate={go} />
          </motion.div>
        </Suspense>
      </main>

      <aside className="hidden lg:block">
        <div className="sticky top-[92px] h-[calc(100vh-116px)]">
          <LiveEventsPanel onJump={jump}/>
        </div>
      </aside>
    </div>

    <AnimatePresence>
      {eventsOpen && (
        <div key="events-drawer" className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-label="Canlı olaylar">
          <motion.button type="button" aria-label="Olayları kapat" className="absolute inset-0 cursor-default bg-black/70" onClick={()=>setEventsOpen(false)}
            initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} transition={{duration:0.2}}/>
          <motion.div className="absolute inset-y-0 right-0 w-[min(92vw,360px)] p-3"
            initial={{x:'100%'}} animate={{x:0}} exit={{x:'100%'}} transition={{type:'spring',stiffness:420,damping:42}}>
            <LiveEventsPanel className="h-full" onJump={jump}/>
          </motion.div>
        </div>
      )}
    </AnimatePresence>

    <footer className="border-t border-border/80 bg-background/90">
      <div className="mx-auto flex w-full max-w-[1600px] flex-wrap items-center justify-between gap-3 px-4 py-5 text-sm text-muted-foreground md:px-6">
        <span className="font-mono text-[11px] tracking-[0.16em]">AEGISNEXUS · AÇIK KAYNAK</span>
        <span className="flex items-center gap-5">
          <Link to="/" className="transition-colors hover:text-primary">Ana Sayfa</Link>
          <a href="/docs" className="transition-colors hover:text-primary">API belgeleri</a>
        </span>
      </div>
    </footer>
  </div>
}
