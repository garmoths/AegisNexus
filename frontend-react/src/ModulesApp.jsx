import { lazy, Suspense, useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Link, Navigate, useLocation, useNavigate, useParams } from 'react-router-dom'
import { Shield, Menu, X, Activity } from 'lucide-react'
import logo from './assets/logo.png'
import useEventBus from './stores/eventBus'
import LiveEventsPanel from './components/LiveEventsPanel'
import { Button } from './components/ui/button'
import { Badge } from './components/ui/badge'
import { Skeleton } from './components/ui/skeleton'
import { cn } from './lib/utils'

// Modül başlıkları ve açıklamaları tek yerde; her modül aynı başlık şablonuyla açılır.
const entries = {
  phishing: {label:'Phishing Tarayıcı', description:'Bir URL’yi tarayın; tehdit istihbaratı, ekran görüntüsü ve güvenilirlik puanını görün.', Component:lazy(()=>import('./modules/phishing.jsx'))},
  analiz: {label:'İçerik Analizi', description:'URL, SMS veya e-posta içeriğini yapıştırın; kararı ve gerekçesini görün.', Component:lazy(()=>import('./pages/AnalyzePage.jsx'))},
  ioc: {label:'IOC / Tuzak', description:'Zararlı IP, alan adı ve URL göstergelerini sorgulayın.', Component:lazy(()=>import('./modules/ioc.jsx'))},
}
const aliases={'phishing-detector':'phishing',honeypot:'ioc',sms:'analiz','ai-analyzer':'analiz'}

function ModuleNav({ module, counts, onPick }) {
  return (
    <nav aria-label="Güvenlik modülleri" className="flex flex-col gap-1">
      {Object.entries(entries).map(([id, item]) => {
        const active = id === module
        const n = counts[id] || 0
        return (
          <Link
            key={id}
            to={'/modules/' + id}
            aria-current={active ? 'page' : undefined}
            onClick={onPick}
            className={cn(
              'press relative flex items-center justify-between gap-2 rounded-lg px-3 py-2 text-sm transition-colors',
              active ? 'text-primary-foreground font-semibold' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )}
          >
            {active && <motion.span layoutId="module-nav-pill" className="absolute inset-0 rounded-lg bg-primary" transition={{ type: 'spring', stiffness: 500, damping: 38 }} />}
            <span className="relative truncate">{item.label}</span>
            {n > 0 ? <Badge variant={active ? 'secondary' : 'muted'} className="relative shrink-0">{n}</Badge>
              : item.status && <span className={cn('relative shrink-0 text-[11px]', active ? 'text-primary-foreground/70' : 'text-muted-foreground/70')}>{item.status}</span>}
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
  const go=(target,value='',profile=null)=>{
    nav('/modules/'+(aliases[target]||target),{state:{value,profile}})
    window.scrollTo({top:0,behavior:'instant'})
  }
  const jump=(target)=>{ const t=aliases[target]||target; if(entries[t]){go(t)}; setEventsOpen(false) }

  return <div className="flex min-h-screen flex-col bg-background text-foreground">
    <header className="sticky top-0 z-40 flex items-center gap-3 border-b border-border bg-background/90 px-4 py-3 backdrop-blur md:px-6">
      <Button variant="ghost" size="icon" className="lg:hidden" aria-label="Modül menüsü" aria-expanded={menuOpen} onClick={()=>setMenuOpen(v=>!v)}>{menuOpen?<X/>:<Menu/>}</Button>
      <Link to="/" className="flex items-center gap-2.5 font-bold text-foreground no-underline"><img src={logo} alt="" width="30" height="30"/>AegisNexus</Link>
      <nav className="ml-auto hidden items-center gap-1 sm:flex">
        <Link to="/dashboard" className="rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground">Hesabım</Link>
        <Link to="/analyze" className="rounded-md px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground">Tek Analiz</Link>
      </nav>
      <Button variant="outline" size="sm" className="lg:hidden" onClick={()=>setEventsOpen(v=>!v)}>
        <Activity className="size-4"/> Olaylar {events.length>0 && <Badge variant="muted">{events.length}</Badge>}
      </Button>
    </header>

    <AnimatePresence initial={false}>
      {menuOpen && (
        <motion.div key="mobile-menu" initial={{height:0,opacity:0}} animate={{height:'auto',opacity:1}} exit={{height:0,opacity:0}}
          transition={{duration:0.22,ease:[0.16,1,0.3,1]}} className="overflow-hidden border-b border-border bg-card lg:hidden">
          <div className="p-3"><ModuleNav module={module} counts={counts} onPick={()=>setMenuOpen(false)}/></div>
        </motion.div>
      )}
    </AnimatePresence>

    <div className="mx-auto grid w-full max-w-[1600px] flex-1 grid-cols-1 gap-5 p-4 md:p-6 lg:grid-cols-[220px_minmax(0,1fr)_340px]">
      <div className="hidden lg:block">
        <div className="sticky top-[84px]">
          <ModuleNav module={module} counts={counts}/>
        </div>
      </div>

      <main className="min-w-0">
        <motion.div key={'head-'+module} initial={{opacity:0,y:6}} animate={{opacity:1,y:0}} transition={{duration:0.25,ease:[0.16,1,0.3,1]}} className="mb-6 border-b border-border pb-5">
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-semibold tracking-tight">{entry.label}</h1>
            {entry.status && <Badge variant="outline">{entry.status}</Badge>}
          </div>
          <p className="mt-1.5 text-sm text-muted-foreground">{entry.description}</p>
        </motion.div>
        <Suspense fallback={<div role="status" aria-label="Modül yükleniyor" className="flex flex-col gap-4"><Skeleton className="h-16 w-full"/><div className="grid grid-cols-2 gap-3 sm:grid-cols-4"><Skeleton className="h-24"/><Skeleton className="h-24"/><Skeleton className="h-24"/><Skeleton className="h-24"/></div><Skeleton className="h-56 w-full"/></div>}>
          <motion.div key={module+location.key} initial={{opacity:0,y:10}} animate={{opacity:1,y:0}} transition={{duration:0.28,ease:[0.16,1,0.3,1]}}>
            <Module initialUrl={location.state?.value||''} initialIocQuery={location.state?.value||''}
              initialProfile={location.state?.profile||null} onNavigate={go} />
          </motion.div>
        </Suspense>
      </main>

      <div className="hidden lg:block">
        <div className="sticky top-[84px] h-[calc(100vh-108px)]">
          <LiveEventsPanel onJump={jump}/>
        </div>
      </div>
    </div>

    <AnimatePresence>
      {eventsOpen && (
        <div key="events-drawer" className="fixed inset-0 z-50 lg:hidden" role="dialog" aria-label="Canlı olaylar">
          <motion.div className="absolute inset-0 bg-black/70 backdrop-blur-sm" onClick={()=>setEventsOpen(false)}
            initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}} transition={{duration:0.2}}/>
          <motion.div className="absolute inset-y-0 right-0 w-[min(92vw,360px)] p-3"
            initial={{x:'100%'}} animate={{x:0}} exit={{x:'100%'}} transition={{type:'spring',stiffness:420,damping:42}}>
            <LiveEventsPanel className="h-full" onJump={jump}/>
          </motion.div>
        </div>
      )}
    </AnimatePresence>

    <footer className="flex items-center justify-center gap-5 border-t border-border py-5 text-sm text-muted-foreground">
      <Shield className="size-[18px]"/><Link to="/" className="hover:text-foreground">Ana Sayfa</Link><a href="/docs" className="hover:text-foreground">API belgeleri</a>
    </footer>
  </div>
}
