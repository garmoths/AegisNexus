import { useEffect, useState } from 'react'
import { Radar, Search, Plus, Play, Pause, ShieldCheck, RefreshCw, ArrowLeft, Globe, FileCode, Settings2, Link2, AlertCircle, CheckCircle2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { cn } from '@/lib/utils'
import type { CrawlCandidate, CrawlConfig, CrawlDetail, CrawlOverview, CrawlRelated, CrawlSource } from '@/lib/types'

type Perform = (action: () => Promise<unknown>, success: string) => Promise<unknown>

const labels: Record<string, string> = { pending:'Sırada', running:'Taranıyor', retry:'Tekrar denenecek', review:'İnceleme bekliyor', confirmed:'Onaylandı', dismissed:'Geri çekildi / elendi', blocked:'Taranamadı', failed:'Başarısız', suggested:'Öneri' }
const errorLabels: Record<string, string> = { robots_denied:'Site taramaya izin vermiyor', excluded_host:'Hariç tutulan alan', daily_budget:'Günlük sınıra ulaşıldı', fetch_failed:'Sayfa alınamadı', access_denied:'Erişim engellendi', host_busy:'Aynı site taranıyor', host_cooldown:'Site için bekleme aralığı', source_unavailable:'Kaynak okunamadı', not_html:'HTML sayfası değil', worker_timeout:'İşçi süresi doldu' }
const coverageLabels: Record<string, string> = { unknown:'Henüz incelenmedi', static:'Kaynak kodu', rendered:'Tarayıcı ile', partial:'Kısmi inceleme' }
const workerLabels: Record<string, string> = { paused:'Duraklatıldı', idle:'Hazır', running:'Çalışıyor', review:'İncelemeye hazır', retry:'Yeniden deniyor', blocked:'Erişilemedi', budget:'Günlük sınırda', busy:'Çalışıyor', deferred:'Bekliyor', worker_error:'İşçi hatası' }
const sourceLabels: Record<string, string> = { manual:'Elle eklendi', snapshot:'İçe aktarıldı', link:'Bağlantı keşfi', certstream:'CertStream (CT akışı)' }
const date = (value: string | null | undefined) => value ? new Date(value.endsWith('Z') ? value : value + 'Z').toLocaleString('tr-TR') : 'Henüz yok'

const selectCls = 'h-10 w-full rounded-md border border-input bg-background px-3 text-sm text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring'

async function request<T = unknown>(path: string, body?: unknown, method = 'POST'): Promise<T> {
  let response: Response
  try { response = await fetch('/api/v2/crawler' + path, { method: body === undefined ? 'GET' : method, credentials:'same-origin', headers:{'Content-Type':'application/json', 'X-Aegis-Local':'1'}, ...(body === undefined ? {} : {body:JSON.stringify(body)}) }) }
  catch { throw new Error('Keşif sunucusuna ulaşılamadı. Yerel konsolu ./run.sh --crawler ile açın.') }
  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) throw new Error('Bu ekran yönetici erişimi gerektirir. Hesabınızla giriş yapın veya yerel keşif konsolunu açın.')
    throw new Error(typeof data.detail === 'string' ? data.detail : Array.isArray(data.detail) ? data.detail.map((item: { msg: string })=>item.msg).join(' · ') : 'İşlem tamamlanamadı.')
  }
  return data
}

function stateBadgeVariant(state: string): 'success' | 'warning' | 'destructive' | 'muted' {
  if (state === 'confirmed') return 'success'
  if (state === 'review') return 'warning'
  if (state === 'failed' || state === 'blocked') return 'destructive'
  return 'muted'
}

export default function CrawlerPage() {
  const [tab,setTab]=useState('queue')
  const [overview,setOverview]=useState<CrawlOverview | null>(null)
  const [rows,setRows]=useState<{ data: CrawlCandidate[]; total: number }>({data:[],total:0})
  const [sources,setSources]=useState<CrawlSource[]>([])
  const [filter,setFilter]=useState('')
  const [page,setPage]=useState(1)
  const [selected,setSelected]=useState<number | null>(null)
  const [detail,setDetail]=useState<CrawlDetail | null>(null)
  const [related,setRelated]=useState<CrawlRelated[]>([])
  const [urls,setUrls]=useState('')
  const [note,setNote]=useState('')
  const [busy,setBusy]=useState(false)
  const [error,setError]=useState('')
  const [notice,setNotice]=useState('')
  const [revision,setRevision]=useState(0)
  useEffect(()=>{
    let cancelled=false
    async function refresh(){
      try{
        const [summary,list,feeds]=await Promise.all([request<CrawlOverview>('/overview'),request<{ data: CrawlCandidate[]; total: number }>(`/candidates?page=${page}&state=${encodeURIComponent(filter)}`),request<{ data: CrawlSource[] }>('/sources')])
        if(!cancelled){setOverview(summary);setRows(list);setSources(feeds.data)}
      }catch(e){if(!cancelled)setError(e instanceof Error?e.message:String(e))}
    }
    refresh()
    const timer=setInterval(refresh,5000)
    return()=>{cancelled=true;clearInterval(timer)}
  },[filter,page,revision])
  useEffect(()=>{
    if(!selected)return
    let cancelled=false
    async function load(){
      try{
        const [item,matches]=await Promise.all([request<CrawlDetail>(`/candidates/${selected}`),request<{ data: CrawlRelated[] }>(`/candidates/${selected}/related`)])
        if(!cancelled){setDetail({...item,fresh:Date.now()-new Date((item.observations?.[0]?.fetched_at||'')+'Z').getTime()<48*3600000});setRelated(matches.data)}
      }catch(e){if(!cancelled)setError(e instanceof Error?e.message:String(e))}
    }
    load()
    const timer=setInterval(load,5000)
    return()=>{cancelled=true;clearInterval(timer)}
  },[selected,revision])
  const perform: Perform=async(action,success)=>{
    if(busy)return
    setBusy(true);setError('');setNotice('')
    try{await action();setNotice(success);setRevision(v=>v+1)}catch(e){setError(e instanceof Error?e.message:String(e))}finally{setBusy(false)}
  }
  const open=(id: number)=>{setSelected(id);setDetail(null);setNote('')}
  const config=overview?.settings
  const latest=detail?.observations?.[0]
  const eligible=latest?.live && !latest?.truncated && detail?.fresh && latest?.assessment?.coverage!=='unknown' && (latest?.http_status??0)>=200 && (latest?.http_status??0)<300 && ['review','confirmed','dismissed'].includes(detail?.state??'')
  const stats=[
    ['Adaylar',Object.values(overview?.counts||{}).reduce((a: number,b: number)=>a+b,0)],
    ['İnceleme bekleyen',overview?.counts?.review||0],
    ['Onaylanan',overview?.counts?.confirmed||0],
    ['Bugünkü tarama',`${overview?.today_crawled||0} / ${config?.daily_limit||'—'}`],
  ]

  return <div className="min-h-screen bg-background text-foreground">
    <header className="sticky top-0 z-40 flex h-[72px] items-center justify-between border-b border-border bg-background/90 px-6 backdrop-blur md:px-[5%]">
      <a href="/" className="flex items-center gap-2.5 text-lg font-semibold text-foreground no-underline">
        <ShieldCheck className="text-primary"/>AegisNexus <span className="font-normal text-muted-foreground">/ Keşif</span>
      </a>
      <span className="hidden items-center gap-2 text-xs text-muted-foreground sm:flex">
        <i className="inline-block size-1.5 rounded-full bg-primary shadow-[0_0_8px_var(--primary)]"/> Kendi altyapınız · Yerel analiz
      </span>
    </header>
    <main className="mx-auto max-w-[1320px] px-5 py-10 md:px-9">
      <div className="mb-8 flex flex-col items-start justify-between gap-6 md:flex-row md:items-center">
        <div>
          <p className="mb-2.5 text-[10px] font-semibold tracking-[2px] text-primary">BAĞIMSIZ TEHDİT KEŞFİ</p>
          <h1 className="text-3xl font-semibold tracking-tight md:text-4xl">Web'i incele. Kanıtı gör.</h1>
          <p className="mt-2 max-w-xl text-sm text-muted-foreground">Şüpheli adresleri toplayın, kaynak kodunu inceleyin ve doğrulanmış bulguları ayırın.</p>
        </div>
        <Button size="lg" disabled={busy||!config} onClick={()=>config&&perform(()=>request('/settings',{...config,enabled:!config.enabled},'PATCH'),config.enabled?'Yeni taramalar duraklatıldı. Devam eden iş tamamlanır.':'Keşif başlatıldı.')} variant={config?.enabled?'secondary':'default'}>
          {config?.enabled?<Pause/>:<Play/>} {config?.enabled?'Duraklat':'Keşfi başlat'}
        </Button>
      </div>

      {error&&<Alert variant="destructive" className="mb-5"><AlertCircle/><AlertDescription className="flex w-full items-center justify-between gap-3">{error}<button className="shrink-0 underline" onClick={()=>{setError('');setRevision(v=>v+1)}}>Tekrar dene</button></AlertDescription></Alert>}
      {notice&&<Alert variant="success" className="mb-5"><CheckCircle2/><AlertDescription>{notice}</AlertDescription></Alert>}

      <div className="mb-7 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.map(([label,value])=>(
          <Card key={label}><CardContent className="p-5">
            <span className="text-xs text-muted-foreground">{label}</span>
            <strong className="mt-2 block text-2xl font-semibold tabular-nums">{value}</strong>
          </CardContent></Card>
        ))}
      </div>

      <Tabs value={tab} onValueChange={v=>{setTab(v);setSelected(null);setDetail(null)}} className="w-full">
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <TabsList>
            <TabsTrigger value="queue"><Radar className="size-4"/>Aday kuyruğu</TabsTrigger>
            <TabsTrigger value="sources"><Globe className="size-4"/>Kaynaklar</TabsTrigger>
            <TabsTrigger value="import"><FileCode className="size-4"/>Kaynak kodu incele</TabsTrigger>
            <TabsTrigger value="settings"><Settings2 className="size-4"/>Ayarlar</TabsTrigger>
          </TabsList>
          <span className="text-xs text-muted-foreground">{config?.enabled?'Keşif açık':'Keşif duraklatıldı'} · İşçi: {workerLabels[overview?.worker?.state ?? '']||'Bekleniyor'}</span>
        </div>

        <TabsContent value="queue">
          {!selected ? <>
            <Card className="mb-5">
              <CardContent className="p-6">
                <form className="grid items-end gap-5 md:grid-cols-[1fr_1.3fr_auto]" onSubmit={e=>{e.preventDefault();perform(async()=>{const result=await request<{ added: number; existing: number; rejected: { index: number; reason: string }[] }>('/candidates',{urls:urls.split('\n').map(v=>v.trim()).filter(Boolean)});if(result.rejected.length)throw new Error(`${result.added} eklendi, ${result.existing} zaten var. ${result.rejected.length} adres reddedildi: ${result.rejected[0].reason}`);setUrls('')},'Adresler kuyruğa alındı. Tekrarlanan adresler korunur.')}}>
                  <div><h2 className="text-base font-semibold">Bir adresle başlayın</h2><p className="mt-1 text-sm text-muted-foreground">Her satıra bir tam URL. Alt sayfa yolları korunur; en fazla 100 adres.</p></div>
                  <div className="grid gap-2"><Label htmlFor="crawl-seeds" className="sr-only">Taranacak adresler</Label><Textarea id="crawl-seeds" value={urls} onChange={e=>setUrls(e.target.value)} placeholder={'https://ornek.com/giris\nhttps://baska-ornek.com'} maxLength={100000} rows={2} required/></div>
                  <Button type="submit" disabled={busy||!urls.trim()}><Plus/> Aday ekle</Button>
                </form>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="flex-row items-center justify-between gap-4 space-y-0">
                <CardTitle className="flex items-center gap-2">Keşif kuyruğu <Badge variant="muted">{rows.total}</Badge></CardTitle>
                <label className="flex items-center gap-2 text-xs text-muted-foreground">Durum
                  <select className={cn(selectCls,'h-9 w-auto')} value={filter} onChange={e=>{setFilter(e.target.value);setPage(1)}}>
                    <option value="">Tümü</option>{Object.entries(labels).map(([key,label])=><option key={key} value={key}>{label}</option>)}
                  </select>
                </label>
              </CardHeader>
              <CardContent>
                {rows.data.length?<div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead><tr className="border-b border-border text-[10px] uppercase tracking-wider text-muted-foreground">
                      <th className="px-3 py-2.5 font-medium">Adres / kaynak</th><th className="px-3 py-2.5 font-medium">Risk</th><th className="px-3 py-2.5 font-medium">Kapsam</th><th className="px-3 py-2.5 font-medium">Durum</th><th className="px-3 py-2.5 font-medium">Son güncelleme</th><th/>
                    </tr></thead>
                    <tbody>{rows.data.map(row=><tr key={row.id} className="border-b border-border/60 align-top">
                      <td className="px-3 py-4"><strong className="text-[13px] font-medium">{row.host}</strong><small className="block max-w-[280px] truncate text-[10px] text-muted-foreground" title={row.url}>{row.url}</small><small className="block text-[10px] text-muted-foreground">{sourceLabels[row.source]||row.source}</small></td>
                      <td className="px-3 py-4"><Badge variant={(row.risk||0)>=55?'destructive':'muted'}>{row.risk===null?'—':`${row.risk}/100`}</Badge></td>
                      <td className="px-3 py-4 text-muted-foreground">{coverageLabels[row.coverage]||row.coverage}</td>
                      <td className="px-3 py-4"><Badge variant={stateBadgeVariant(row.state)}>{labels[row.state]||row.state}</Badge>{row.last_error&&<small className="mt-1 block text-[10px] text-muted-foreground">{errorLabels[row.last_error]||row.last_error}</small>}</td>
                      <td className="px-3 py-4 text-muted-foreground">{date(row.updated_at)}</td>
                      <td className="px-3 py-4"><button className="whitespace-nowrap text-xs font-medium text-primary hover:underline" onClick={()=>open(row.id)}>İncele →</button></td>
                    </tr>)}</tbody>
                  </table>
                </div>:<div className="flex flex-col items-center gap-2 px-5 py-12 text-center text-muted-foreground">
                  <Search className="size-8 text-primary"/><h3 className="text-foreground">{overview?'Henüz aday yok':'Keşif konsoluna bağlanılıyor'}</h3>
                  <p className="max-w-md text-sm">Adres ekleyin veya bir HTML örneğiyle başlayın. Toplanan adresler otomatik phishing sayılmaz.</p>
                </div>}
                <div className="mt-5 flex items-center justify-end gap-4 text-xs text-muted-foreground">
                  <Button variant="outline" size="sm" disabled={page<=1} onClick={()=>setPage(v=>v-1)}>Önceki</Button><span>Sayfa {page}</span><Button variant="outline" size="sm" disabled={page*30>=rows.total} onClick={()=>setPage(v=>v+1)}>Sonraki</Button>
                </div>
              </CardContent>
            </Card>
          </> : <>
            <Button variant="ghost" size="sm" className="mb-5 -ml-2" onClick={()=>{setSelected(null);setDetail(null)}}><ArrowLeft/> Kuyruğa dön</Button>
            {!detail?<p role="status" className="text-muted-foreground">Kanıtlar yükleniyor…</p>:<div className="grid items-start gap-5 lg:grid-cols-[minmax(0,1.6fr)_minmax(280px,1fr)]">
              <Card><CardContent className="p-6">
                <p className="text-[10px] font-semibold tracking-[2px] text-primary">ADAY #{detail.id} · {labels[detail.state]}</p>
                <h2 className="mt-1 text-xl font-semibold">{detail.host}</h2>
                <p className="mt-1 break-all font-mono text-sm text-muted-foreground">{detail.url}</p>
                <p className="mt-2 text-sm text-muted-foreground">{detail.reason}</p>
                {latest?<>
                  <div className="my-5 flex items-center gap-5 border-y border-border py-5">
                    <strong className="text-3xl font-semibold">{latest.assessment.risk===null?'—':`${latest.assessment.risk}/100`}</strong>
                    <span className="text-xs text-muted-foreground">Risk puanı · {latest.assessment.coverage}<br/>{latest.live?'Canlı gözlem':'İçe aktarılan kaynak'} · {date(latest.fetched_at)}</span>
                  </div>
                  <h3 className="mb-2.5 text-sm font-semibold">Gözlenen işaretler</h3>
                  {latest.assessment.evidence.length?<ul className="list-none">{latest.assessment.evidence.map(e=><li key={e.code} className="border-b border-border/60 py-3"><strong className="text-[10px] uppercase tracking-wider text-primary">{e.group}</strong><p className="text-xs text-muted-foreground">{e.detail}</p></li>)}</ul>:<p className="text-sm text-muted-foreground">Belirgin işaret bulunamadı. Bu, sayfanın güvenli olduğunu doğrulamaz.</p>}
                  <div className="mt-5 grid grid-cols-[120px_1fr] gap-2 break-all text-xs"><span className="text-muted-foreground">Başlık</span><p>{latest.features.title||'Yok'}</p><span className="text-muted-foreground">Marka adları</span><p>{latest.features.brands.join(', ')||'Yok'}</p><span className="text-muted-foreground">Formlar</span><p>{latest.features.forms.length} form</p><span className="text-muted-foreground">Script / tracker</span><p>{latest.features.scripts.length} / {latest.features.trackers.length}</p><span className="text-muted-foreground">Son adres</span><p>{latest.final_url}</p></div>
                  {latest.features.forms.map((form,index)=><p className="mt-2.5 break-all rounded-md border border-border p-2.5 text-[11px]" key={index}>{form.fields.join(', ')||'Standart form'} → {form.target_host||'Hedef çözümlenemedi'} · {form.method.toUpperCase()}</p>)}
                  {latest.has_screenshot&&<img className="mt-5 w-full rounded-lg border border-border" src={`/api/v2/crawler/observations/${latest.id}/screenshot`} alt="Taranan sayfanın çalıştırılmayan ekran görüntüsü"/>}
                  <details className="mt-5"><summary className="cursor-pointer text-xs text-muted-foreground">Script ve tracker kanıtları</summary><pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md bg-background p-4 text-[10px] text-muted-foreground">{JSON.stringify({scripts:latest.features.scripts,script_hashes:latest.features.script_hashes,trackers:latest.features.trackers},null,2)}</pre></details>
                </>:<p className="mt-4 text-sm text-muted-foreground">Henüz gözlem yok. {(detail.last_error && errorLabels[detail.last_error])||detail.last_error}</p>}
              </CardContent></Card>

              <aside className="flex flex-col gap-5">
                <Card><CardContent className="p-6">
                  <h2 className="text-base font-semibold">İnceleme kararı</h2>
                  <p className="mt-1 text-sm text-muted-foreground">Risk puanı olasılık değildir. Kaydı yalnızca kanıtları inceledikten sonra onaylayın.</p>
                  <Label htmlFor="review-note" className="mt-4 block">Karar gerekçesi</Label>
                  <Textarea id="review-note" className="mt-2" value={note} onChange={e=>setNote(e.target.value)} rows={4} maxLength={2000} placeholder="Hangi bulgu kararınızı destekliyor?"/>
                  <Button className="mt-3 w-full" disabled={busy||!eligible||note.trim().length<5} onClick={()=>perform(()=>request(`/candidates/${selected}/review`,{decision:'confirmed',observation_id:latest?.id,note}),'Phishing kaydı onaylandı.')}>Phishing olarak onayla</Button>
                  <Button variant="secondary" className="mt-2 w-full" disabled={busy||!latest||!['review','confirmed','dismissed'].includes(detail.state)||note.trim().length<5} onClick={()=>perform(()=>request(`/candidates/${selected}/review`,{decision:'dismissed',observation_id:latest?.id,note}),'Aday elendi; bu crawler’ın varsa yayını geri çekildi.')}>Yanlış pozitif / geri çek</Button>
                  <Button variant="outline" className="mt-2 w-full" disabled={busy||detail.state==='running'} onClick={()=>perform(()=>request(`/candidates/${selected}/retry`,{}),'Yeniden tarama kuyruğuna alındı.')}><RefreshCw className="size-3.5"/> Yeniden tara</Button>
                  {!eligible&&<small className="mt-2.5 block text-[11px] text-muted-foreground">Onay için son 48 saat içinde başarılı ve tam bir canlı gözlem gerekir.</small>}
                </CardContent></Card>
                <Card><CardContent className="p-6">
                  <h2 className="flex items-center gap-2 text-base font-semibold"><Link2 className="size-[17px]"/> İlişkili gözlemler</h2>
                  <p className="mt-1 text-sm text-muted-foreground">Son 500 gözlem içinde kod ve parmak izi benzerliği. Aynı saldırgan veya phishing kanıtı değildir.</p>
                  {related.length?<div className="mt-2">{related.map(item=><button key={item.candidate_id} className="w-full border-b border-border/60 py-3 text-left break-all text-sm text-foreground/90 hover:text-primary" onClick={()=>open(item.candidate_id)}>{item.url}<small className="block text-[11px] text-muted-foreground">{item.reasons.join(' · ')}</small></button>)}</div>:<small className="mt-2 block text-[11px] text-muted-foreground">Eşleşme bulunmadı.</small>}
                </CardContent></Card>
                <Card><CardContent className="p-6">
                  <h2 className="text-base font-semibold">Karar geçmişi</h2>
                  {detail.reviews.length?<div className="mt-2">{detail.reviews.map((item,index)=><div className="border-t border-border/60 py-3 text-xs first:border-t-0" key={index}><strong>{labels[item.decision]||item.decision}</strong><p className="text-muted-foreground">{item.note}</p><small className="text-[11px] text-muted-foreground">{item.actor} · {date(item.created_at)}</small></div>)}</div>:<p className="mt-2 text-sm text-muted-foreground">Henüz karar yok.</p>}
                </CardContent></Card>
              </aside>
            </div>}
          </>}
        </TabsContent>

        <TabsContent value="sources"><Sources sources={sources} perform={perform} busy={busy}/></TabsContent>
        <TabsContent value="import"><SnapshotImport perform={perform} busy={busy} onOpen={id=>{setTab('queue');open(id)}}/></TabsContent>
        <TabsContent value="settings">{config&&<Configuration config={config} perform={perform} busy={busy}/>}</TabsContent>
      </Tabs>

      <Separator className="mt-10"/>
      <footer className="flex flex-col justify-between gap-2 py-5 text-[10px] text-muted-foreground sm:flex-row">
        <span>AegisNexus Discovery · Kanıtlar size ait.</span><span>LLM ve ücretli tehdit API'si gerektirmez.</span>
      </footer>
    </main>
  </div>
}

function Sources({sources,perform,busy}: { sources: CrawlSource[]; perform: Perform; busy: boolean }){
  const [name,setName]=useState(''),[url,setUrl]=useState(''),[kind,setKind]=useState('url_list')
  return <div className="grid items-start gap-5 lg:grid-cols-2">
    <Card><CardContent className="p-6">
      <h2 className="text-base font-semibold">Keşif kaynakları</h2>
      <p className="mt-1 text-sm text-muted-foreground">URL listesi ve CT JSON kaynakları keşif açıkken saatlik okunur. CertStream canlı akışı sürekli dinlenir. Her adres yalnızca adaydır.</p>
      {sources.length?<div className="mt-2">{sources.map(source=><div className="border-t border-border/60 py-5 first:border-t-0" key={source.id}>
        <div className="flex items-center gap-2"><strong className="text-sm">{source.name}</strong><Badge variant="outline">{sourceLabels[source.kind]||source.kind}</Badge></div>
        <p className="mt-1 break-all text-xs text-muted-foreground">{source.url}</p>
        <small className="mt-1 block text-[11px] text-muted-foreground">{source.added_count} aday · {date(source.last_checked_at)}</small>
        {source.last_error&&<p className="mt-1 text-xs text-destructive">{errorLabels[source.last_error]||source.last_error}</p>}
        <Button variant="ghost" size="sm" className="mt-2 -ml-2 text-destructive hover:text-destructive" disabled={busy} onClick={()=>perform(()=>request(`/sources/${source.id}`,{},'DELETE'),'Kaynak kaldırıldı.')}>Kaldır</Button>
      </div>)}</div>:<div className="mt-4 rounded-lg border border-dashed border-border px-5 py-8 text-center text-sm text-muted-foreground">Henüz kaynak eklenmedi. Tek URL ile de başlayabilirsiniz.</div>}
    </CardContent></Card>
    <Card><CardContent className="p-6">
      <form onSubmit={e=>{e.preventDefault();perform(async()=>{await request('/sources',{name,url,kind});setName('');setUrl('')},'Kaynak eklendi.')}}>
        <h2 className="text-base font-semibold">Kaynak ekle</h2>
        <div className="mt-4 grid gap-2"><Label htmlFor="src-name">Kaynak adı</Label><Input id="src-name" value={name} onChange={e=>setName(e.target.value)} required minLength={2} maxLength={120}/></div>
        <div className="mt-4 grid gap-2"><Label htmlFor="src-kind">Biçim</Label>
          <select id="src-kind" className={selectCls} value={kind} onChange={e=>setKind(e.target.value)}>
            <option value="url_list">Satır başına URL</option>
            <option value="ct_json">CT JSON — name_value alanı</option>
            <option value="certstream">CertStream — canlı CT akışı (ücretsiz)</option>
          </select>
        </div>
        {kind!=='certstream' && <div className="mt-4 grid gap-2"><Label htmlFor="src-url">Kaynak adresi</Label><Input id="src-url" value={url} onChange={e=>setUrl(e.target.value)} required={kind!=='certstream'} maxLength={4096} placeholder="https://…"/></div>}
        <p className="mt-3 text-xs text-muted-foreground">{kind==='certstream'?'Sabit, ücretsiz genel CT uç noktası dinlenir; adres girmeniz gerekmez. Eşleşen alan adları süzülerek aday olur.':'Herkese açık HTTP(S) kaynakları desteklenir. CT kaydı, yeni alan adı veya phishing olduğu anlamına gelmez.'}</p>
        <Button type="submit" className="mt-4" disabled={busy}>Kaynağı ekle</Button>
      </form>
    </CardContent></Card>
  </div>
}

function SnapshotImport({perform,busy,onOpen}: { perform: Perform; busy: boolean; onOpen: (id: number) => void }){
  const [url,setUrl]=useState(''),[html,setHtml]=useState('')
  return <Card className="max-w-3xl"><CardContent className="p-6">
    <form onSubmit={e=>{e.preventDefault();perform(async()=>{const result=await request<{ id: number }>('/snapshots',{url,html});onOpen(result.id)},'Kaynak kod incelendi. Canlı tarama yapılmadı.')}}>
      <h2 className="text-base font-semibold">HTML kaynak kodunu incele</h2>
      <p className="mt-1 text-sm text-muted-foreground">Kaynak kod çalıştırılmaz ve hedef siteye istek yapılmaz. İçe aktarılan gözlem canlı doğrulama yerine geçmez.</p>
      <div className="mt-4 grid gap-2"><Label htmlFor="snap-url">Sayfanın tam adresi</Label><Input id="snap-url" value={url} onChange={e=>setUrl(e.target.value)} required maxLength={4096} placeholder="https://ornek.com/giris"/></div>
      <div className="mt-4 grid gap-2"><Label htmlFor="snap-html">HTML kaynak kodu</Label><Textarea id="snap-html" rows={12} value={html} onChange={e=>setHtml(e.target.value)} required maxLength={1000000} placeholder="<!doctype html>…" spellCheck={false} className="font-mono text-xs"/></div>
      <Button type="submit" className="mt-4" disabled={busy||!html.trim()}>Kaynak kodunu incele</Button>
    </form>
  </CardContent></Card>
}

function Configuration({config,perform,busy}: { config: CrawlConfig; perform: Perform; busy: boolean }){
  const [daily,setDaily]=useState(String(config.daily_limit)),[browserLimit,setBrowserLimit]=useState(String(config.browser_limit)),[browser,setBrowser]=useState(config.browser_enabled),[excluded,setExcluded]=useState(config.excluded_hosts.join('\n'))
  return <Card className="max-w-3xl"><CardContent className="p-6">
    <form onSubmit={e=>{e.preventDefault();perform(()=>request('/settings',{...config,daily_limit:Number(daily),browser_limit:Number(browserLimit),browser_enabled:browser,excluded_hosts:excluded.split('\n').map(v=>v.trim()).filter(Boolean)},'PATCH'),'Ayarlar kaydedildi.')}}>
      <h2 className="text-base font-semibold">Kontrollü keşif</h2>
      <p className="mt-1 text-sm text-muted-foreground">Taramalar iki seviye ve başlangıç adresi başına beş sayfa ile sınırlıdır. Formlar gönderilmez. robots.txt ve hariç tutulan alanlar gözetilir.</p>
      <div className="mt-4 grid gap-5 sm:grid-cols-2">
        <div className="grid gap-2"><Label htmlFor="cfg-daily">Günlük aday tarama sınırı</Label><Input id="cfg-daily" type="number" min={1} max={10000} value={daily} onChange={e=>setDaily(e.target.value)} required/></div>
        <div className="grid gap-2"><Label htmlFor="cfg-browser">Günlük tarayıcı sınırı</Label><Input id="cfg-browser" type="number" min={0} max={500} value={browserLimit} onChange={e=>setBrowserLimit(e.target.value)} required/></div>
      </div>
      <label className="mt-4 flex items-center gap-2.5 text-sm"><input type="checkbox" className="size-4 accent-[color:var(--primary)]" checked={browser} onChange={e=>setBrowser(e.target.checked)}/> Ön incelemede risk işareti bulunan sayfalarda izole tarayıcı kullan</label>
      <p className="mt-2 text-xs text-muted-foreground">Chromium kurulu olmalıdır. Tarayıcı kullanılamazsa statik kanıt korunur; eksik inceleme güvenli sonuç sayılmaz.</p>
      <div className="mt-4 grid gap-2"><Label htmlFor="cfg-excluded">Hariç tutulan alanlar</Label><Textarea id="cfg-excluded" value={excluded} onChange={e=>setExcluded(e.target.value)} rows={5} placeholder={'ornek.com\nbaska-ornek.com'}/></div>
      <Button type="submit" className="mt-4" disabled={busy}>Ayarları kaydet</Button>
    </form>
  </CardContent></Card>
}
