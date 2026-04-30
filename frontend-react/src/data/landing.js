// Tüm landing sayfası içerikleri tek dosyada toplanmıştır.
// İleride i18n için bu dosya namespace bazlı dilim (TR/EN) yapısına taşınabilir.

export const kpis = [
  { value: 1.24, suffix: 'M+', label: 'Taranan Phishing URL', desc: 'Son 12 ayda analiz edilen şüpheli adres', color: '#00d4ff' },
  { value: 9.4, suffix: 'K', label: 'Aktif IOC', desc: 'Korelasyon motorunda canlı tutulan tehdit göstergesi', color: '#ff6b35' },
  { value: 99.97, suffix: '%', label: 'Platform Uptime', desc: 'Son 90 günlük SLA üzeri kullanılabilirlik', color: '#22c55e' },
  { value: 1.8, suffix: 's', label: 'Ortalama Analiz', desc: 'AI motorunun tek URL için yanıt süresi', color: '#9f7aea' },
]

export const modules = [
  {
    icon: '🤖',
    title: 'AI Güvenlik Asistanı',
    badge: 'AKTIF',
    color: '#00d4ff',
    subtitle: 'Bağlamsal Tehdit Yorumlayıcı',
    desc: 'DeepSeek ve Groq tabanlı çift LLM mimarisi; gelen tehditleri kullanıcı bağlamıyla yorumlar, anlaşılır Türkçe öneri ve SOC için makine okunabilir özet üretir.',
  },
  {
    icon: '🎣',
    title: 'Phishing Dedektörü',
    badge: 'ANALIZ',
    color: '#ff6b35',
    subtitle: 'URL · SSL · Domain Reputation',
    desc: 'Bir URL için 40+ özellik üzerinden risk skoru: domain yaşı, sertifika anomalisi, homoglif benzerliği, hosting itibar değeri ve içerik desen analizi.',
  },
  {
    icon: '🕸️',
    title: 'Honeypot & IOC',
    badge: 'CANLI',
    color: '#f59e0b',
    subtitle: 'Sinyal Korelasyon Katmanı',
    desc: 'Türkiye odaklı dağıtık honeypot ağından gelen ham sinyalleri AbuseIPDB, OTX ve URLhaus ile çapraz doğrulayıp tek IOC akışına çevirir.',
  },
  {
    icon: '🔓',
    title: 'Veri Sızıntı Radarı',
    badge: 'SCAN',
    color: '#ef4444',
    subtitle: 'Leak Surface Mapping',
    desc: 'E-posta, kullanıcı adı veya domain bazında bilinen veri sızıntılarını tarar; saldırgan zincirini tahmin etmek için tarihçeli görselleştirme sunar.',
  },
  {
    icon: '🔐',
    title: 'Kriptografik Kalkan',
    badge: 'HARDEN',
    color: '#22c55e',
    subtitle: 'Şifre & Anahtar Sağlığı',
    desc: 'Şifreler tarayıcı tarafında üretilir, hiçbir ham veri sunucuya gönderilmez. Şifre dayanıklılığı, yeniden kullanım ve sızıntı kontrolü tek panelde.',
  },
]

// voxr.ai "Your Path from Leads to Live Conversations" pattern'inden esinlenen
// numaralı dikey adım listesi.
export const platformPath = [
  {
    num: '01',
    title: 'Bağla',
    desc: 'AegisNexus’ı SIEM/SOAR, e-posta gateway ve kimlik sağlayıcılarınıza dakikalar içinde bağlayın. Hazır konnektörler, REST API ve webhook desteği ile mevcut ekosisteminizi bozmadan çalışır.',
  },
  {
    num: '02',
    title: 'Keşfet',
    desc: 'Dış yüzey, kullanıcı kimlikleri ve kritik varlıklarınız tek panelde haritalanır. Risk skoru otomatik hesaplanır; önceliklendirilmiş bir varlık envanteri elde edersiniz.',
  },
  {
    num: '03',
    title: 'Tespit Et',
    desc: '10+ tehdit beslemesi ve Türkiye odaklı honeypot sinyalleri çift LLM triyajdan geçer. Gürültü filtrelenir; SOC ekibinize yalnızca aksiyon almaya değer alarmlar düşer.',
  },
  {
    num: '04',
    title: 'Yanıt Ver',
    desc: 'NIST 800-61 playbook’ları ile ortalama 18 dakikada containment. Her aksiyon zaman damgalı kanıt zincirine yazılır; denetim ve adli analiz hazır.',
  },
  {
    num: '05',
    title: 'İyileştir',
    desc: 'Her olay metriklere dökülür; KPI panelinden risk drift’inizi izleyin, kontrolleri proaktif sıkılaştırın. Olgunluk eğriniz tek bakışta görünür.',
  },
]

// Son 24 saat tehdit grafiği için sentetik veri (saatlik bucket).
// Backend canlıya bağlandığında /api/v2/telemetry/last-24h ile değiştirilecek.
export const threatLast24h = Array.from({ length: 24 }, (_, i) => {
  const base = 80 + Math.sin((i / 24) * Math.PI * 2) * 35
  const noise = ((i * 1103515245 + 12345) % 47) // determinist, SSR/CSR uyumlu
  return {
    hour: `${String(i).padStart(2, '0')}:00`,
    blocked: Math.max(0, Math.round(base + noise * 0.6)),
    flagged: Math.max(0, Math.round(base * 0.35 + noise * 0.4)),
  }
})

export const threatSparks = [
  { label: 'Phishing URL', value: '+412', delta: '+8.2%', color: '#00d4ff' },
  { label: 'Malware C2', value: '+87', delta: '+3.1%', color: '#ff6b35' },
  { label: 'Brute Force', value: '+1.2K', delta: '+12.4%', color: '#ef4444' },
  { label: 'Şüpheli Login', value: '+318', delta: '−2.7%', color: '#22c55e' },
]

export const cases = [
  {
    sector: 'E-Ticaret',
    title: 'Sezon kampanyasında phishing dalgasını engelledik',
    summary: 'Black Friday öncesi marka taklidi yapan 217 sahte alan adı 6 saat içinde tespit edilip takedown sürecine alındı.',
    metric: '−92%',
    metricLabel: 'Marka taklidi tıklamaları',
    color: '#00d4ff',
  },
  {
    sector: 'Fintech',
    title: 'Sızdırılmış API anahtarlarını dakikalar içinde rotated ettik',
    summary: 'GitHub yüzeyinde sızan 4 anahtar tespit edildi, otomatik rotation playbook’u tetiklendi, müşteri etkisi sıfır.',
    metric: '0',
    metricLabel: 'Etkilenen kullanıcı',
    color: '#9f7aea',
  },
  {
    sector: 'Sağlık',
    title: 'Hastane ağında ransomware lateral movement’ı kestik',
    summary: 'Honeypot tetiklenmesinden sonra 11 dakika içinde containment sağlandı; veri sızıntısı oluşmadı.',
    metric: '11dk',
    metricLabel: 'Containment süresi',
    color: '#ef4444',
  },
  {
    sector: 'KOBİ Portföyü',
    title: '6 ayda başarılı phishing tıklamaları %38 düştü',
    summary: '12 KOBİ’nin oluşturduğu pilot grupta otomatik kullanıcı eğitimi + URL filtreleme entegrasyonu.',
    metric: '−38%',
    metricLabel: 'Başarılı saldırı oranı',
    color: '#22c55e',
  },
]

export const incidentSteps = [
  { phase: 'Detect', icon: '📡', title: 'Tespit', desc: 'AI triyaj ve IOC korelasyonu olayı saniyeler içinde gündeme alır.' },
  { phase: 'Triage', icon: '🧠', title: 'Önceliklendirme', desc: 'Etki, güven skoru ve varlık kritikliğine göre playbook seçilir.' },
  { phase: 'Contain', icon: '🛡️', title: 'Sınırlandırma', desc: 'Etkilenen kimlik/oturum/host izole edilir, lateral movement durdurulur.' },
  { phase: 'Eradicate', icon: '🧹', title: 'Temizleme', desc: 'IOC’ler kaldırılır, kalıcılık mekanizmaları sökülür, kanıt korunur.' },
  { phase: 'Recover', icon: '🔄', title: 'Geri Dönüş', desc: 'Sistemler doğrulanır, post-mortem yazılır, kontroller sıkılaştırılır.' },
]

export const testimonials = [
  {
    quote: 'AegisNexus’u kurduktan sonra ilk ay içinde fark ettiğimiz phishing kampanyası bize altı haneli zarar yazdırırdı. Hızlı kurulum, net Türkçe raporlama.',
    author: 'CISO',
    role: 'Orta ölçek e-ticaret',
    color: '#00d4ff',
  },
  {
    quote: 'Honeypot sinyallerinin SOC paneline dakikalar içinde düşmesi, bizim için oyun değiştirici oldu. Eskiden saatler süren korelasyon artık otomatik.',
    author: 'SecOps Lead',
    role: 'Fintech',
    color: '#9f7aea',
  },
  {
    quote: 'KVKK denetimine girerken eksik kontrollerimizi haftalar değil günler içinde kapattık. Kanıt zinciri otomatik üretiliyor.',
    author: 'BT Müdürü',
    role: 'Sağlık grubu',
    color: '#22c55e',
  },
  {
    quote: 'KOBİ olarak kendi SOC’umuzu kuramazdık. AegisNexus sayesinde kurumsal seviye telemetriye erişim sağladık.',
    author: 'Kurucu',
    role: 'SaaS startup',
    color: '#ff6b35',
  },
]

export const why = [
  { icon: '🧠', title: 'Yapay Zeka Destekli', desc: 'Çift LLM mimarisi (DeepSeek + Groq) ile gerçek zamanlı triyaj. Tek model down olsa bile servis kesintisiz.' },
  { icon: '🌐', title: 'Gerçek Zamanlı İstihbarat', desc: '10+ kaynaktan beslenen, Türkiye’ye özel honeypot sinyalleriyle zenginleştirilmiş tehdit akışı.' },
  { icon: '🛡️', title: '5 Katmanlı Koruma', desc: 'AI Analiz → Phishing → IOC → Sızıntı → Kripto. Tek bir kapı değil, üst üste kalkanlar.' },
  { icon: '🇹🇷', title: 'Türkçe & KVKK Uyumlu', desc: 'Türkçe arayüz, KVKK ve GDPR uyumlu veri işleme; Türkiye’deki tehdit yüzeyine özel kurallar.' },
  { icon: '🔒', title: 'Gizlilik Önce', desc: 'Şifreler ve hassas içerik sunucuya gönderilmez; kriptografik işlemler tarayıcıda yapılır.' },
  { icon: '📊', title: 'Açıklanabilir Raporlar', desc: 'Her uyarı için neden-sonuç açıklaması, PDF export ve e-posta bildirimleri.' },
]
