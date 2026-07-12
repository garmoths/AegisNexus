// Tüm landing sayfası içerikleri tek dosyada toplanmıştır.
// İleride i18n için bu dosya namespace bazlı dilim (TR/EN) yapısına taşınabilir.

export const kpis = [
  { value: 1.7, suffix: 'M+', label: 'Taranan Phishing URL', desc: 'Son 12 ayda analiz edilen şüpheli adres', color: '#00d4ff' },
  { value: 30, suffix: 'K', label: 'Aktif IOC', desc: 'Korelasyon motorunda canlı tutulan tehdit göstergesi', color: '#ff6b35' },
  { value: 99.97, suffix: '%', label: 'Platform Uptime', desc: 'Son 90 günlük SLA üzeri kullanılabilirlik', color: '#22c55e' },
  { value: 1.8, suffix: 's', label: 'Ortalama Analiz', desc: 'AI motorunun tek URL için yanıt süresi', color: '#9f7aea' },
]

export const modules = [
  {
    title: 'AI Güvenlik Asistanı',
    badge: 'AKTIF',
    color: '#00d4ff',
    subtitle: 'Bağlamsal Tehdit Yorumlayıcı',
    desc: 'DeepSeek + Groq çift LLM mimarisi; gelen tehditleri kullanıcı geçmişi ve varlık bağlamıyla yorumlar. SOC için makine okunabilir JSON özet, analist için anlaşılır Türkçe açıklama — tek sorguda her ikisi de üretilir.',
  },
  {
    title: 'Phishing Dedektörü',
    badge: 'ANALIZ',
    color: '#ff6b35',
    subtitle: 'URL · SSL · Domain Reputation',
    desc: 'Bir bağlantıyı 40\u2019tan fazla sinyalle değerlendirir: domain yaşı, homoglif saldırısı, SSL anomalisi, hosting itibar skoru, sayfa içerik deseni ve SMS kurban atlasındaki görünme sıklığı. Sonuç: 0–100 risk skoru ve eylem önerisi.',
  },
  {
    title: 'Honeypot & IOC',
    badge: 'CANLI',
    color: '#f59e0b',
    subtitle: 'Sinyal Korelasyon Katmanı',
    desc: 'Türkiye odaklı dağıtık honeypot ağından saniyede toplanan sinyalleri AbuseIPDB, OTX ve URLhaus ile çapraz doğrular; temizlenmiş 30.000+ IOC\u2019yi tek akışta sunar. Her kayıt kaynak, güven skoru ve ilişkili saldırı grubu etiketiyle gelir.',
  },
  {
    title: 'Veri Sızıntı Radarı',
    badge: 'SCAN',
    color: '#ef4444',
    subtitle: 'Leak Surface Mapping',
    desc: '1,7 milyonun üzerinde kayıtlı phishing URL ve sızıntı veritabanında e-posta, domain veya kullanıcı adı tarar. Tespit edilen sızıntı ağ haritasıyla görselleştirilir; olası saldırgan zinciri tahmin edilir.',
  },
  {
    title: 'Kriptografik Kalkan',
    badge: 'HARDEN',
    color: '#22c55e',
    subtitle: 'Şifre & Anahtar Sağlığı',
    desc: 'Şifre üretimi ve hash kontrolü tarayıcı tarafında çalışır — hiçbir ham veri sunucuya iletilmez. Şifre dayanıklılığı, yeniden kullanım tespiti ve bilinen sızıntı kontrolü tek ekranda; KVKK uyumlu işlem kaydıyla.',
  },
]

// voxr.ai "Your Path from Leads to Live Conversations" pattern'inden esinlenen
// numaralı dikey adım listesi.
export const platformPath = [
  {
    num: '01',
    title: 'Bağla',
    desc: 'AegisNexus’ı SIEM, SOAR, e-posta gateway ve kimlik sağlayıcılarınıza dakikalar içinde entegre edin. 20+ hazır konnektör, REST API ve webhook desteğiyle mevcut araç zincirinizi sıfırdan değiştirmeniz gerekmez.',
  },
  {
    num: '02',
    title: 'Keşfet',
    desc: 'Dış saldırı yüzeyi, tüm kullanıcı kimlikleri ve kritik varlıklar tek panelde otomatik haritalanır. Risk skoru anlık hesaplanır; öncelik sırasına göre işlem bekleyen kontrol listesi oluşturulur.',
  },
  {
    num: '03',
    title: 'Tespit Et',
    desc: '10+ tehdit beslemesi ve honeypot ham sinyalleri çift LLM triyajdan geçer. Korelasyon motoru gürültüyü filtreler; SOC ekibinize yalnızca aksiyon almaya değer, bağlamlanmış alarmlar iletilir.',
  },
  {
    num: '04',
    title: 'Yanıt Ver',
    desc: 'NIST 800-61 playbook’larıyla ortalama 18 dakikada containment. Her aksiyon zaman damgalı ve imzalı kanıt zincirine yazılır; adli analiz ve KVKK denetimi için hazır raporlar otomatik oluşturulur.',
  },
  {
    num: '05',
    title: 'İyileştir',
    desc: 'Her olay MTTD, MTTR ve risk drift metrikleriyle puanlanır. Trend grafikleri ekibinizin olgunluk eğrisini gösterir; kapatılmamış kontroller proaktif olarak öne çekilir.',
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
    summary: 'Black Friday öncesi marka taklidi yapan 217 sahte domain, Breach Intelligence modülü tarafından 6 saat içinde tespit edilip otomatik takedown sürecine alındı. Kampanya döneminde sıfır başarılı kimlik avı vakası raporlandı.',
    metric: '−92%',
    metricLabel: 'Marka taklidi tıklamaları',
    color: '#00d4ff',
  },
  {
    sector: 'Fintech',
    title: 'Sızdırılmış API anahtarlarını dakikalar içinde rotated ettik',
    summary: 'Açık GitHub repolarında sızan 4 API anahtarı, Veri Sızıntı Radarı tarafından commit anında işaretlendi. Otomatik rotation playbook tetiklendi; saldırgan erişim penceresi 4 dakikayla sınırlı kaldı, hiçbir müşteri hesabı etkilenmedi.',
    metric: '0',
    metricLabel: 'Etkilenen kullanıcı',
    color: '#9f7aea',
  },
  {
    sector: 'Sağlık',
    title: 'Hastane ağında ransomware lateral movement’ı kestik',
    summary: 'Honeypot ağı fidye yazılımı yayılma sinyalini tespit ettikten 11 dakika sonra etkilenen segment otomatik izole edildi. Üçüncü taraf denetim raporunda KVKK’ya tam uyum teyit edildi, veri sızıntısı oluşmadı.',
    metric: '11dk',
    metricLabel: 'Containment süresi',
    color: '#ef4444',
  },
  {
    sector: 'KOBİ Portföyü',
    title: '6 ayda başarılı phishing tıklamaları %38 düştü',
    summary: '12 KOBİ’lik pilot grupta Phishing Dedektörü, URL filtreleme ve otomatik kullanıcı eğitimi tetikleyicileriyle entegrasyon kuruldu. Altı ay içinde başarılı phishing tıklama oranı %38 geriledi.',
    metric: '−38%',
    metricLabel: 'Başarılı saldırı oranı',
    color: '#22c55e',
  },
]

export const incidentSteps = [
  { phase: 'Detect', title: 'Tespit', desc: 'DeepSeek tabanlı AI triyaj motoru, ham sinyali 30.000+ IOC veritabanıyla milisaniyeler içinde eşleştirir; kritik olay saniyeler içinde SOC paneline düşer.' },
  { phase: 'Triage', title: 'Önceliklendirme', desc: 'Olayın etki yarıçapı, varlık kritikliği ve güven skoru otomatik hesaplanır; duruma en uygun NIST playbook seçilip tetiklenir.' },
  { phase: 'Contain', title: 'Sınırlandırma', desc: 'Etkilenen kimlik, oturum ve host otomatik izole edilir. Lateral movement vektörleri kapatılır, saldırı yüzeyi dondurulur — müdahale ekibine hazır zemin bırakılır.' },
  { phase: 'Eradicate', title: 'Temizleme', desc: 'IOC’ler kaldırılır, kalıcılık mekanizmaları (cron, servis, registry girişi) sökümlenir. Tüm adımlar değiştirilemez kanıt zincirine yazılır.' },
  { phase: 'Recover', title: 'Geri Dönüş', desc: 'Sistem bütünlüğü doğrulandıktan sonra servis restore edilir. Otomatik post-mortem raporu yazılır; kontroller sıkılaştırılarak döngü kapatılır.' },
]

export const testimonials = [
  {
    quote: 'AegisNexus\'u sıfırdan inşa ederken en büyük önceliğimiz Türkiye\'ye özgü tehdit yüzeyini gerçek veriyle kapsayan bir platform kurmaktı. Honeypot ağı, breach intelligence ve AI triyaj — üçü birleşince gerçekten fark yaratan bir savunma katmanı oluşuyor.',
    author: 'Enes Tekdemir',
    role: 'Founder & Backend Dev',
    color: '#00d4ff',
  },
  {
    quote: 'Kullanıcının tek bakışta durumu anlamasını sağlayan bir arayüz kurmak için tasarım ve veri görselleştirmeye aynı anda odaklandık. Karanlık tema, animasyonlar ve modüler yapı, ekibin geliştirme hızını da ciddi ölçüde artırdı.',
    author: 'Zeyd Adouli',
    role: 'Frontend Builder',
    color: '#9f7aea',
  },
  {
    quote: 'Risk aggregation motoru ve modüller arası event bus, platforma gerçek zamanlı bir sinir sistemi kazandırdı. Her modülün bağımsız çalışıp ortak telemetri katmanında buluşması, ölçeklenebilir mimari açısından doğru tercih oldu.',
    author: 'Arda Kaya',
    role: 'Backend Dev',
    color: '#22c55e',
  },
  {
    quote: 'Phishing dedektörü ile aynı gün birden fazla sahte bağlantı tespit edildi. KVKK başvuru belgesinin otomatik üretilmesi ise beklediğimizden çok daha pratik çıktı.',
    author: 'Beta Kullanıcısı',
    role: 'Erken Erişim Katılımcısı',
    color: '#ff6b35',
  },
]

export const why = [
  { title: 'Yapay Zeka Destekli', desc: 'DeepSeek + Groq çift LLM mimarisi; bir model hizmet dışı olsa bile diğeri devreye girer. Gerçek zamanlı triyaj, Türkçe öneri ve SOC için makine okunabilir özet tek istek döngüsünde üretilir.' },
  { title: 'Gerçek Zamanlı İstihbarat', desc: 'AbuseIPDB, OTX, URLhaus ve Türkiye odaklı honeypot ağından dakikada işlenen 10+ kaynak; 30.000+ IOC canlı tutulur, yeni sinyal saniyeler içinde tüm modüllere yayılır.' },
  { title: '5 Katmanlı Koruma', desc: 'AI Analiz → Phishing Tespiti → IOC Korelasyonu → Sızıntı Tarama → Kriptografik Kalkan. Her katman bağımsız çalışır; ortak telemetri katmanı üzerinden birbirini güçlendirir.' },
  { title: 'Türkçe & KVKK Uyumlu', desc: 'Türkçe arayüz ve raporlama, KVKK ile GDPR uyumlu veri işleme. Türkiye’deki tehdit yüzeyine özel IOC kuralları; denetim için otomatik kanıt zinciri ve PDF export.' },
  { title: 'Gizlilik Önce', desc: 'Şifre üretimi ve hash işlemleri tarayıcıda yapılır — ham veri hiçbir zaman sunucuya iletilmez. Kriptografik Kalkan modülü sıfır-bilgi prensibiyle tasarlandı.' },
  { title: 'Açıklanabilir Raporlar', desc: 'Her uyarı için neden-sonuç açıklaması, etki yarıçapı tahmini ve önerilen aksiyon listesi. PDF export, e-posta bildirimleri ve SIEM/webhook entegrasyonu standart olarak gelir.' },
]
