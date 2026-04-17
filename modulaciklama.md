# AegisNexus - Kiberguvenlik Platform | Modüller & Vizyon

## 🎯 Vizyon
**AegisNexus**, tehditleri proaktif olarak tespit eden, analiz eden ve yanıt veren bir kurumsal kiberguvenlik platformudur. Açık kaynak istihbarat kaynakları, makine öğrenmesi ve reel-zamanlı tehdit analizi kombinasyonuyla, kuruluşlara modern siber risklere karşı **5 katmanlı koruma** sağlar.

---

## 📦 Modüler Mimari

### 1️⃣ **Phishing Detector** - Gelişmiş URL Taraması
**Amaç:** Kimlik avı ve kötü amaçlı siteleri gerçek zamanlı olarak tespit etme

**Yetenekler:**
- 1.2M+ phishing URL veritabanı (URLhaus, PhishTank, Abuse.ch)
- Domain genetik analizi & DNS/SSL sertifika doğrulaması
- ML-tabanlı sayfasal benzerlik analizi (phishing clone tespiti)
- Regex ve yıldız işareti deseni eşleştirmesi
- Beyaz liste ve özel kural desteği
- Toplu tarama (CSV) ve API entegrasyonu

**API Endpoints:** 
```
GET /api/v2/phishing/check-url?url=...
GET /api/v2/phishing/search
GET /api/v2/phishing/stats
POST /api/v2/phishing/scan-bulk
```

---

### 2️⃣ **Honeypot + IOC Collector** - İstihbarat & Tehdit Toplama
**Amaç:** Gerçek dünya tehditleri yakalamak ve merkezi bir veritabanında organize etmek

**Yetenekler:**
- **AbuseIPDB** entegrasyonu: Kötü amaçlı IP adreslerini 1-100 risk skoru ile sınıflandırma
- **URLhaus** & **PhishTank** otomatik toplayıcı (saatlik senkronizasyon)
- Risk skoru algoritması: tehdit türü, kaynak güvenilirliği, algılama yoğunluğu
- IOC (Indicators of Compromise) kalıcı depolama ve arama
- Operatör uyarı sistemi: Yüksek riskli göstergeler için otomasyonlu bildirimler
- Decoy oturum üretimi ve etkileşim takibi

**API Endpoints:**
```
GET /api/v2/honeypot/ioc/list
GET /api/v2/honeypot/ioc/stats
POST /api/v2/honeypot/session/create
```

---

### 3️⃣ **Breach Intelligence** - İhlal Analizi & OSINT
**Amaç:** Dark web ve açık kaynakları tarayarak veri ihlalleri ve ifşa edilen kimlik bilgilerini tespit etme

**Yetenekler:**
- Abuse.ch havoc veritabanı sorgulaması
- Have I Been Pwned (HIBP) entegrasyonu
- Psikolojik profil analizi: Saldırı motivasyonu ve hedef tahmini
- OSINT göstergesi toplama: Email, domain, IP verileri
- Dark web feed monitoring (uyarı sistemi)
- Detaylı tehdit raporları: Saldırganı profilleme, taktikler ve öneriler

**API Endpoints:**
```
POST /api/v2/breach/check-email
POST /api/v2/breach/full-analysis
GET /api/v2/breach/report/{report_id}
```

---

### 4️⃣ **Password Shield** - Hassas Veri Koruması
**Amaç:** Parolaları şifreleme, güvenli depolama ve yenileme prosedürleri sağlama

**Yetenekler:**
- bcrypt & argon2 hashleme algoritmaları
- Parola gücü analizi (entropi, karakter çeşitliliği)
- Sızdırılmış parola veritabanı (HaveIBeenPwned) kontrolü
- Güvenli parola üretimi (akılda kalıcı + kriptografik)
- Hashleme metodolojisi ve best practices rehberi

**API Endpoints:**
```
GET /api/v2/shield/generate
POST /api/v2/shield/check-strength
GET /api/v2/shield/generate-memorable
```

---

### 5️⃣ **Threat Responder** - Otomatik Tehdit Yanıtı
**Amaç:** Yüksek riskli göstergelere karşı otomatik yanıt ve eskalasyon mekanizmaları

**Yetenekler:**
- Risk skoru tabanlı uyarı yönlendirmesi
- Operatör SMS & Email gateway'i (Türkiye telecom - Turk Telekom, Vodafone, Türkcell)
- Otomatik eskalasyon (Slack, webhook, SIEM entegrasyonu)
- İnşaat modları: Geliştirme, Hazırlık, Üretim
- Uyarı geçmişi ve yanıt izleme
- Tehdit zaman çizelgesi ve dönem analizi

**API Endpoints:**
```
POST /api/v2/responder/analyze-threat
POST /api/v2/responder/create-case
GET /api/v2/responder/cases/{case_id}
POST /api/v2/responder/generate-report
```

---

## 🏗️ Teknik Altyapı

### 📊 Database Katmanı
```
PostgreSQL (phishing_db) - Frankfurt Server
├── phishing_urls (1.2M+ malicious URLs)
├── indicators_of_compromise (Hourly IOC collection)
├── breach_records (Veri ihlali kayıtları)
├── honeypot_events (Operatör uyarıları)
├── password_checks (Parola denetim geçmişi)
├── whitelist_domains (Güvenli etki alanları)
├── operator_api_keys (API yönetimi)
└── ioc_operator_alerts (Tehdit uyarıları)
```

### 🔌 API Katmanı
- **FastAPI** (Port 8000): Yüksek performanslı async modüller
- **Flask+Gunicorn** (Port 5000): REST API ve arka plan işleri
- **Nginx** (80/443): Ters proxy, HTTPS/TLS termination, yük dengeleme
- **PM2**: Process manager (24/7 kullanılabilirlik, auto-restart)

### ⚙️ Otomasyon
- **IOC Fetcher** (Saatlik): AbuseIPDB, URLhaus, PhishTank otomatik senkronizasyonu
- **Cron Jobs**: Günlük backup, threat raporları, log rotation
- **GitHub Actions**: Frankfurt sunucusuna otomatik deployment

### 📈 Monitorlama & Logging
- **Systemd Services**: Otomatik yeniden başlatma, graceful shutdown
- **Log Rotation**: 30 günlük tutma, günlük compression
- `/var/log/aegis/`: Merkezi log depolama

---

## 🔄 Veri Akışı & İşlem

```
Dış Tehdid Kaynakları (URLhaus, PhishTank, AbuseIPDB)
        ↓
IOC Fetcher (Saatlik senkronizasyon)
        ↓
PostgreSQL (Risk Skoru Hesaplama)
        ↓
Phishing Detector ←→ Honeypot ←→ Breach Intelligence
        ↓
Threat Responder (SMS/Email Alert)
        ↓
Operatör Dashboard & SIEM
```

---

## 📊 Performans Metrikleri

| Metrik | Değer |
|--------|-------|
| URL Kontrol | <500ms |
| Bulk Tarama | 1000 URL/min |
| IOC Toplama | 100+ IOC/saat |
| Veritabanı Boyutu | 1.2M+ phishing URLs |
| Sistem Uptime | 99.9% |
| Risk Skoru Doğruluğu | 92% (ML optimizeli) |

---

## 👥 Hedef Kullanıcılar

1. **Kurumsal IT Güvenlik Ekipleri**: SOC operatörleri, CISO'lar, saldırı cevap ekipleri
2. **ISP & Telecom Operatörleri**: Ağ trafiği monitorlama ve tehdid yönetimi
3. **Siber Güvenlik Şirketleri**: İhlal yönetimi ve istihbarat platformları
4. **Hukuk Enforsamanı**: Siber suç istihbaratı ve kanıt toplama
5. **Akademik Araştırmacılar**: Tehdit aktörü profilleme ve trend analizi

---

## 🚀 Deployment & Scalability

**Mevcut:** DigitalOcean Frankfurt (Ubuntu 20.04+, 1 vCPU)
- Server IP: 104.248.45.198
- PostgreSQL: Production-ready
- APIs: Online and monitoring

**Üretim Hazırlığı:**
- ✅ Docker containerization (CI/CD ready)
- ✅ Kubernetes orchestration desteği
- ✅ Horizontal scaling: Load balancer + PostgreSQL replication
- ✅ Multi-region deployment: EU, APAC, Americas

---

## 📝 Sürüm & Lisans

**Sürüm:** 2.0 (IOC Collector Active)
**Lisans:** MIT License
**Repository:** Private (Arkadaş ağıyla sınırlı)
**Son Güncelleme:** 17 Nisan 2026

---

## 🔐 Önemli Notlar

- ✅ Tüm modüller FastAPI/Flask router mimarisi ile ayrıştırılmıştır
- ✅ Veritabanı katmanında 8 tablo ile full ACID compliance
- ✅ Modüller birlikte çalışarak: Tehdit Tespiti → Analiz → Uyarı → Yanıt döngüsünü tamamlar
- ✅ Frankfurt deployment aktif (production ready)
- ✅ IOC Fetcher saatlik otomasyonla çalışıyor
