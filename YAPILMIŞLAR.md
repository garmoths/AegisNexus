# 🛡️ AegisNexus - Yapılan İşler ve Mimari Özeti

**Tarih:** 15 Nisan 2026  
**Platform:** DigitalOcean (Ubuntu Droplet)  
**Domain:** aegisnexus.dev  
**Live API:** https://aegisnexus.dev (HTTPS)  
**Status:** ✅ **AKTIF VE GÜVENLI - HEP AYAKTA**

---

## 🎯 Yapılan Son İşler (Kısaca)
- ✅ **HTTPS/SSL Sertifikası**: Let's Encrypt (aegisnexus.dev + www) - Nginx ile
- ✅ **Terminal Kapanaması Sorunu ÇÖZÜLDÜ**: Ubuntu Systemd Service → Hep ayakta kalıyor
- ✅ **Otomatik Yeniden Başlama**: Crash/reboot sonrası otomatik servis başlatma

---

## 📋 İçindekiler
1. [Mimari Yapı](#mimari-yapı)
2. [Tamamlanan Modüller](#tamamlanan-modüller)
3. [Veritabanı Şeması](#veritabanı-şeması)
4. [Teknoloji Stack'i](#teknoloji-stacki)
5. [API Yapısı](#api-yapısı)
6. [Frontend](#frontend)
7. [SSL/TLS ve HTTPS](#ssltls-ve-https)
8. [Deployment ve Otomasyon](#deployment-ve-otomasyon)
9. [Konfigürasyon ve Secrets](#konfigürasyon-ve-secrets)
10. [Dosya Organizasyonu](#dosya-organizasyonu)

---

## 🏗️ Mimari Yapı

Aegis Nexus, **6 katmanlı modüler güvenlik kalkanı** mimarisi ile inşa edilmiştir:

```
┌─────────────────────────────────────────────────────────────┐
│                         İstemci (Frontend)                   │
│                    (Browser/Web Interface)                   │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                      Nginx Web Sunucusu                      │
│  • HTTPS/SSL Termination (aegisnexus.dev)                   │
│  • Trafik Yönetimi (Port 8000'e yönlendirme)               │
│  • Statik Dosya Sunumu (/static)                            │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Backend Server                    │
│               (Python 3.x - Port 8000)                       │
│  Uvicorn ASGI Application Server                            │
└─────────────────────────────────────────────────────────────┘
                              ↓
        ┌─────────────────────┼──────────────────────┐
        ↓                     ↓                      ↓
   ┌─────────┐          ┌──────────┐         ┌──────────┐
   │ 6 Modül │          │ Ortak    │         │ API      │
   │ Router  │          │ Models   │         │ Endpoint │
   │ Sistemi │          │ (Shared) │         │          │
   └─────────┘          └──────────┘         └──────────┘
        ↓
┌─────────────────────────────────────────────────────────────┐
│                   PostgreSQL Veritabanı                     │
│          Frankfurt Veri Merkezi (DigitalOcean)             │
│  • phishing_urls tablosu (Tehdit Veritabanı)               │
│  • honeypot_events tablosu (Tuzak Olayları)                │
└─────────────────────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────────────────────┐
│                  Harici API İntegrasyonları                 │
│  • VirusTotal (Kötü Amaçlı Yazılım Taraması)               │
│  • Google Safe Browsing (URL Güvenliği)                    │
│  • AbuseIPDB (IP İtibarı Kontrol)                          │
│  • Groq LLM (Yapay Zeka Raporları)                         │
│  • Telegram API (Sosyal Ağ Analizi) - Hazır              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🎯 Tamamlanan Modüller

### 01️⃣ **Phishing Detector** (Kimlik Avı Dedektörü)
- **Amaç:** URL'leri kötü amaçlı/phishing sitesi olup olmadığı açısından tarama
- **Özellikler:**
  - Veritabanında URL depolama (hash ile indeksleme)
  - VirusTotal API entegrasyonu
  - Google Safe Browsing API entegrasyonu
  - URL normalize etme (domain standardizasyonu)
  - Gerçek zamanlı tehdit sorgulaması
  - SQLAlchemy ORM ile URL yönetimi
- **Veri Modeli:** `PhishingURL` (phishing_urls tablosu)
- **API Prefix:** `/api/v2/phishing`
- **Endpoint Örnekleri:**
  - `POST /api/v2/phishing/scan` - URL taraması
  - `GET /api/v2/phishing/status/{url_hash}` - Durum sorgusu

### 02️⃣ **Honeypot** (IP Avcısı - Tuzak Sistemi)
- **Amaç:** Kültülenmiş tuzak sayfalarına erişen saldırganların IP'lerini yakalamak
- **Özellikler:**
  - Sahte web sayfaları ile saldırganları çekme
  - Client IP, User-Agent, Referrer kaydetme
  - Ziyaretçi yavru izleri (fingerprint) analizi
  - Timestamp ile olay zamanlaması (UTC)
  - AbuseIPDB ile IP itibar kontrolü
- **Veri Modeli:** `HoneypotEvent` (honeypot_events tablosu)
- **API Prefix:** `/api/v2/honeypot`
- **Endpoint Örnekleri:**
  - `POST /api/v2/honeypot/log` - Tuzak olayı kaydetme
  - `GET /api/v2/honeypot/events` - Tuzak olayları listeleme
  - `GET /api/v2/honeypot/ip-reputation/{ip}` - IP itibar analizi

### 03️⃣ **Breach Intelligence** (Veri Radarı - Deep Web İzleme)
- **Amaç:** Deep Web'de kullanıcı verilerinin sızıntısını takip etme
- **Özellikler:**
  - Dark Web veri tabanlarını tarama
  - Sızıntılı mail/şifre kütüphaneleri kontrolü
  - Erken uyarı sistemi
  - İstatistik ve raporlama
  - LLM entegrasyonu (Groq) ile yapay zeka raporları
- **API Prefix:** `/api/v2/breach`
- **Endpoint Örnekleri:**
  - `POST /api/v2/breach/scan-email` - Email sızıntı kontrolü
  - `GET /api/v2/breach/report/{email}` - Sızıntı raporu

### 04️⃣ **Password Shield** (Kriptografik Kalkan - Şifre Üretimi)
- **Amaç:** Kırılması yüzyıllar süren ultra-güvenli şifreler üretmek
- **Özellikler:**
  - Kriptografik olarak güvenli rastgele şifre generation
  - Özelleştirilebilir karmaşıklık seviyeleri
  - Tüm karakterlerin (lower, upper, digit, special) kullanımı
  - Entropy hesaplaması
  - Batch şifre generasyon
- **API Prefix:** `/api/v2/shield`
- **Endpoint Örnekleri:**
  - `POST /api/v2/shield/generate` - Güvenli şifre üretimi
  - `GET /api/v2/shield/entropy` - Entropi analizi

### 05️⃣ **Infrastructure Guard** (Altyapı Kalkanı - Sunucu Analizi)
- **Amaç:** Sunucu altyapısının (SSL, portlar, DNS) güvenliğini analiz etme
- **Özellikler:**
  - SSL/TLS sertifika analizi
  - Açık port taraması
  - DNS konfigürasyonu kontrolü
  - Protokol güvenliği değerlendirmesi
  - Sunucu başlıkları (headers) analizi
  - Versiyon bilgisi tespiti
- **API Prefix:** `/api/v2/infra`
- **Endpoint Örnekleri:**
  - `POST /api/v2/infra/scan-domain` - Domain güvenlik analizi
  - `GET /api/v2/infra/ssl-cert/{domain}` - SSL sertifika detayları
  - `POST /api/v2/infra/port-scan` - Port taraması

### 06️⃣ **Cyber Guardian** (Siber Koruyucu - Sosyal Tehdit)
- **Amaç:** Siber zorbalık, şantaj ve sosyal ağ tehditleri tespit etme
- **Özellikler:**
  - Siber zorbalık deteksiyonu
  - Sextortion (cinsel şantaj) uyarıları
  - Sosyal medya profil güvenlik analizi
  - Reputasyon yönetimi
  - Tehlikeli içerik tespiti
  - Toplum odaklı tehdit analizi
- **API Prefix:** `/api/v2/guardian`
- **Endpoint Örnekleri:**
  - `POST /api/v2/guardian/check-profile` - Profil güvenlik analizi
  - `GET /api/v2/guardian/threats/{username}` - Tehdit raporu

---

## 🗄️ Veritabanı Şeması

### PostgreSQL (Frankfurt Veri Merkezi - DigitalOcean)

#### Tablo #1: `phishing_urls`
```sql
CREATE TABLE phishing_urls (
    id SERIAL PRIMARY KEY,
    phish_id VARCHAR(255) UNIQUE NOT NULL,
    url VARCHAR(MAX) NOT NULL,
    url_hash VARCHAR(64) UNIQUE NOT NULL,
    domain_norm VARCHAR(512) NOT NULL,
    status VARCHAR(50),
    online BOOLEAN,
    target VARCHAR(255),
    submission_time TIMESTAMP DEFAULT NOW()
);

-- İndeksler (Hız)
CREATE INDEX ix_phishing_urls_phish_id ON phishing_urls(phish_id);
CREATE INDEX ix_phishing_urls_url_hash ON phishing_urls(url_hash);
CREATE INDEX ix_phishing_urls_domain_norm ON phishing_urls(domain_norm);
CREATE INDEX ix_phishing_urls_status ON phishing_urls(status);
```

**Amaçları:**
- `phish_id`: Phishing.Army'den gelen benzersiz kimlik
- `url_hash`: SHA-256 hash (tekrarlanan eklemeyi önlemek)
- `domain_norm`: Normalize edilmiş domain (arama hızı)
- `status`: "online", "offline", "parked"
- `online`: Boolean işareti (hızlı filtreleme)
- `submission_time`: Kayıt zamanı (UTC)

#### Tablo #2: `honeypot_events`
```sql
CREATE TABLE honeypot_events (
    id SERIAL PRIMARY KEY,
    client_ip VARCHAR(128) NOT NULL,
    user_agent VARCHAR(512),
    path VARCHAR(256),
    referer VARCHAR(512),
    note TEXT,
    created_at TIMESTAMP DEFAULT (NOW() AT TIME ZONE 'utc')
);

-- İndeksler (Hız)
CREATE INDEX ix_honeypot_events_client_ip ON honeypot_events(client_ip);
CREATE INDEX ix_honeypot_events_created_at ON honeypot_events(created_at);
```

**Amaçları:**
- `client_ip`: Saldırganın IP adresi
- `user_agent`: Tarayıcı bilgisi (işletim sistemi, versiyon)
- `path`: Erişilen URL path'i
- `referer`: From nereden geldiği
- `note`: Etiket/kategori (örn: "Bot", "Scanner", "Attacker")
- `created_at`: Olayın UTC zamanı

### Bağlantı Bilgileri
```
Host: DigitalOcean Frankfurt Veri Merkezi
Kullanıcı: enes
Şifre: [.env'de saklanmış]
Port: 5432
Veritabanı: phishing_db
```

**Pool Ayarları (Yüksek Eşzamanlılık):**
- Pool Size: 20
- Max Overflow: 40
- Pre-Ping: Enabled (Canlı bağlantı kontrolü)

---

## 💻 Teknoloji Stack'i

### Backend Framework
| Kütüphane | Versiyon | Amaç |
|-----------|----------|------|
| `fastapi` | 0.128.0 | Modern Python web framework (async/await) |
| `uvicorn[standard]` | 0.40.0 | ASGI sunucu (FastAPI çalıştırması) |
| `pydantic` | 2.12.5 | Veri doğrulama ve serileştirme |
| `pydantic-core` | 2.41.5 | Pydantic çekirdeği (performans) |

### Veritabanı
| Kütüphane | Versiyon | Amaç |
|-----------|----------|------|
| `sqlalchemy` | 2.0.45 | ORM (Object-Relational Mapping) |
| `psycopg2-binary` | 2.9.11 | PostgreSQL Python sürücüsü |

### HTTP ve Web Gerekçeleri
| Kütüphane | Versiyon | Amaç |
|-----------|----------|------|
| `requests` | 2.32.5 | HTTP istekleri (API çağrıları) |
| `certifi` | 2026.1.4 | SSL sertifikaları DB'si |
| `beautifulsoup4` | 4.14.3 | HTML parsing ve scraping |
| `lxml` | 6.0.2 | XML/HTML işlemleri (hızlı parser) |

### Konfigürasyon
| Kütüphane | Versiyon | Amaç |
|-----------|----------|------|
| `python-dotenv` | 1.2.1 | .env dosyasından environment değişkenleri |

### Yapay Zeka ve LLM
| Kütüphane | Versiyon | Amaç |
|-----------|----------|------|
| `groq` | 1.0.0 | Groq LLM API (rapor üretimi) |

### External API İntegrasyonları (Not: SDK değil, manuel requests)
- **VirusTotal**: Kötü amaçlı yazılım taraması
- **Google Safe Browsing**: URL güvenliği
- **AbuseIPDB**: IP itibar kontrol
- **Telegram API**: Sosyal ağ analizi
- **Groq API**: Yapay zeka raporları

---

## 🔌 API Yapısı

### API Versiyonlandırması
Tüm API'lar `/api/v2/` prefix'i ile başlar (v1'den yükseltildi)

### Modüler Router Sistemi
FastAPI'nin built-in router sistemi kullanılarak her modülün kendi namespace'i var:

```python
# app/main.py içinde router inclusion
app.include_router(phishing_detector_router, prefix="/api/v2/phishing")
app.include_router(honeypot_router, prefix="/api/v2/honeypot")
app.include_router(breach_intel_router, prefix="/api/v2/breach")
app.include_router(password_shield_router, prefix="/api/v2/shield")
app.include_router(infra_guard_router, prefix="/api/v2/infra")
app.include_router(cyber_guardian_router, prefix="/api/v2/guardian")
```

### Root Endpoint
- `GET /` - index.html sunarsa Ana sayfa, aksi takdirde JSON hata mesajı

### Lifespan Management
FastAPI'nin lifespan context manager'i ile uygulama başlatıldığında:
1. SQLAlchemy tabloları otomatik olarak oluşturulur
2. Veritabanı bağlantısı sınanır
3. Log mesajı: "Aegis Nexus - 5 Katmanlı Güvenlik Kalkanı hazır"

---

## 🌐 Frontend

### Templates Klasörü: `/frontend/templates`

#### 1. `index.html`
- **Amaç:** Ana sayfa interfacesi
- **Statik Dosyalar:** `/static` klasöründen CSS/JS yükleme
- **Özellikler:**
  - Responsive tasarım
  - 6 modülün web UI'ı (arayüz)
  - Real-time sonuç görüntüleme

#### 2. `llm_report.html`
- **Amaç:** Yapay zeka tarafından oluşturulan güvenlik raporlarını görüntüleme
- **Kaynak:** Groq LLM (OpenAI-compatible API)
- **İçerik:** Markdown formatında raporlar

### Static Dosyaları: `/frontend/static`

#### CSS Dosyaları
- `style.css` - Ana styling (Genel tasarım)
- `aegis.css` - Tema ve markalaşma (Aegis özel stilleri)

### Statik Dosya Sunumu
```python
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
```

---

## � SSL/TLS ve HTTPS

### Let's Encrypt Sertifikası Kurulumu
```bash
# 1. Certbot yükleme
sudo apt-get update
sudo apt-get install certbot python3-certbot-nginx

# 2. DNS A kaydı ayarlandı
# aegisnexus.dev    A    104.248.45.198
# www.aegisnexus.dev CNAME aegisnexus.dev

# 3. Sertifika oluşturma (Nginx eklentisi ile)
sudo certbot certonly --nginx -d aegisnexus.dev -d www.aegisnexus.dev

# 4. Otomatik yenileme (Certbot service - her ay kontrol eder)
sudo systemctl enable certbot.timer
sudo systemctl start certbot.timer
sudo systemctl status certbot.timer
```

### HTTPS Test
```bash
# Sertifika bilgilerini kontrol et
openssl s_client -connect aegisnexus.dev:443

# Curl ile HTTPS test
curl -I https://aegisnexus.dev
curl -I https://www.aegisnexus.dev
```

### Nginx SSL Yapılandırması
```nginx
# /etc/nginx/sites-available/aegisnexus

# HTTP → HTTPS yönlendirme
server {
    listen 80;
    server_name aegisnexus.dev www.aegisnexus.dev;
    return 301 https://$server_name$request_uri;
}

# HTTPS (SSL) sunucu
server {
    listen 443 ssl http2;
    server_name aegisnexus.dev www.aegisnexus.dev;
    
    # SSL sertifikaları (Let's Encrypt tarafından)
    ssl_certificate /etc/letsencrypt/live/aegisnexus.dev/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/aegisnexus.dev/privkey.pem;
    
    # SSL ayarları (Modern + Eski browser uyumlu)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5:!3DES;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # HSTS (Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Gzip compression
    gzip on;
    gzip_types text/plain text/css application/json application/javascript;
    gzip_vary on;
    
    # FastAPI reverse proxy
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $server_name;
        
        # WebSocket desteği
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # Statik dosyalar (caching ile)
    location /static/ {
        alias /home/enes/AegisNexus/frontend/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
}
```

**Certbot Service Kontrolü:**
```bash
# Yenileme testi (kuru koşu)
sudo certbot renew --dry-run

# Sertifika geçerlilik kontrolü
sudo certbot certificates

# Nginx konfigürasyonu testi
sudo nginx -t

# Nginx yeniden yükle
sudo systemctl reload nginx
```

**Sertifika Detayları:**
- **Sağlayıcı:** Let's Encrypt (Ücretsiz)
- **Geçerlilik:** 90 gün
- **Otomatik Yenileme:** Certbot timer (çalışmakta) - 30 gün kala yenileme başlar
- **Sertifika Yolu:** `/etc/letsencrypt/live/aegisnexus.dev/`
- **Key Yolu:** `/etc/letsencrypt/live/aegisnexus.dev/privkey.pem`
- **Etkinleştirilen Domainler:** aegisnexus.dev, www.aegisnexus.dev
- **Protokoller:** TLSv1.2, TLSv1.3
- **HSTS:** Enabled (max-age: 1 yıl)

---

## �🚀 Deployment ve Otomasyon

### Sunucu Ortamı
- **Platform:** DigitalOcean
- **OS:** Ubuntu (Droplet)
- **Bölge:** Frankfurt Veri Merkezi
- **IP Adresi:** 104.248.45.198

### Port Yapılandırması
- **80:** HTTP (Nginx auto-redirect → HTTPS)
- **443:** HTTPS/SSL (Nginx SSL Termination - Let's Encrypt sertifikası)
- **8000:** FastAPI Backend (Nginx reverse proxy - localhost only)

### Nginx Konfigürasyonu
- **Görev:** Reverse proxy, load balancing, SSL termination
- **İşlevleri:**
  - Gelen HTTP trafiğini HTTPS'ye yönlendirme
  - SSL/TLS sertifikası termination (Let's Encrypt)
  - Trafik 8000 portundaki FastAPI'ye yönlendirme
  - Statik dosya sunumu (caching)
  - Request/response compression
  - Security headers (HSTS, X-Frame-Options vb.)

**Not:** Detaylı Nginx konfigürasyonu [SSL/TLS ve HTTPS](#ssltls-ve-https) bölümünde

### FastAPI Çalıştırması - Arka Planda Hep Ayakta Kalma
Terminal kapanması koşullarında arka planda devam etmek için Ubuntu'da sistemd service kuruldu:

#### ✅ **AegisNexus Systemd Service** (AKTIF - Üretim)
```bash
# /etc/systemd/system/aegisnexus.service
[Unit]
Description=AegisNexus FastAPI Security Platform
After=network.target postgresql.service
Wants=network-online.target

[Service]
Type=notify
User=enes
Group=enes
WorkingDirectory=/home/enes/AegisNexus
Environment="PATH=/home/enes/AegisNexus/.venv/bin"
EnvironmentFile=/home/enes/AegisNexus/.env

# FastAPI Uvicorn sunucusu
ExecStart=/home/enes/AegisNexus/.venv/bin/uvicorn app.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --workers 4 \
    --log-level info

# Otomatik yeniden başlama
Restart=always
RestartSec=10
StartLimitInterval=60s
StartLimitBurst=3

# Resource limitleri
LimitNOFILE=65535
LimitNPROC=65535

# Graceful shutdown
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
```

**Systemd Service Yönetimi:**
```bash
# Servisi yükle/etkinleştir
sudo systemctl daemon-reload
sudo systemctl enable aegisnexus

# Başlat/Durdur/Kontrol et
sudo systemctl start aegisnexus         # Başlat
sudo systemctl stop aegisnexus          # Durdur
sudo systemctl restart aegisnexus       # Yeniden başlat
sudo systemctl status aegisnexus        # Durum kontrol
sudo systemctl is-active aegisnexus     # Çalışıyor mu?

# Log görüntüle
sudo journalctl -u aegisnexus -f        # Real-time loglar
sudo journalctl -u aegisnexus -n 100    # Son 100 satır
```

**Systemd Ayarları Detayı:**
- **Type=notify:** Uvicorn'un systemd'ye başarı sinyali göndermesini bekle
- **User=enes:** Service enes kullanıcısısı ile çalış
- **Restart=always:** Hata durumunda otomatik yeniden başla
- **RestartSec=10:** 10 saniye bekle yeniden başlama öncesi
- **StartLimitBurst=3:** 60 saniye içinde max 3 kez başlama (crash loop önleme)
- **KillMode=mixed:** SIGTERM sonra SIGKILL (graceful + forceful)
- **TimeoutStopSec=30:** 30 saniye içinde kapatmazsa -9 ile öldür

**Sonuç:** Terminal kapansa, SSH session bitense, reboot olsa bile service otomatik başlar ve çalışmaya devam eder!

---

#### Alternatif Yöntemler (Opsiyonel)

#### Yöntem 2: **Supervisor** (İşlem Yönetimi)
```ini
[program:aegisnexus]
command=/home/enes/AegisNexus/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
directory=/home/enes/AegisNexus
user=enes
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/var/log/aegisnexus.log
```

#### Yöntem 3: **tmux/Screen Session** (Geliştirme/Ad-hoc)
```bash
# tmux ile
tmux new-session -d -s aegis "source /home/enes/AegisNexus/.venv/bin/activate && \
  cd /home/enes/AegisNexus && \
  uvicorn app.main:app --host 0.0.0.0 --port 8000"

# Screen ile
screen -d -m -S aegis bash -c "source /home/enes/AegisNexus/.venv/bin/activate && \
  cd /home/enes/AegisNexus && \
  uvicorn app.main:app --host 0.0.0.0 --port 8000"
```

### GitHub Actions Auto-Deploy Pipeline
- **Trigger:** Her push'ta `main` branch'ine
- **Workflow:** `.github/workflows/deploy.yml`
- **İşlemler:**
  1. Code checkout
  2. Python env setup
  3. Dependencies yükleme (pip install -r requirements.txt)
  4. Tests çalıştırma (eğer varsa)
  5. DigitalOcean sunucusuna SSH bağlantısı
  6. Git pull (sunucuda)
  7. Migrations çalıştırma
  8. Service restart (systemd)

**Badge:** README'de gösterilen auto-deploy durumu

### Cron-based Auto-Deployment (Planlı)
- **Frekans:** Saatlik/günlük periyodik deploys
- **Amaç:** En son kodun sunucuya yüklenmesini garantileme
- **Son çalışma:** Tue Apr 14 18:18:10 +03 2026

### Logging
- **Format:** `%(levelname)s %(name)s %(message)s`
- **Log Level:** INFO
- **Logger adı:** "aegis"
- **Çıktı:** Console (systemd journal'a kaydedilir)

---

## ⚙️ Konfigürasyon ve Secrets

### .env Dosyası (Sensitive Data)
```
# Veritabanı
DB_USER=enes
DB_PASSWORD=password
DB_HOST=127.0.0.1
DB_PORT=5432
DB_NAME=phishing_db
DATABASE_URL=postgresql://enes:password@127.0.0.1:5432/phishing_db
DB_POOL_SIZE=20
DB_MAX_OVERFLOW=40

# Harici API Anahtarları
VIRUSTOTAL_API_KEY=fe5254a6196c4f23a7d0f1a3164b7318818e1213c7c5c3e479fc999976f2a5d2
GOOGLE_SAFE_BROWSING_KEY=AIzaSyAXbw-TjL73BWW59GT6byqrommVnlzWZBE
ABUSEIPDB_API_KEY=ae8a19a62b099438874a87a49a12793313d6e5a2eb6f7e53a11db13b05470580a38dcd96b37d5e18
GROQ_API_KEY=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

# Sosyal Ağ
TELEGRAM_API_ID=36167683
TELEGRAM_API_HASH=7d250a8acae18e12b3334dd8fd788fae
```

### Python-dotenv Yükleme
```python
from dotenv import load_dotenv
load_dotenv()
```

**Güvenli Depolama:**
- `.env` dosyası `.gitignore`'da (Git'e commit edilmez)
- DigitalOcean sunucusuna manuel kopyalanır
- Umask ayarı: 600 (sadece owner okuyor)

---

## 📁 Dosya Organizasyonu

```
AegisNexus/
├── README.md                    # Proje açıklaması ve badge'ler
├── requirements.txt             # Python bağımlılıkları (pip freeze)
├── .env                         # Secrets ve konfigürasyon (gitignore'lanmış)
├── YAPILMIŞLAR.md              # Bu dosya - Detaylı yapılan işler
│
├── app/                         # FastAPI ana uygulaması
│   ├── __init__.py
│   ├── main.py                 # FastAPI app ve router inclusion
│   ├── config.py               # Konfigürasyon (HIBP, veritabanı)
│   ├── database.py             # SQLAlchemy engine, SessionLocal, Base
│   ├── models.py               # Pydantic request/response modelleri
│   ├── deps.py                 # Dependency injection (DB session vb.)
│   ├── routers/                # Alt routerlar
│   │   ├── __init__.py
│   │   ├── contact.py          # İletişim endpoint'leri
│   │   └── system.py           # Sistem bilgileri endpoint'leri
│   └── ...
│
├── modules/                     # 6 Güvenlik Modülü
│   ├── __init__.py             # Router exports (phishing_detector_router vb.)
│   │
│   ├── phishing_detector/       # 01 - Phishing Detector
│   │   ├── __init__.py
│   │   ├── router.py           # API route tanımları
│   │   ├── engine.py           # VirusTotal, Safe Browsing, URL tarama
│   │   ├── scanner.py          # URL tarama lojik
│   │   ├── threat_intel.py     # Tehdit veritabanı entegrasyonu
│   │   ├── url_normalize.py    # Domain/URL standardizasyonu
│   │   ├── ml_classifier.py    # ML-alaşmış sonuçlar
│   │   ├── fetch_data.py       # External data fetching
│   │   ├── fetch_all_sources.py # Multi-source veri çekme
│   │   ├── routers/            # Sub-routers (varsa)
│   │   └── utils.py            # Helper fonksiyonlar
│   │
│   ├── honeypot/               # 02 - Honeypot (IP Avcısı)
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── engine.py           # Tuzak mantığı, IP takibi
│   │   ├── routers/
│   │   └── ...
│   │
│   ├── breach_intel/           # 03 - Breach Intelligence
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── engine.py           # Dark Web scanning
│   │   ├── dark_web_scanner.py # Deep Web tarama
│   │   ├── hibp_client.py      # Have I Been Pwned API
│   │   ├── osint_checker.py    # OSINT verisi kontrol
│   │   ├── psychology_analyzer.py # Sosyal mühendislik analizi
│   │   ├── llm_reporter.py     # Groq LLM raporları
│   │   ├── radar_generator.py  # Görsel radarlar/charts
│   │   ├── routers/
│   │   └── utils.py
│   │
│   ├── password_shield/        # 04 - Password Shield
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── generator.py        # Kriptografik şifre üretimi
│   │   ├── routers/
│   │   └── ...
│   │
│   ├── infra_guard/            # 05 - Infrastructure Guard
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── analyzer.py         # SSL/port/DNS analizi
│   │   ├── routers/
│   │   └── ...
│   │
│   └── cyber_guardian/         # 06 - Cyber Guardian
│       ├── __init__.py
│       ├── router.py
│       ├── engine.py           # Zorbalık deteksiyonu
│       ├── routers/
│       └── ...
│
├── shared/                      # Ortak Modeller ve Utilities
│   ├── __init__.py
│   ├── models/                 # Veritabanı ORM modelleri
│   │   ├── __init__.py
│   │   ├── phishing.py         # PhishingURL SQLAlchemy modeli
│   │   └── honeypot.py         # HoneypotEvent SQLAlchemy modeli
│   └── utils/                  # Shared utilities
│       ├── __init__.py
│       └── db.py               # Veritabanı helper'ları
│
├── frontend/                    # Web UI
│   ├── static/                 # Statik dosyalar
│   │   ├── style.css           # Ana stiller
│   │   └── aegis.css           # Tema stilleri
│   └── templates/              # HTML şablonları
│       ├── index.html          # Ana sayfa
│       └── llm_report.html     # Rapor sayfası
│
├── scripts/                     # Veritabanı migration scriptleri
│   ├── migrate_add_url_hash.sql    # URL hash sütunu ekleme
│   └── migrate_honeypot.sql        # Honeypot tablosu oluşturma
│
├── logs/                        # Uygulama logları (runtime)
│   └── [runtime çıktıları]
│
└── docs/                        # Dokümantasyon (varsa)
    └── [docs]
```

---

## ✅ Tamamlanan Görevler Özeti

### Altyapı
- ✅ DigitalOcean Ubuntu Droplet sunucu konfigürasyonu
- ✅ PostgreSQL veritabanı Frankfurt veri merkezinde kurulumu
- ✅ Python 3.x virtual environment (.venv) oluşturma
- ✅ Nginx reverse proxy yapılandırması
- ✅ Domain (aegisnexus.dev) DNS yönlendirmesi
- ✅ Port 80/443/8000 konfigürasyonu

### Backend Development
- ✅ FastAPI framework kurulumu ve temel app.main.py
- ✅ SQLAlchemy ORM setup (PostgreSQL connection pooling)
- ✅ 6 modüler router sistemi (phishing, honeypot, breach, shield, infra, guardian)
- ✅ Pydantic data validation
- ✅ Harici API entegrasyonları (VirusTotal, Google Safe Browsing, AbuseIPDB, Groq)
- ✅ Database lifespan management (auto-create tables)

### Veritabanı
- ✅ `phishing_urls` tablosu (6 indexed columns)
- ✅ `honeypot_events` tablosu (event logging)
- ✅ Migration scripts (SQL)
- ✅ Connection pooling (20 size, 40 overflow)

### Frontend
- ✅ index.html statik sayfası
- ✅ llm_report.html rapor sayfası
- ✅ CSS styling (style.css, aegis.css)
- ✅ Static file mounting (/static route)

### Deployment & Automation
- ✅ GitHub Actions auto-deploy pipeline (main branch tracking)
- ✅ **SSL/TLS Sertifikası (Let's Encrypt + Certbot)** - aegisnexus.dev ve www için
- ✅ **Nginx HTTPS Yapılandırması** - HTTP → HTTPS yönlendirme
- ✅ **Ubuntu Systemd Service (aegisnexus.service)** - Terminal kapansa bile arka planda çalışan process
- ✅ Cron-based periyodik deployments
- ✅ .env secrets yönetimi

### Konfigürasyon
- ✅ python-dotenv environment variable yükleme
- ✅ .gitignore ile .env gizleme
- ✅ Logging setup (INFO level, aegis logger)

---

## 📊 Proje İstatistikleri

| Metrik | Değer |
|--------|-------|
| **Modül Sayısı** | 6 |
| **API Endpoint Kategorileri** | 6+ |
| **Veritabanı Tablosu** | 2 |
| **Harici API Entegrasyonu** | 4 (VirusTotal, Safe Browsing, AbuseIPDB, Groq) |
| **Frontend Template** | 2 |
| **Python Kütüphanesi** | 13 |
| **Sunucu Bölgesi** | Frankfurt (DigitalOcean) |
| **Deployment Türü** | CI/CD (GitHub Actions) + Cron |

---

## 🔄 Devam Eden Geliştirmeler

- 🟡 Telegram API entegrasyonu (hazır, henüz etkinleştirilmemiş)
- 🟡 Daha fazla ML sınıflandırıcıları (honeypot event analiz)
- 🟡 Dashboard/analytics sayfası
- 🟡 Kullanıcı authentication (JWT)
- 🟡 Rate limiting
- 🟡 Webhook sistemi

---

**Son Güncelleme:** 15 Nisan 2026  
**Proje Durumu:** ✅ **AKTIF, GÜVENLI VE HEP AYAKTA**

---

## 📝 Son Yapılan Değişiklikler

### Tarih: 15 Nisan 2026 - Güvenlik ve Dayanıklılık Güncellemesi

#### ✅ SSL/TLS HTTPS Entegrasyonu Tamamlandı
- Let's Encrypt sertifikası kurulumuyla aegisnexus.dev ve www.aegisnexus.dev UHTTPSlestirildi
- Nginx HTTPS termination aktif
- Otomatik sertifika yenileme (Certbot timer)
- HSTS header aktivasyonu
- TLSv1.2 ve TLSv1.3 desteği

#### ✅ Background Process Dayanıklılığı Sağlandı
- Ubuntu Systemd Service (`aegisnexus.service`) kurulumuyla terminal kapanırken bile arka planda çalışıyor
- Otomatik yeniden başlama (3 retry maxed)
- Graceful shutdown/restart
- Systemd journal'da logging
- Reboot sonrası auto-start

**Artık:**
- Terminal kapatıldığında → ✅ Çalışmaya devam
- SSH session bittiğinde → ✅ Çalışmaya devam
- Server reboot olduğunda → ✅ Otomatik başlıyor
- Crash/error olduğunda → ✅ 10 sn içinde restart
