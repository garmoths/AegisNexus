# 🛡️ Phishing Detector — Teknik Mimari Dökümanı

**Modül:** `modules/phishing_detector/`  
**Son Güncelleme:** 4 Mayıs 2026  
**Durum:** Tüm ölçeklendirme görevleri tamamlandı (A1–C1)

---

## İçindekiler

1. [Genel Mimari](#1-genel-mimari)
2. [A1 — Redis Cache Katmanı](#2-a1--redis-cache-katmanı)
3. [A2 — Celery Async Pipeline](#3-a2--celery-async-pipeline)
4. [A3 — Playwright Browser Pool](#4-a3--playwright-browser-pool)
5. [A4 — Paralel Threat Intelligence](#5-a4--paralel-threat-intelligence)
6. [B1 — HTML Derin Analizi](#6-b1--html-derin-analizi)
7. [B2 — pHash Logo Karşılaştırma](#7-b2--phash-logo-karşılaştırma)
8. [B3 — EasyOCR Metin Okuma](#8-b3--easyocr-metin-okuma)
9. [B4 — Koşullu Gemini](#9-b4--koşullu-gemini)
10. [C1 — Frontend Polling UI](#10-c1--frontend-polling-ui)
11. [Analiz Zinciri Akışı](#11-analiz-zinciri-akışı)
12. [Ortam Değişkenleri](#12-ortam-değişkenleri)
13. [Servis Yönetimi](#13-servis-yönetimi)

---

## 1. Genel Mimari

```
İstek
  │
  ▼
POST /check-url (FastAPI)
  │
  ├─► run_quick_checks()         ~200ms — whitelist, Redis cache, SQLite, PhishTank, ML
  │       │
  │       ├─ Sonuç kesinse ──► Direkt yanıt dön
  │       │
  │       └─ Belirsizse ──────► Celery task kuyruğa al → {status:"analyzing", job_id}
  │
  ▼
run_heavy_analysis() [Celery Worker]
  │
  ├─► HTML Derin Analizi (B1)    — AI'sız marka/credential tespiti
  ├─► Playwright Screenshot (A3) — Persistent browser pool
  ├─► pHash Logo Check (B2)      — 20 marka DB karşılaştırma
  ├─► EasyOCR Analizi (B3)       — Screenshot'tan metin okuma
  ├─► Paralel Threat Intel (A4)  — VirusTotal, AbuseIPDB, PhishTank, vb.
  └─► Gemini AI (B4/koşullu)     — Yalnızca önceki katmanlar yetersizse
  │
  ▼
Redis DB-1'e sonuç yaz (TTL: 3600s)
  │
  ▼
GET /result/{job_id} polling (C1 Frontend)
```

**Stack:**
- **FastAPI** — async API katmanı
- **Celery** — ağır analiz task queue (concurrency: 2, prefork)
- **Redis DB-1** — job sonuç saklama (TTL 3600s), Celery broker/backend
- **Redis DB-0** — genel uygulama cache
- **SQLite** — yerel tarama geçmişi cache
- **Playwright** — headless Chromium screenshot
- **Gemini 2.0 Flash** — görsel/içerik AI analizi (günlük 1400 limit)

---

## 2. A1 — Redis Cache Katmanı

**Dosya:** `modules/phishing_detector/redis_cache.py`  
**Etki:** Trafiğin %60-70'ini Redis cache ile keserek Playwright/Gemini çağrılarını önler.

### Katmanlar (hız sırasıyla)

| Katman | TTL | Açıklama |
|--------|-----|----------|
| Redis hit | — | Daha önce taranmış URL → anında yanıt |
| Whitelist | — | Bilinen güvenli domainler (google.com, github.com, vb.) |
| SQLite cache | 24h | Yerel DB'de kayıtlı scan sonucu |
| PhishTank DB | — | Yerel PhishTank veritabanı sorgusu |

### Önemli Fonksiyonlar

```python
redis_get_scan(url: str) -> dict | None
redis_set_scan(url: str, result: dict, ttl: int = 3600)
redis_get_gemini_count() -> int
redis_incr_gemini_counter() -> int
redis_get_job_result(job_id: str) -> dict | None
redis_set_job_result(job_id: str, result: dict, ttl: int = 3600)
```

### `/cache-health` Endpoint Yanıtı

```json
{
  "redis": {
    "available": true,
    "used_memory_human": "1.60M",
    "gemini_daily_count": 42,
    "gemini_daily_limit": 1400
  },
  "sqlite": { "available": true, "total_urls": 9, "today_scans": 0 },
  "playwright_pool": { "browser_alive": true },
  "module": "01_phishing_detector"
}
```

---

## 3. A2 — Celery Async Pipeline

**Dosyalar:** `modules/phishing_detector/celery_tasks.py`, `router.py`  
**Etki:** API yanıt süresi ~200ms'e düşer; ağır analiz arka planda çalışır.

### Akış

```
POST /check-url
  └─ run_quick_checks() ~200ms
       ├─ Kesin sonuç → 200 OK (sync yanıt)
       └─ Belirsiz  → Celery'e gönder → 202 Accepted
                         {
                           "status": "analyzing",
                           "job_id": "abc123",
                           "safety_score": 45,
                           "risk_level": "⚠️ Şüpheli"
                         }

GET /result/{job_id}
  ├─ pending  → {"status": "pending"}
  └─ complete → {"status": "complete", ...tam sonuç...}
```

### Celery Konfigürasyonu

```python
CELERY_BROKER_URL  = "redis://127.0.0.1:6379/1"
CELERY_RESULT_BACKEND = "redis://127.0.0.1:6379/1"
task_soft_time_limit = 120   # saniye
task_time_limit      = 150   # saniye
worker_concurrency   = 2
worker_pool          = "prefork"
```

### Systemd Servisi

```
/etc/systemd/system/aegisnexus-celery-phishing.service
```

```bash
systemctl status aegisnexus-celery-phishing.service
journalctl -u aegisnexus-celery-phishing.service -f
```

---

## 4. A3 — Playwright Browser Pool

**Dosya:** `modules/phishing_detector/playwright_pool.py`  
**Etki:** Her request için yeni Chromium başlatmak yerine process başına 1 kalıcı instance → ~600MB RAM tasarrufu.

### Mimari

```
Celery Worker Process 1
  └─ _pool: PlaywrightPool (singleton)
       └─ browser: Chromium (persistent)
            ├─ context_1 (request izolasyonu)
            └─ context_2 (request izolasyonu)

Celery Worker Process 2
  └─ _pool: PlaywrightPool (singleton)
       └─ browser: Chromium (persistent)
```

### API

```python
from modules.phishing_detector.playwright_pool import (
    init_pool,           # worker_process_init sinyalinde çağrılır
    close_pool,          # worker_process_shutdown sinyalinde çağrılır
    acquire_browser_context,  # context manager, request başına
    is_healthy,          # {"browser_alive": True/False}
)

# Kullanım
with acquire_browser_context() as context:
    page = context.new_page()
    page.goto(url)
    screenshot = page.screenshot()
```

### Başlatma Argümanları

```python
PLAYWRIGHT_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-sync",
    "--single-process",
]
```

### Celery Sinyalleri (`celery_tasks.py`)

```python
@worker_process_init.connect
def init_playwright_pool(**kwargs):
    init_pool()

@worker_process_shutdown.connect
def close_playwright_pool(**kwargs):
    close_pool()
```

---

## 5. A4 — Paralel Threat Intelligence

**Dosya:** `modules/phishing_detector/threat_intel.py`  
**Etki:** 5 threat intel kaynağı eş zamanlı sorgulanır → toplam süre en yavaş kaynağa eşit (~3s yerine ~1s).

### Kaynaklar

| Kaynak | Fonksiyon | Limit |
|--------|-----------|-------|
| VirusTotal | `check_virustotal()` | 4 req/dk (key rotation) |
| AbuseIPDB | `check_abuseipdb()` | 1500 req/gün |
| Google Safe Browsing | `check_google_safe_browsing()` | API key gerekli |
| PhishTank | `check_phishtank()` | Yerel DB |
| URLScan.io | `check_urlscan()` | — |

### Paralel Çalışma

```python
with ThreadPoolExecutor(max_workers=5) as ex:
    futures = {
        ex.submit(check_virustotal, url): "virustotal",
        ex.submit(check_abuseipdb, ip):   "abuseipdb",
        ex.submit(check_gsb, url):        "gsb",
        ex.submit(check_phishtank, url):  "phishtank",
        ex.submit(check_urlscan, url):    "urlscan",
    }
    for f in as_completed(futures, timeout=10):
        results[futures[f]] = f.result()
```

---

## 6. B1 — HTML Derin Analizi

**Dosya:** `modules/phishing_detector/visual_analyzer.py` → `analyze_html()`  
**Etki:** Gemini çağrısı gerektirmeden, sadece HTML içeriğini analiz ederek marka taklidi ve kimlik bilgisi toplama tespiti.

### Tespit Edilen Örüntüler

| Kategori | Örnek |
|----------|-------|
| Marka taklit | `<title>PayPal Giriş</title>` ama domain `paypal-secure.tk` |
| Credential form | `<input type="password">`, `<input name="cvv">` |
| Domain uyumsuzluğu | Sayfada "Ziraat Bankası" logosu ama domain `ziraat.xyz` |
| Gizlenmiş form | Form action URL'i farklı domaine gönderir |

### Çıktı

```python
{
    "penalty": 55,            # 0-100 arası risk puanı
    "brand": "ziraat",        # Tespit edilen marka
    "credential_fields": 2,   # Şifre/kart alanı sayısı
    "domain_mismatch": True,  # Domain uyumsuzluğu
    "detail": "Marka domain uyumsuzluğu: ziraat"
}
```

### Desteklenen Markalar

`BRAND_DOMAINS` sözlüğünde tanımlı:  
PayPal, Google, Microsoft, Apple, Amazon, Netflix, Facebook, Instagram, Twitter, WhatsApp, Ziraat, Garanti, Akbank, İşbank, VakıfBank, Halkbank, Denizbank, Enpara, BtcTurk, Paribu + daha fazlası.

---

## 7. B2 — pHash Logo Karşılaştırma

**Dosya:** `modules/phishing_detector/visual_analyzer.py` → `check_logo_phash()`  
**Araç:** `imagehash` kütüphanesi (perceptual hash)  
**DB:** `modules/phishing_detector/data/logo_hashes.json`  
**Etki:** Screenshot'ta bilinen marka logosu tespit edilince Gemini atlanır.

### Çalışma Prensibi

```
Screenshot PNG
  │
  ├─► Tam ekran pHash hesapla
  ├─► Üst %30 (header bölgesi) pHash hesapla
  │
  ▼
logo_hashes.json içindeki her hash ile karşılaştır
  │
  ├─ Hamming mesafesi ≤ 8 → Eşleşme!
  │     └─ Domain kontrolü: markanın kendi sitesiyse ceza yok
  │     └─ Farklı domain: penalty=60, definitive=True → Gemini bypass
  │
  └─ Mesafe > 8 → Eşleşme yok, penalty=0
```

### Logo Veritabanı (20 Marka, 22 Hash)

| Kategori | Markalar |
|----------|----------|
| Global Teknoloji | PayPal, Google, Microsoft, Apple, Amazon, Netflix, Facebook, Instagram, Twitter, WhatsApp |
| Türk Bankalar | Ziraat, Garanti, Akbank, İşbank, VakıfBank, Halkbank, Denizbank, Enpara |
| Kripto | BtcTurk, Paribu |

### DB'yi Yenileme

```bash
# Sunucuda
cd /var/www/aegis_nexus
venv/bin/python -m modules.phishing_detector.build_logo_db
```

### Çıktı

```python
{
    "penalty": 60,
    "brand": "ziraat",
    "definitive": True,
    "distance": 3,
    "similarity": 96.1,
    "detail": "Logo eşleşti (ziraat): mesafe=3"
}
```

---

## 8. B3 — EasyOCR Metin Okuma

**Dosya:** `modules/phishing_detector/visual_analyzer.py` → `analyze_with_ocr()`  
**Model:** EasyOCR `['tr', 'en']`, CPU, ~400MB RAM  
**Model Dizini:** `/var/www/aegis_nexus/.easyocr_models`  
**Etki:** Screenshot'taki metin marka adı veya kimlik bilgisi içeriyorsa, Gemini çağrısı atlanır.

### Singleton Yükleme

```python
# process-başına tek seferlik lazy init
_ocr_reader = None

def get_ocr_reader():
    global _ocr_reader
    if _ocr_reader is None:
        import easyocr
        _ocr_reader = easyocr.Reader(
            ['tr', 'en'],
            gpu=False,
            verbose=False,
            model_storage_directory=_OCR_MODEL_DIR,
        )
    return _ocr_reader
```

### Tespit Mantığı

| Durum | Penalty |
|-------|---------|
| Marka adı görünüyor (yanlış domain) | +55 |
| Marka + kimlik bilgisi alanı | +55 ~ +70 (max 70) |
| Markanın kendi domaini | 0 (ceza yok) |
| Sadece kimlik alanı (marka yok) | 0 (false positive önlemi) |

### Kimlik Bilgisi Anahtar Kelimeleri (22 adet)

`şifre, parola, password, pin, kart no, cvv, iban, tc kimlik, username, otp, sms kodu` ve diğerleri.

### Çıktı

```python
{
    "penalty": 70,
    "definitive": True,
    "ocr_text_sample": "ziraat bankası giriş şifre kart numarası...",
    "brands_found": ["ziraat"],
    "credentials_found": ["şifre", "kart numarası"],
    "detail": "OCR marka tespiti: ziraat | Kimlik bilgisi isteği: şifre, kart numarası"
}
```

---

## 9. B4 — Koşullu Gemini

**Dosya:** `modules/phishing_detector/screenshot_analyzer.py` → `_should_skip_gemini()`  
**Etki:** Önceki katmanlar (HTML, pHash, OCR) yüksek penalty üretirse Gemini çağrılmaz → günlük ~%80 kota tasarrufu.

### Karar Mantığı

```python
GEMINI_DAILY_LIMIT = 1400  # .env ile yapılandırılabilir
PRE_PENALTY_THRESHOLD = 65

def _should_skip_gemini(pre_penalty: int) -> tuple[bool, str]:
    # 1. Önceki katmanlar yeterliyse atla
    if pre_penalty >= PRE_PENALTY_THRESHOLD:
        return True, f"Önceki katmanlar yeterli (penalty={pre_penalty})"
    # 2. Günlük limit dolmuşsa atla
    if redis_get_gemini_count() >= GEMINI_DAILY_LIMIT:
        return True, "Günlük Gemini limiti aşıldı"
    return False, ""
```

### Analiz Zinciri İçinde Sıra

```
HTML analizi (B1)      → pre_penalty += html_penalty
pHash logo (B2)        → kesin eşleşmede direkt dön (Gemini atla)
EasyOCR (B3)           → pre_penalty += ocr_penalty
                              │
                              ▼
                    _should_skip_gemini(pre_penalty)
                              │
                    ┌─────────┴─────────┐
                  Evet                 Hayır
                    │                   │
              OCR sonucu         Gemini çağır
              ile dön            sayaç++
```

---

## 10. C1 — Frontend Polling UI

**Dosya:** `frontend-react/src/ModulesApp.jsx` → `PhishingDetector` component  
**Etki:** 15-30s bloke eden tek fetch yerine anında hızlı sonuç göster + arka planda derin analizi izle.

### State Yönetimi

```javascript
const [jobId, setJobId] = useState(null)
const [analyzing, setAnalyzing] = useState(false)
const [pollCount, setPollCount] = useState(0)
const MAX_POLLS = 30   // 30 × 3s = 90s maksimum bekleme
```

### handleCheck() Akışı

```javascript
const d = await fetch('/api/v2/phishing/check-url', {...}).then(r => r.json())

if (d.status === 'analyzing' && d.job_id) {
    // Hızlı katman sonucunu hemen göster
    setResult(d)
    setJobId(d.job_id)
    setAnalyzing(true)   // polling useEffect tetiklenir
} else {
    setResult(d)         // Kesin sonuç, direkt göster
}
```

### Polling useEffect

```javascript
useEffect(() => {
    if (!jobId || !analyzing) return
    if (pollCount >= MAX_POLLS) {
        setAnalyzing(false)
        showToast('Analiz zaman aşımı', 'error')
        return
    }
    const timer = setTimeout(async () => {
        const d = await fetch(`/api/v2/phishing/result/${jobId}`).then(r => r.json())
        if (d.status === 'complete') {
            setResult(d)      // UI tam sonuçla güncellenir
            setAnalyzing(false)
            setJobId(null)
        } else {
            setPollCount(c => c + 1)   // 3s sonra tekrar dene
        }
    }, 3000)
    return () => clearTimeout(timer)
}, [jobId, analyzing, pollCount])
```

### Progress Bar UI

- 🔍 dönen ikon (framer-motion rotate animasyonu)
- "Derin Analiz Devam Ediyor..." + geçen süre (`pollCount × 3` saniye)
- `AnimatePresence` ile smooth mount/unmount
- Progress bar dolumu: `(pollCount / MAX_POLLS) × 100%`, max %95

---

## 11. Analiz Zinciri Akışı

```
URL girer
    │
    ▼
run_quick_checks() — ~200ms
    ├── Redis cache hit?    → dön ✅
    ├── Whitelist?          → dön ✅
    ├── SQLite cache hit?   → dön ✅
    ├── PhishTank DB?       → dön ⚠️/🚨
    ├── ML skor >= 80?      → dön 🚨
    └── Belirsiz            → Celery'e ilet
                                │
                                ▼
                    run_heavy_analysis() [Celery]
                                │
                    ┌───────────┼───────────────┐
                    │           │               │
              HTML analizi  Playwright     Threat Intel
                (B1)        screenshot      (A4 paralel)
                    │           │
                    │       pHash (B2)
                    │       ├── Eşleşme → Gemini atla, dön 🚨
                    │       │
                    │       EasyOCR (B3)
                    │       ├── Kesin → Gemini atla, dön 🚨
                    │       │
                    │       pre_penalty hesapla
                    │       │
                    │       _should_skip_gemini()?
                    │       ├── Evet → local sonuç dön
                    │       └── Hayır → Gemini çağır (B4)
                    │                       │
                    └───────────────────────┘
                                │
                    Redis'e sonuç yaz (TTL 3600s)
                                │
                    Frontend polling tamamlar (C1)
```

---

## 12. Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|----------|------------|----------|
| `REDIS_URL` | `redis://127.0.0.1:6379/0` | Ana Redis bağlantısı |
| `CELERY_BROKER_URL` | `redis://127.0.0.1:6379/1` | Celery broker |
| `GEMINI_DAILY_LIMIT` | `1400` | Günlük max Gemini çağrısı |
| `PHASH_THRESHOLD` | `8` | pHash Hamming mesafe eşiği |
| `PLAYWRIGHT_POOL_SIZE` | `1` | Process başına Chromium instance |
| `EASYOCR_MODEL_DIR` | `/var/www/aegis_nexus/.easyocr_models` | Model dizini |
| `VIRUSTOTAL_API_KEYS` | — | Virgülle ayrılmış key listesi (rotation) |
| `GOOGLE_SAFE_BROWSING_KEYS` | — | GSB API key |
| `ABUSEIPDB_API_KEYS` | — | AbuseIPDB key listesi |
| `GEMINI_API_KEY` | — | Google Gemini API key |

---

## 13. Servis Yönetimi

### Servisler

```bash
# API
systemctl status aegisnexus-api.service
systemctl restart aegisnexus-api.service

# Celery Worker
systemctl status aegisnexus-celery-phishing.service
systemctl restart aegisnexus-celery-phishing.service

# Loglar
journalctl -u aegisnexus-celery-phishing.service -f -n 50
```

### Deployment

```bash
# Sunucuda
cd /var/www/aegis_nexus
git pull origin main

# Frontend build
cd frontend-react && npm run build

# Logo DB güncelle (gerektiğinde)
venv/bin/python -m modules.phishing_detector.build_logo_db

# Servis yeniden başlat
systemctl restart aegisnexus-api.service
systemctl restart aegisnexus-celery-phishing.service
```

### Sağlık Kontrolleri

```bash
# Cache health
curl http://localhost:8000/api/v2/phishing/cache-health | python3 -m json.tool

# Test endpoint
curl -X POST http://localhost:8000/api/v2/phishing/check-url \
     -H "Content-Type: application/json" \
     -d '{"url": "https://example.com"}'

# Unit testler
cd /var/www/aegis_nexus
venv/bin/pytest tests/ -v --tb=short
```
