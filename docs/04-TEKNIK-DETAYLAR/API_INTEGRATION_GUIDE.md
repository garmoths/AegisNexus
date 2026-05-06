# AegisNexus API Integration Guide

## Base URL
- Production: `https://aegisnexus.dev/api/v2`
- Local: `http://127.0.0.1:8000/api/v2`

## Core Endpoints
- `POST /phishing/check-url` — Hızlı kontrol; belirsizse `{status:"analyzing", job_id}` döner (A2)
- `GET /phishing/result/{job_id}` — Async job sonucu sorgulama (A2/C1)
- `GET /phishing/stats`
- `GET /phishing/latest-paged?limit=20&page=1`
- `GET /phishing/history?limit=50&days=30`
- `GET /phishing/cache-health` — Redis + SQLite + Playwright pool sağlık durumu (A1/A3)

## Minimal Request/Response
### `POST /phishing/check-url`
```json
{"url":"https://example.com"}
```

**Request:**
```json
{"url": "https://example.com", "force_fresh": false}
```

`force_fresh: true` → Redis + SQLite cache bypass eder, taze tarama yapar.

**Success response:**
```json
{
  "url": "https://example.com",
  "safety_score": 85,
  "score": 85,
  "risk_level": "✅ Güvenli",
  "details": [],
  "sources": [],
  "cache": "redis-hit",
  "module": "01_phishing_detector"
}
```

`cache` alanı değerleri: `"redis-hit"` | `"sqlite-hit"` | `"none"` (yeni tarama)

**Async yanıt (ağır analiz kuyruğa alındıysa — A2):**
```json
{
  "status": "analyzing",
  "job_id": "3f7a21b0-...",
  "safety_score": 45,
  "risk_level": "⚠️ Şüpheli",
  "cache": "none",
  "module": "01_phishing_detector"
}
```

### `GET /phishing/result/{job_id}` (A2/C1)

**Bekliyor:**
```json
{"status": "pending"}
```

**Tamamlandı:**
```json
{
  "status": "complete",
  "url": "https://example.com",
  "safety_score": 12,
  "risk_level": "🚨 Tehlikeli",
  "threat_intel": { ... },
  "gemini_skipped": false
}
```

**Polling Örüntüsü (JavaScript):**
```javascript
async function pollResult(jobId, interval = 3000, maxTries = 30) {
  for (let i = 0; i < maxTries; i++) {
    await new Promise(r => setTimeout(r, interval))
    const d = await fetch(`/api/v2/phishing/result/${jobId}`).then(r => r.json())
    if (d.status === 'complete') return d
  }
  throw new Error('Analiz zaman aşımına uğradı')
}
```

**Önemli:** `score` alanı `safety_score` ile eşanlamlıdır; ikisi de aynı değeri döner. Frontend `safety_score` kullanmalıdır.

`check-url` cevabında `threat_intel` altında görsel analiz sonucu da dönebilir:
```json
{
  "threat_intel": {
    "virustotal": {},
    "google_safe_browsing": {},
    "abuseipdb": {},
    "screenshot_analysis": {
      "risk_score": 72,
      "risk_level": "HIGH",
      "verdict": "Brand impersonation şüphesi",
      "screenshot_analysis": "...",
      "threat_indicators": [
        {"type": "visual", "value": "PayPal logo clone", "reason": "Brand impersonation"}
      ],
      "recommendation": "...",
      "screenshot_b64": "<base64 PNG data — frontend'de görsel göstermek için>"
    },
    "urlhaus": {
      "listed": false,
      "status": "clean"
    },
    "spamhaus_domain": {
      "listed": false,
      "status": "clean"
    },
    "spamhaus_ip": {
      "listed": false,
      "status": "clean"
    },
    "threatfox": {
      "found": false,
      "status": "not found"
    }
  }
}
```

### Threat Intel Scoring (Penalties)
| Source | Condition | Penalty |
|--------|-----------|---------|
| URLhaus | URL listed | -40 |
| Spamhaus DBL | Domain listed | -35 |
| Spamhaus XBL/eXBL | IP listed | -30 |
| ThreatFox | IOC found | -25 |
| Spamhaus ZRD | Zero-reputation domain | -15 |

## External Threat Intel API Authentication

### Spamhaus Intel API
- **Auth:** Login-based JWT token (`POST /api/v1/login`)
- **Env:** `SPAMHAUS_USERNAME` + `SPAMHAUS_PASSWORD`
- **Rate Limits (std tier):** 150 req/s, 9000 req/min, 200K req/saat
- **Endpoints:**
  - `GET /api/v1/bl?q=<domain>` — DBL/ZRD domain sorgulama
  - `GET /api/v1/bl?q=<ip>` — XBL/eXBL/CBL IP sorgulama
- **Token TTL:** 1 saat (otomatik yenileme)

### abuse.ch URLhaus
- **Auth:** `Auth-Key` header ile API key
- **Env:** `ABUSE_API_KEY`
- **Endpoint:** `POST https://urlhaus-api.abuse.ch/v1/url/`
- **Body:** `{"url": "<target_url>"}`
- **CSV Download:** `https://urlhaus.abuse.ch/downloads/csv_recent/` (public, auth gerekmez)

### abuse.ch ThreatFox
- **Auth:** `Auth-Key` header ile API key
- **Env:** `ABUSE_API_KEY`
- **Endpoint:** `POST https://threatfox-api.abuse.ch/api/v1/`
- **Body:** `{"query": "search_ioc", "search_term": "<value>"}`
- **Ingest:** `{"query": "get_iocs", "days": 7, "limit": 500}`
- **Not:** API'de IOC alan adı `ioc` (eski versiyonlarda `ioc_value`)

### AbuseIPDB
- **Durum:** API collector'dan kaldırıldı (free plan: 1000 check/gün limiti aşıldığı için)
- **Yerine:** Local IP blacklist (Firehol, Spamhaus DROP, Emerging Threats) kullanılıyor
- **Env:** `ABUSEIPDB_API_KEYS` hâlâ tanımlı ama sadece manuel sorgularda kullanılır

## Celery Beat Schedule (Otomatik Veri Çekme)

| Task | Schedule | Açıklama |
|------|----------|----------|
| `update_ioc_feeds` | Her saat | URLhaus + PhishTank IOC toplama |
| `update_phishing_feeds` | Her 2 saat | Tüm kaynaklardan phishing URL çekme (OpenPhish, URLhaus CSV, Kaggle, CertStream, OTX, ThreatFox) |
| `fetch_threatfox_iocs` | Her 4 saat (:00) | ThreatFox'tan son IOC'ları çekip IOC tablosuna yazma |
| `fetch_spamhaus_iocs` | Her 6 saat (:30) | Yüksek riskli domain'leri Spamhaus'ta sorgulayıp listed olanları IOC tablosuna yazma |
| `fetch_urlhaus` | Manuel/Orchestrator | URLhaus IOC toplama (run_ioc_fetch ile) |
| `fetch_otx` | Manuel/Orchestrator | AlienVault OTX IOC toplama (run_ioc_fetch ile) |
| `refresh_ip_blacklists` | Günde 1 kez (02:00 UTC) | Firehol, Spamhaus DROP, Emerging Threats IP listelerini indir + memory'e yükle |
| `victim_atlas_ingest_daily` | Günde 1 kez (03:30 UTC) | Victim Atlas günlük veri çekme |
| `victim_atlas_enrich_cases` | Günde 1 kez (03:50 UTC) | Victim Atlas case zenginleştirme |
| `victim_atlas_prune_hotset` | Günde 1 kez (04:10 UTC) | Victim Atlas hotset temizleme |
| `modules.victim_atlas.celery_tasks.ingest_6h` | Her 6 saat (varsayılan 21600 sn) | Victim Atlas için alternatif sık ingest schedule |

### Orchestrator Task
`run_ioc_fetch` — Tüm IOC task'larını paralel kuyruğa alır:
- `fetch_urlhaus`
- `fetch_otx`
- `fetch_threatfox_iocs`
- `fetch_spamhaus_iocs`

## Victim Atlas (Güncel Entegrasyon Notları)

### Kaynak Politikası
- Varsayılan ingest yalnız güvenilir Türk haber RSS kaynaklarına odaklıdır.
- Runtime source registry her ingest başında sync edilir; konfigürde olmayan legacy kaynaklar `enabled=false` yapılır.

### Ingest Filtreleri
- Son 1 yıl filtresi: RSS yayın tarihi `now - 365 gün` altında ise kayıt alınmaz.
- Tarihi parse edilemeyen kayıtlar, `VICTIM_ATLAS_ALLOW_UNDATED=false` iken ingest edilmez.
- Fraud relevance filtresi + kaynak bazlı hint seti uygulanır.
- URL canonicalization uygulanır (`utm_*`, `fbclid`, `gclid`, `yclid` temizlenir).

### Dedupe ve Vaka Birleştirme
- Raw doc düzeyinde: `source_id + external_id` ve `hash` dedupe.
- Vaka düzeyinde: benzer başlık/token eşleşmesinde (Jaccard) mevcut vakaya merge + evidence bağlama.
- Vaka listesi sıralaması en güncel içerik üstte olacak şekilde `last_seen DESC` önceliklidir.

### Region (İl) Çıkarma
- İl çıkarımı başlık + özet metinden yapılır.
- Türkçe normalize (`İ/ı`, aksanlar, ekli yazımlar: `istanbulda`, `ankaraya` vb.) desteklenir.
- Metinden il bulunamazsa URL/external_id/source_name metadata fallback devreye girer.

### API Çıktı Alanları (Victim Atlas Cases)
`GET /victim-atlas/cases` ve `GET /victim-atlas/cases/{id}` dönüşlerine eklenen alanlar:
- `attack_method_tr`
- `loss_type_tr`
- `target_platform_tr`

### Ingest Health Gözlemlenebilirlik
`GET /victim-atlas/ingest/health` → `last_run.filter_stats` içerir:
- `entries_seen`
- `skipped_lookback`
- `skipped_relevance`
- `accepted`
- `by_source` (kaynak kırılımı)

### Heatmap Entegrasyonu
- `GET /victim-atlas/stats/heatmap` il bazlı `FeatureCollection` döner.
- Frontend harita katmanı, il yoğunluğunu bu endpoint'ten; yöntem rengini vaka listesinden birleştirir.
- Böylece bazı vakalarda `region` boş olsa bile il bazlı görünüm korunur.

## Screenshot Analyzer (Gemini Vision + Koşullu Çağrı)
- **Model:** `gemini-2.0-flash`
- **Akış:** Playwright screenshot → base64 PNG → _Koşullu kontrol_ → Gemini Vision API → JSON verdict
- **Env:** `GEMINI_API_KEY`, `GEMINI_DAILY_LIMIT` (varsayılan: `1400`), `GEMINI_SKIP_THRESHOLD` (varsayılan: `65`)
- **Çıktı (normal):** `{risk_score, risk_level, verdict, threat_indicators, recommendation}`
- **Çıktı (Gemini atlandı):** `{risk_score: 35, risk_level: "UNKNOWN", gemini_skipped: true, gemini_skip_reason: "...", available: true}`

### Koşullu Gemini Mantığı (B4)
Gemini, aşağıdaki koşullarda **atlanır**:
1. **`pre_penalty >= GEMINI_SKIP_THRESHOLD` (65):** B1/B2/B3 katmanları zaten yeterli penaltı ürettiyse (B1/B2/B3 uygulandığında aktif).
2. **Günlük kota aşıldıysa:** Redis `gemini:daily_count` sayıcısı `GEMINI_DAILY_LIMIT`'e ulaştıysa.

Gemini atlandığında `threat_intel`'de `+10` belirsizlik cezası uygulanır (ekran görüntüsü yoksa `+15`).

**Gemini günlük sayıcı izleme:**
```
GET /phishing/cache-health
→ redis.gemini_daily_count  # bugün kaç kez Gemini çağrıldı
→ redis.gemini_daily_limit  # 1400 (default)
```

## Threat Intel Cache

### Katmanlı Cache Mimarisi (A1)
| Katman | Backend | TTL | Amacı |
|--------|---------|-----|--------|
| 1. Sıcak cache | **Redis** | 30 gün | ~0.3ms hit, RAM-based |
| 2. Soğuk cache | **SQLite** (`threat_intel_cache.db`) | 30 gün | Kalıcı geçmiş |
| 3. API | Spamhaus / URLhaus / ThreatFox | — | Cache miss durumunda |

**Çalışma akışı:**
1. Redis'te var → dön (~0.3ms)
2. SQLite'ta var → Redis'e de yaz, dön
3. İkisi de yok → API çağr, her ikisine yaz

**Redis yoksa:** Sessizce SQLite fallback (hata fırlatmaz).

### Threat Intel API Cache
- **Backend:** SQLite (`threat_intel_cache` tablosu)
- **TTL:** 12 saat (Spamhaus, URLhaus, ThreatFox sorgu sonuçları)
- **Fonksiyonlar:** `write_threat_cache(key, data, ttl_seconds)`, `read_threat_cache(key)`
- **Otomatik:** Cache hit → API çağrısı atlanır, cache miss → API sorgulanıp cache'e yazılır

### Cache Health Endpoint
```
GET /api/v2/phishing/cache-health
```
```json
{
  "redis": {
    "available": true,
    "used_memory_human": "1.60M",
    "gemini_daily_count": 42,
    "gemini_daily_limit": 1400
  },
  "sqlite": {
    "available": true,
    "total_urls": 1823,
    "today_scans": 14
  },
  "playwright_pool": {
    "browser_alive": true
  },
  "module": "01_phishing_detector"
}
```

## Frontend Integration

### API Fetch — Async Polling Örüntüsü (C1)

`check-url` anında sync veya async yanıt dönebilir. Frontend her iki durumu da işlemelidir:

```javascript
const API = import.meta.env.VITE_API_BASE_URL || "/api/v2";

async function handleCheck(url) {
  const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`
  const d = await fetch(`${API}/phishing/check-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: normalized }),
  }).then(r => r.json())

  if (d.status === "analyzing" && d.job_id) {
    // Hızlı sonucu göster, polling başlat
    showQuickResult(d)
    return pollUntilComplete(d.job_id)
  }
  // Kesin sonuç — direkt göster
  return d
}

async function pollUntilComplete(jobId, maxPolls = 30) {
  for (let i = 0; i < maxPolls; i++) {
    await new Promise(r => setTimeout(r, 3000))
    const d = await fetch(`${API}/phishing/result/${jobId}`).then(r => r.json())
    if (d.status === "complete") return d
  }
  throw new Error("Analiz zaman aşımına uğradı (90s)")
}
```

### PhishingResult Component (React)
`check-url` yanıtı `PhishingResult` bileşeninde görselleştirilir:

| Bölüm | Açıklama |
|-------|----------|
| **Hero Result Card** | Risk gauge + risk level badge + screenshot thumbnail (tıklayınca büyür) + tespit listesi |
| **Threat Intel Source Cards** | 8 kaynak kartı grid layout: URLhaus, Spamhaus Domain, Spamhaus IP, ThreatFox, VirusTotal, Google Safe Browsing, AbuseIPDB (Local), Screenshot Analyzer — her biri listed/clean/found badge + penalty göstergesi |
| **Görsel Tehdit İndikatörleri** | Gemini Vision'dan `threat_indicators` listesi (visual/url/domain/ip tipinde, değer + neden) |
| **Taranan Kaynaklar** | API'den `sources` listesi, başarı/hata durumuna göre renkli |

**Screenshot Display:**
- `screenshot_b64` alanı varsa → `<img src="data:image/png;base64,...">` thumbnail gösterilir
- Tıklama → yeni pencerede tam ekran screenshot
- `screenshot_b64` yoksa → screenshot bölümü gizlenir

**Source Card Renk Kuralları:**
- 🔴 Kırmızı: `isBad` (listed/found/threat) — `theme.accent`
- 🟢 Yeşil: `isClean` (clean/safe/not found) — `theme.success`
- ⚪ Gri: veri yok / N/A — `theme.textMuted`

## Error Handling Rules
- `400`: invalid/empty input
- `429`: rate limit exceeded
- `500`: unexpected server error
- `status: "degraded"`: partial result returned when external providers fail

## Deployment Notes
- Canonical API surface is `v2` on FastAPI/Uvicorn.
- If frontend uses another origin, set `CORS_ALLOW_ORIGINS`.
- Keep `.env` out of git, use `.env.example` as template.
