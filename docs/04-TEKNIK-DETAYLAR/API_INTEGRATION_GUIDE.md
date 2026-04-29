# AegisNexus API Integration Guide

## Base URL
- Production: `https://aegisnexus.dev/api/v2`
- Local: `http://127.0.0.1:8000/api/v2`

## Core Endpoints
- `POST /phishing/check-url`
- `GET /phishing/stats`
- `GET /phishing/latest-paged?limit=20&page=1`
- `GET /phishing/history?limit=50&days=30`

## Minimal Request/Response
### `POST /phishing/check-url`
```json
{"url":"https://example.com"}
```

Success or degraded response shape:
```json
{
  "status": "ok",
  "url": "https://example.com",
  "score": 42,
  "risk_level": "medium",
  "details": [],
  "sources": [],
  "module": "01_phishing_detector"
}
```

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
      "threat_indicators": [],
      "recommendation": "..."
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

### Orchestrator Task
`run_ioc_fetch` — Tüm IOC task'larını paralel kuyruğa alır:
- `fetch_urlhaus`
- `fetch_otx`
- `fetch_threatfox_iocs`
- `fetch_spamhaus_iocs`

## Screenshot Analyzer (Gemini Vision)
- **Model:** `gemini-2.0-flash`
- **Akış:** Playwright screenshot → base64 PNG → Gemini Vision API → JSON verdict
- **Env:** `GEMINI_API_KEY`
- **Çıktı:** `{risk_score, risk_level, verdict, threat_indicators, recommendation}`

## Threat Intel Cache
- **Backend:** SQLite (`threat_intel_cache` tablosu)
- **TTL:** 12 saat (Spamhaus, URLhaus, ThreatFox sorgu sonuçları)
- **Fonksiyonlar:** `write_threat_cache(key, data, ttl_seconds)`, `read_threat_cache(key)`
- **Otomatik:** Cache hit → API çağrısı atlanır, cache miss → API sorgulanıp cache'e yazılır

## Frontend Integration (Fetch)
```javascript
const API = import.meta.env.VITE_API_BASE_URL || "/api/v2";

export async function checkUrl(url) {
  const normalized = /^https?:\/\//i.test(url) ? url : `https://${url}`;
  const res = await fetch(`${API}/phishing/check-url`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: normalized }),
  });
  if (!res.ok) throw new Error(`API error ${res.status}`);
  return await res.json();
}
```

## Error Handling Rules
- `400`: invalid/empty input
- `429`: rate limit exceeded
- `500`: unexpected server error
- `status: "degraded"`: partial result returned when external providers fail

## Deployment Notes
- Canonical API surface is `v2` on FastAPI/Uvicorn.
- If frontend uses another origin, set `CORS_ALLOW_ORIGINS`.
- Keep `.env` out of git, use `.env.example` as template.
