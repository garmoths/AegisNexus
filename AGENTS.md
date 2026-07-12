# AegisNexus — Agent Rehberi

Bu dosya yapay zeka asistanlarının (opencode vb.) projeyi hızlı anlaması ve dış bağımlılık envanterini görmesi içindir.

## Mimari Özet (kişisel çalışma konfigürasyonu)

- **Backend:** FastAPI (`app/main.py`) — `http://localhost:8000`
- **Frontend:** React SPA — `frontend-react/dist` host'ta `npm run build` edilip backend'e bind mount (compose) ile serve edilir (`/`, `/modules`, catch-all route'ları).
- **Worker:** Tek Celery servis (worker + beat embed, `-B -Q default,phishing -P solo -c 1`)
- **Broker:** RabbitMQ (compose `rabbitmq` servisi)
- **DB:** SQLite (`./data/aegis.db`) — Postgres/Redis kaldırıldı
- **Cache:** In-memory (Python dict + TTL, `modules/phishing_detector/redis_cache.py`)
- **Celery job polling:** SQLite `celery_jobs` tablosu (`modules/phishing_detector/cache_db.py`)

## Docker komutları

```bash
# Frontend build (host) → sonra backend image build + up
cd frontend-react && npm run build && cd ..
docker compose up -d --build

# Loglar / durum
docker compose logs -f api celery
docker compose ps

# Tam sıfırlama (veri KORUNUR): docker compose down
# Tehlikeli (SQLite dahil veri silinir): docker compose down -v && rm -f data/aegis.db
```

## Dış API bağımlılık envanteri

### Bakımdaki modüller (dış API kullanmaz hâlde)
| Modül | Durum | Bilgi |
|---|---|---|
| `breach_intel` | **BAKIMDA** (`BREACH_INTEL_MAINTENANCE=1`) | 503 döner. HIBP breachedaccount + Groq + Ollama bağımlılıkları awaits. Diğer endpoint'lerin hepsi guard'lı. |

### Çalışan modüllerin dış bağımlılıkları
| Modül | API / Servis | Env var | Anahtar gerekli mi? |
|---|---|---|---|
| `phishing_detector` | VirusTotal | `VIRUSTOTAL_API_KEYS` / `VIRUSTOTAL_API_KEY` | EVET (yoksa layer atlanır) |
| `phishing_detector` | Google Safe Browsing | `GOOGLE_SAFE_BROWSING_KEYS` / `GOOGLE_SAFE_BROWSING_KEY` | EVET |
| `phishing_detector` | AbuseIPDB | `ABUSEIPDB_API_KEYS` / `ABUSEIPDB_API_KEY` | EVET |
| `phishing_detector` | abuse.ch ThreatFox/URLhaus/MalwareBazaar | `ABUSE_API_KEY` / `ABUSE_API_KEYS` / `URLHAUS_API_KEY` | EVET (URLhaus key opsiyonel) |
| `phishing_detector` | AlienVault OTX | `ALIENVAULT_OTX_API_KEY` | EVET |
| `phishing_detector` | SpamHaus Intel | `SPAMHAUS_USERNAME` / `SPAMHAUS_PASSWORD` | EVET |
| `phishing_detector` | PhishTank | `PHISHTANK_APP_KEY` / `PHISHTANK_USERNAME` | HAYIR (keyless çalışır) |
| `phishing_detector` | Shodan InternetDB, RDAP, GitHub raw feeds | — | HAYIR (auth'suz) |
| `phishing_detector` | Groq (screenshot analizi) | `GROQ_API_KEY` / `GROQ_BASE_URL` / `GROQ_MODEL` | EVET (yoksa AI skip) |
| `ai_analyzer` | Groq (LLM) | `GROQ_API_KEY` / `GROQ_BASE_URL` / `GROQ_MODEL` | EVET (yoksa yerli sklearn TF-IDF fallback) |
| `ai_analyzer` | VirusTotal + URLScan (opt.) | `VIRUSTOTAL_API_KEY` / `URLSCAN_API_KEY` | EVET (opsiyonel) |
| `ai_analyzer` | transformers emotion pipeline | — | KALDIRNDI (no-op) |
| `honeypot` | URLhaus, PhishTank, AbuseIPDB, AlienVault, ThreatFox, SpamHaus (phishing_detector client'ları paylaşır) | Yukarıdakiler | EVET (yoksa boş IOC feed) |
| `password_shield` | HIBP Pwned Passwords (k-anonymity) | — | HAYIR (keyless public API) |
| `victim_atlas` | Google Gemini | `GEMINI_API_KEY` / `GEMINI_MODEL` | EVET (yoksa sınıflandırma pasif) |
| `victim_atlas` | TR haber RSS feedleri | — | HAYIR (public, `VICTIM_ATLAS_*` env ile özelleştirilebilir) |
| `sms_guard` | (yok) | — | — |
| `risk_dashboard` | (yok) | — | — |
| `breach_intel` | (BAKIMDA — çalışırken HIBP/Ollama/Groq/scrape) | `HIBP_API_KEY`, `GROQ_API_KEY`, `OLLAMA_URL` | BAKIMDA |

### Yerel servisler (docker-compose)
| Servis | image | Portu |
|---|---|---|
| RabbitMQ | `rabbitmq:3.13-management-alpine` | `5672` (broker), `15672` (mgmt UI) |
| AegisNexus API + Celery | `aegisnexus:latest` | `8000` (API) |

### Lite footprint (~700 MB image) gerekirse
Playwright Chromium (~1.4 GB) kaldırılabilir — bu takdirde phishing `screenshot_analyzer.py` / `playwright_pool.py` devre dışı kalır. Dockerfile'dan ilgili `RUN playwright install` ve `PLAYWRIGHT_BROWSERS_PATH` env kaldırılır, `requirements.txt`'ten `playwright==1.52.0` silinir.

## Build/lint/typecheck komutları

```bash
# Backend testleri (host'ta venv)
pytest tests/

# Frontend build + lint
cd frontend-react && npm run lint && npm run build

# Backend image build
docker compose build api

# İmport smoke test (devam eden container'da)
docker compose exec api python -c "import app.main; print('OK')"
```

## Sık karşılaşılan sorunlar

- **`alembic upgrade head` SQLite'ta patlar:** `ALTER COLUMN TYPE` SQLite'ta desteklenmez — migration `if bind.dialect.name == 'sqlite': return` ile guard'lanmalı (örnek: `b1bd93ace2e8`).
- **celery `-Q` ile task_default_queue uyuşmazlığı:** `celery_app.py`'de `task_default_queue=\"default\"`. Çalışan celery servisi `-Q default,phishing` dinlemelidir.
- **Host 5432/6379 portu çakışması:** Postgres/Redis artık compose'da yok; ama host'ta lokal servisler çalışıyorsa kendi instance'lar ile çakışma olmaz.
- **Playwright \"Sync API inside asyncio\":** API process'inde preload atılır, ama çağrılar her zaman celery worker (solo pool) tarafından yapılmalıdır.
- **`easyocr yüklü değil` warnings:** benign — easyocr kaldırıldı, kod try/except guard'lı, no-op davranır.
- **`IP list file not found: /opt/phishing/...`:** benign — IP blacklist opsiyonel; `refresh_ip_blacklists` beat task'ı indirince dosyalar oluşur.