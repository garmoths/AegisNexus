# AegisNexus — Siber Mağduriyet Atlası Full-Stack Planı

Mevcut projeye User/Auth, Gemini analiz, yeni API endpoint'leri, Celery görevleri ve zengin frontend sayfaları ekler.

## Kararlar
- Frontend: Vite+React+framer-motion+inline CSS (Next.js yok)
- DB: Tümü PostgreSQL (Victim Atlas SQLite→PG)
- Auth: API key tabanlı (JWT yok), X-API-Key header
- Ödeme: Stub/mock (İyzico interface hazır)
- Tema: Mevcut renkler korunur (#080c14, #00d4ff, #ff6b35 vb.)

---

## AŞAMA 1 — Veritabanı (PostgreSQL + SQLAlchemy)
- `app/models.py`'e ekle: users, api_keys, case_tags, user_reports, subscriptions, alert_subscriptions
- Victim Atlas SQLite→PG: ORM modelleri oluştur, `database.py` güncelle, taşıma script'i yaz
- Alembic kur + ilk migration
- Test: `tests/test_models.py`, `tests/test_migration.py`

## AŞAMA 2 — Backend API (FastAPI)
- Auth: `/api/v2/auth` — register, login, rotate-key, logout + rate limit middleware
- Cases: mevcut router'ı genişlet (POST/PATCH admin, protection-card)
- Reports: `/api/v2/reports` — analyze(Gemini), list, PDF(quota)
- Stats: `/api/v2/victim-atlas/stats` — overview, heatmap(GeoJSON), weekly-digest
- Subscription: `/api/v2/subscription` — me, upgrade(stub)
- Corporate: `/api/v2/corporate` — cases, stats, webhook
- Admin: genişlet — classify, users, role change
- Test: auth, reports, stats, subscription, corporate API testleri

## AŞAMA 3 — Gemini Entegrasyonu
- `modules/victim_atlas/gemini_service.py`: analyze_user_report, classify_case, generate_weekly_digest, generate_protection_card
- `modules/victim_atlas/prompts/`: 4 prompt template dosyası
- Retry, token limit, hata yönetimi
- Test: mock Gemini yanıtları

## AŞAMA 4 — Celery Görevleri
- `modules/victim_atlas/celery_tasks.py`: ingest(6h), classify(1h), hot-set(gece), alert, digest(Pzt), PDF
- Beat schedule güncelle
- Test: task unit testleri

## AŞAMA 5 — Frontend (Vite+React+react-router-dom)
- Routing: /, /atlas, /atlas/:slug, /analyze, /harita, /dashboard, /admin
- Yeni deps: zustand, axios, react-simple-maps, jspdf
- Auth store: zustand (apiKey, role, email)
- API client: axios interceptor (X-API-Key)
- Sayfalar: Ana Sayfa(hero+sayaçlar), Atlas(filtre+grid), Vaka Detay, Analiz Aracı, Harita, Dashboard, Admin
- Ortak bileşenler: CaseCard, RiskBadge, AttackTypeBadge, ProtectionPlan, ThreatTicker, StatCounter, GeminiLoader, PremiumGate, PrivateRoute
- Mevcut tema ve efektlerle uyumlu

## AŞAMA 6 — Deployment
- docker-compose.yml (fastapi, postgresql, redis, celery worker/beat, nginx)
- nginx.conf (reverse proxy)
- .env.example
- Makefile (up, down, migrate, logs, shell)
