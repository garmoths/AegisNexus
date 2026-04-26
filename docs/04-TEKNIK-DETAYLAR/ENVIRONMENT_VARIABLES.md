# Environment Variables

## Core
- `DATABASE_URL` (required): PostgreSQL connection string.
- `ADMIN_API_KEY` (required): Protects sensitive admin endpoints.

## Frontend and CORS
- `VITE_API_BASE_URL` (required for separate frontend origin): API base, default `/api/v2`.
- `CORS_ALLOW_ORIGINS` (required): Comma-separated allowed origins.

## Threat Intel Providers
- `VIRUSTOTAL_API_KEY` or `VIRUSTOTAL_API_KEYS`
- `GOOGLE_SAFE_BROWSING_KEY` or `GOOGLE_SAFE_BROWSING_KEYS`
- `URLSCAN_API_KEY` or `URLSCAN_API_KEYS`
- `ABUSEIPDB_API_KEY` or `ABUSEIPDB_API_KEYS`
- `ALIENVAULT_OTX_API_KEY` (required for OTX phishing pulls)
- `KAGGLE_API_TOKEN` (recommended for Kaggle dataset download)
- `KAGGLE_USERNAME` + `KAGGLE_KEY` (legacy alternative)

If both singular and plural are present, plural key list is preferred.

## AI and Breach
- `OPENAI_API_KEY` (optional)
- `GROQ_API_KEY` (optional)
- `HIBP_API_KEY` (optional)

## Celery Threat Intel Jobs
- `CELERY_BROKER_URL` (optional): Broker URL, default `amqp://guest:guest@localhost:5672//`.
- `CELERY_RESULT_BACKEND` (optional): Celery result backend, default `rpc://`.
- `CELERY_TIMEZONE` (optional): Celery timezone, default `UTC`.
- `CELERY_IOC_INTERVAL_SECONDS` (optional): IOC refresh interval, default `3600`.
- `CELERY_PHISHING_INTERVAL_SECONDS` (optional): Phishing refresh interval, default `7200`.
- `CELERY_IOC_SOURCES` (optional): Comma-separated IOC sources, default `abuse_urlhaus,abuse_phishtank,abuseipdb`.
- `CELERY_IOC_LIMIT_PER_SOURCE` (optional): Per-source IOC fetch limit, default `1000`.

## Phishing Multi-Source Collector
- `PHISHING_GITHUB_FEEDS` (optional): Comma-separated GitHub raw feed URLs.
- `PHISHING_OPENPHISH_LIMIT` (optional): Max OpenPhish URLs per run (default `20000`).
- `PHISHING_URLHAUS_LIMIT` (optional): URLHaus fetch limit (default `3000`).
- `PHISHING_URLHAUS_PHISHING_ONLY` (optional): `1` ise URLHaus sadece phishing etiketli kayıtları alır (default `0`).
- `PHISHING_KAGGLE_DATASET` (optional): Kaggle dataset ref `owner/dataset` (default `taruntiwarihp/phishing-site-urls`).
- `PHISHING_KAGGLE_LIMIT` (optional): Max Kaggle URLs per run (default `100000`).
- `PHISHING_OTX_LIMIT` (optional): OTX pulse fetch size (default `200`).
- `CERTSTREAM_WS_URL` (optional): CertStream websocket URL (default `wss://certstream.calidog.io/`).
- `CERTSTREAM_MAX_URLS` (optional): Max CertStream domains per run (default `500`).
- `CERTSTREAM_DURATION_SECONDS` (optional): CertStream consume duration in seconds (default `20`).
- `CERTSTREAM_KEYWORDS` (optional): Comma-separated phishing keyword list for CertStream domain heuristic.
- `CERTSTREAM_ALLOW_GENERIC_DOMAINS` (optional): Şüpheli eşleşme yoksa genel domain fallback aktif (`1` default).

## Victim Atlas Module
- `VICTIM_ATLAS_DB_PATH` (optional): Separate SQLite DB path. Default `data/victim_atlas.db`.
- `VICTIM_ATLAS_HOT_SET_LIMIT` (optional): Number of hot cases kept active. Default `1000`.
- `VICTIM_ATLAS_SOURCE_ITEM_LIMIT` (optional): Max fetched items per source run. Default `120`.
- `VICTIM_ATLAS_ENRICH_LIMIT` (optional): Enrichment pass limit. Default `500`.
- `VICTIM_ATLAS_SIKAYETVAR_RSS_URL` (optional): ToS-uyumlu sikayet akisi (RSS/Atom) URL'i.
- `VICTIM_ATLAS_SIKAYETVAR_TRUST_TIER` (optional): `tier1` or `tier2` (default `tier2`).
- `VICTIM_ATLAS_TR_CERT_FEED_URL` (optional): TR CERT/kurumsal duyuru RSS URL'i.
- `VICTIM_ATLAS_TR_CERT_TRUST_TIER` (optional): `tier1` or `tier2` (default `tier1`).

Source toggles (optional, `1` or `0`):
- `VICTIM_ATLAS_SOURCE_CISA_ADVISORIES`
- `VICTIM_ATLAS_SOURCE_KREBSONSECURITY`
- `VICTIM_ATLAS_SOURCE_BLEEPINGCOMPUTER`
- `VICTIM_ATLAS_SOURCE_PROOFPOINT_BLOG`
- `VICTIM_ATLAS_SOURCE_REDDIT_SCAM`
- `VICTIM_ATLAS_SOURCE_GOOGLE_NEWS_TR_DOLANDIRICILIK`
- `VICTIM_ATLAS_SOURCE_GOOGLE_NEWS_TR_SAHTE_UYGULAMA`
- `VICTIM_ATLAS_SOURCE_SIKAYETVAR_RSS` (env URL tanimliysa)
- `VICTIM_ATLAS_SOURCE_TR_CERT_FEED` (env URL tanimliysa)

Celery daily schedule (UTC):
- `VICTIM_ATLAS_INGEST_HOUR_UTC` (default `3`)
- `VICTIM_ATLAS_INGEST_MINUTE` (default `30`)
- `VICTIM_ATLAS_ENRICH_HOUR_UTC` (default `3`)
- `VICTIM_ATLAS_ENRICH_MINUTE` (default `50`)
- `VICTIM_ATLAS_PRUNE_HOUR_UTC` (default `4`)
- `VICTIM_ATLAS_PRUNE_MINUTE` (default `10`)

## Security Rules
1. Do not commit `.env` files.
2. Keep `.env.example` as non-secret template only.
3. Rotate any leaked keys immediately.
