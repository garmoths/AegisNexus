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
- `KAGGLE_USERNAME` + `KAGGLE_KEY` (required for Kaggle dataset download)

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

## Security Rules
1. Do not commit `.env` files.
2. Keep `.env.example` as non-secret template only.
3. Rotate any leaked keys immediately.
