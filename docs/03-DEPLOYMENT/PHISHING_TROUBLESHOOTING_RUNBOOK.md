# Phishing Troubleshooting Runbook

## Scope
This runbook targets failures in `modules.aegisnexus.dev` phishing analysis flow.

## Canonical Endpoints
- `POST /api/v2/phishing/check-url`
- `GET /api/v2/phishing/stats`
- `GET /api/v2/phishing/latest-paged?limit=20&page=1`
- `GET /api/v2/phishing/history?limit=50&days=30`

## Smoke Checks
```bash
curl -s http://127.0.0.1:8000/api/v2/phishing/stats
curl -s "http://127.0.0.1:8000/api/v2/phishing/latest-paged?limit=5&page=1"
curl -s -X POST http://127.0.0.1:8000/api/v2/phishing/check-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Common Failure Modes
1. `500` on history/latest due to model-field drift  
   - Ensure `submission_time` is used consistently for `PhishingURL`.
2. Frontend cannot fetch API
   - Verify reverse proxy to `127.0.0.1:8000`.
   - Verify `CORS_ALLOW_ORIGINS` includes frontend origins.
3. Slow/timeouts on `check-url`
   - Local threat intelligence kullanılıyor (sıfır external API call)
   - Threat-intel providers artık local DB ve IP blacklist kullanıyor
   - Hala yavaşsa: DB connection pool veya CPU kullanımını kontrol et
4. Empty stats/latest
   - Verify `phishing_urls` table has data.
   - Verify ingestion jobs and credentials.

## Validation Queries
```bash
sudo -u postgres psql -d phishing_db -c "SELECT COUNT(*) FROM phishing_urls;"
sudo -u postgres psql -d phishing_db -c "SELECT MAX(submission_time) FROM phishing_urls;"
```

## Recovery Order
1. API process health (`uvicorn` / service).
2. DB connectivity and row counts.
3. Provider keys and outbound connectivity.
4. Frontend API base (`VITE_API_BASE_URL`) and CORS.

