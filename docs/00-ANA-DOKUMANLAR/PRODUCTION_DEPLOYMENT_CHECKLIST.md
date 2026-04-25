# Production Deployment Checklist

## Runtime
- API: FastAPI/Uvicorn
- Port: `8000`
- Canonical routes: `/api/v2/*`
- Domain: `https://aegisnexus.dev`

## Required Environment
- `DATABASE_URL`
- `ADMIN_API_KEY`
- `CORS_ALLOW_ORIGINS`
- Threat intel keys (`VIRUSTOTAL_*`, `URLSCAN_*`, `ABUSEIPDB_*`, `GOOGLE_SAFE_BROWSING_*`)

## Pre-Deploy Checks
- Install dependencies
- Validate env values
- Run syntax/tests
- Build frontend if needed

## Post-Deploy Smoke Tests
```bash
curl -s http://127.0.0.1:8000/api/v2/ai-analyzer/health
curl -s http://127.0.0.1:8000/api/v2/phishing/stats
curl -s "http://127.0.0.1:8000/api/v2/phishing/latest-paged?limit=5&page=1"
curl -s -X POST http://127.0.0.1:8000/api/v2/phishing/check-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Failure Triage Order
1. API process up?
2. DB reachable?
3. Provider keys valid?
4. CORS and reverse proxy correct?
5. Frontend API base correct?
