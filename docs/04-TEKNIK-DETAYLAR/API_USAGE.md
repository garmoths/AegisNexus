# AegisNexus API Usage (Quick)

## 1) Health
```bash
curl -s http://127.0.0.1:8000/api/v2/ai-analyzer/health
```

## 2) URL Scan
```bash
curl -s -X POST http://127.0.0.1:8000/api/v2/phishing/check-url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## 3) Stats
```bash
curl -s http://127.0.0.1:8000/api/v2/phishing/stats
```

## 4) Latest (Paged)
```bash
curl -s "http://127.0.0.1:8000/api/v2/phishing/latest-paged?limit=20&page=1"
```

## 5) History
```bash
curl -s "http://127.0.0.1:8000/api/v2/phishing/history?limit=50&days=30"
```

## Notes
- `score` grows as risk increases.
- `risk_level` is typically `safe|low|medium|high|critical`.
- `status: degraded` means system returned a safe fallback result.
- Frontend base URL should come from `VITE_API_BASE_URL` (fallback `/api/v2`).
