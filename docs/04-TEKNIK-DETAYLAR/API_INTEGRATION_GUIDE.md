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
