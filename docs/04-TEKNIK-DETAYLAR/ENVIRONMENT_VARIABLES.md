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

If both singular and plural are present, plural key list is preferred.

## AI and Breach
- `OPENAI_API_KEY` (optional)
- `GROQ_API_KEY` (optional)
- `HIBP_API_KEY` (optional)

## Security Rules
1. Do not commit `.env` files.
2. Keep `.env.example` as non-secret template only.
3. Rotate any leaked keys immediately.

