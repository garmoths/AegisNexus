# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's [private vulnerability reporting](https://github.com/garmoths/AegisNexus/security/advisories/new) instead. Include the affected endpoint or file, reproduction steps and the impact. We aim to acknowledge reports within 7 days.

Only the latest commit on `main` receives security fixes.

## Security model

- **Deployment scope:** AegisNexus is built for a single self-hosted machine. By default the API binds to `127.0.0.1`. Before exposing it, put it behind a TLS-terminating reverse proxy (see `deploy/nginx.conf`) and set `CORS_ALLOW_ORIGINS` to your own origin.
- **Authentication:** API keys (`X-API-Key`) or an HttpOnly, `SameSite=Strict` session cookie. Keys, session tokens and recovery tokens are 256-bit random values, stored only as SHA-256 hashes. Expired sessions and spent recovery tokens are purged daily.
- **Authorization:** one role model (`free` < `premium` < `corporate` < `admin`). Every maintenance or bulk endpoint requires `admin`. Admins are created locally with `make create-admin`. Public registration can never grant a privileged role.
- **CSRF:** cookie-authenticated writes from origins that are neither the API host nor an allowed origin are rejected.
- **SSRF:** URLs fetched for a user are resolved, and requests to private, loopback, link-local or reserved addresses are refused on every redirect hop (`app/outbound.py`).
- **Rate limiting:** a per-IP cap on all API calls and per-user budgets for mutating calls, by role. Recovery endpoints have a stricter limit.
- **Data minimisation:** access logs omit query strings. Error responses never contain exception text. The honeypot records *that* a field was filled in, never its value. Anonymous scans are not stored per user.
- **Secrets:** all secrets come from the environment or `.env`, which is git-ignored and never committed. `.env.example` contains no real values.

## Out of scope

Rate-limit tuning on your own deployment, missing hardening headers when the app is served without the recommended reverse proxy, and findings that need an existing admin account.
