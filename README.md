# AegisNexus

AegisNexus is an open-source, self-hosted cybersecurity platform. It combines phishing detection, threat-intelligence aggregation, AI-assisted message analysis, an IOC feed with a honeypot, SMS fraud checks and a phishing discovery crawler. One FastAPI backend serves them all, and a React + TypeScript UI sits on top.

**Stack:** FastAPI · Pydantic v2 · SQLAlchemy 2 + Alembic · SQLite · Celery + Redis (Unix socket) · React 19 + TypeScript · Vite

## Quick start

Requirements: Python 3.11–3.13, Node.js 20.19+ or 22.12+ with npm, and `redis-server`. The launcher installs Redis for you if it's missing.

```bash
git clone https://github.com/garmoths/AegisNexus.git
cd AegisNexus
cp .env.example .env     # optional: every setting has a default
./run.sh                 # installs deps, migrates, builds the UI, starts everything
make create-admin        # in a second terminal: prints an admin API key once
```

Then open http://127.0.0.1:8000 and sign in with that e-mail and key. API docs are at http://127.0.0.1:8000/docs.

`./run.sh` creates `.venv`, installs dependencies, applies database migrations, builds the frontend and starts the API, Redis, the Celery worker and Celery beat. All data is stored in `data/`.

```bash
./run.sh status          # show running services
./run.sh stop            # stop everything
./run.sh --port 8001     # use another port
./run.sh --no-install    # skip install/build (after a first run)
./run.sh --crawler       # standalone discovery console on :8010
```

## Modules

| Module | API prefix | What it does |
|---|---|---|
| Phishing detector | `/api/v2/phishing` | URL scans (quick checks, then a queued browser + threat-intel analysis), phishing database, per-user scan history |
| Honeypot / IOC | `/api/v2/honeypot`, `/api/v2/ioc` | Decoy login page, IOC extraction and feeds, IP/hash reputation, STIX 2.1 export |
| AI analyzer | `/api/v2/ai-analyzer` | Hybrid (rules + LLM) phishing/scam scoring for messages and raw e-mails |
| SMS guard | `/api/v2/sms` | Explainable Turkish smishing rules with an IOC cross-check |
| Discovery | `/api/v2/crawler` | CertStream/seed-driven crawler with human review before anything is published |
| Workspace | `/api/v2/...` | Incident reports and PDFs, watchlists, notifications, feedback, admin |

Every external integration (VirusTotal, Google Safe Browsing, AbuseIPDB, abuse.ch, Spamhaus, PhishTank, OTX, Gemini, Groq) is optional. Without a key, that source is skipped and the response says so.

## API conventions

- **Auth:** send `X-API-Key: <key>`, or use the HttpOnly session cookie from `POST /api/v2/auth/login`. Permissions come from the key's role (`free`, `premium`, `corporate`, `admin`).
- **Errors:** every error has the same shape. `detail` is human-readable, `error.code` is stable and machine-readable, and `error.request_id` matches the `X-Request-ID` header and the server logs:
  ```json
  {"detail": "Endpoint bulunamadı.", "error": {"code": "not_found", "status": 404, "request_id": "9f2c41d07a3b5e18"}}
  ```
- **Rate limits:** per user or IP, by role. A rejected request gets `429` with a `Retry-After` header.

## Configuration

All settings live in [`app/config.py`](app/config.py) as one typed `Settings` class, and every variable is documented in [`.env.example`](.env.example). Values are read from the environment first, then from `.env`. `LOG_FORMAT=json` switches to structured logs.

## Development

```bash
make dev         # dev tools + pre-commit hooks
make check       # everything a change must pass: lint, typecheck, tests, frontend build
make test        # pytest (backend) + vitest (frontend)
make lint        # ruff + eslint
make typecheck   # mypy + tsc
make migrate     # alembic upgrade head
```

Schema changes go through Alembic (`alembic revision --autogenerate -m "..."`). A test fails if the models and migrations drift apart.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): components, request and scan flows, design decisions
- [CRAWLER_DESIGN.md](CRAWLER_DESIGN.md): the discovery crawler (Turkish)
- [CONTRIBUTING.md](CONTRIBUTING.md): workflow, conventions and how to add a module
- [SECURITY.md](SECURITY.md): reporting vulnerabilities and the security model

## License

[MIT](LICENSE)
