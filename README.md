# AegisNexus

AegisNexus is an open-source, modular cybersecurity platform for running on your own machine. It combines phishing detection, threat intelligence, AI-assisted analysis, a honeypot/IOC feed, SMS fraud checks and incident-report analysis behind one FastAPI backend and React UI.

**Stack:** FastAPI · React (Vite) · Celery · Redis (local Unix socket) · SQLite

## Quick start

Requirements: Python 3.11–3.13, Node.js 20+ with npm, and `redis-server`. The launcher tries to install Redis for you if it's missing.

```bash
git clone https://github.com/garmoths/AegisNexus.git
cd AegisNexus
cp .env.example .env   # optional: every API key is optional
./run.sh
```

Then open http://127.0.0.1:8000.

`./run.sh` creates `.venv`, installs dependencies, builds the frontend and starts the API, Redis and the Celery worker and beat. Data is stored in `data/`.

Other commands:

```bash
./run.sh status          # show running services
./run.sh stop            # stop everything
./run.sh --port 8001     # use another port
./run.sh --no-install    # skip install/build (after a first run)
./run.sh --crawler       # standalone discovery console on :8010
```

See [CRAWLER_DESIGN.md](CRAWLER_DESIGN.md) for the discovery crawler.

## Modules

| Module | API prefix |
|---|---|
| Phishing detector | `/api/v2/phishing` |
| Honeypot / IOC feed | `/api/v2/honeypot`, `/api/v2/ioc` |
| AI analyzer | `/api/v2/ai-analyzer` |
| SMS guard | `/api/v2/sms` |
| Reports, workspace, admin, auth | `/api/v2/...` |

## Configuration

All settings live in `.env` (see [.env.example](.env.example)). Without API keys (Gemini, VirusTotal, Safe Browsing, URLScan, …), the integrations that need them are simply skipped. Set `ADMIN_API_KEY` to a long random value before exposing the app anywhere.

## Tests

```bash
.venv/bin/python -m pytest -q
```

## License

[MIT](LICENSE)
