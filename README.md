# AegisNexus — Modular Cybersecurity Platform

AegisNexus is an open-source, modular cybersecurity platform with 8 defense modules. It combines phishing detection, threat intelligence, AI-powered analysis, and victim profiling in a single Dockerized stack.

**Stack:** FastAPI + React SPA + Celery + RabbitMQ + SQLite

---

## Quick Start (Docker)

```bash
# Prerequisites: Docker 24+, docker compose v2, Node.js 20+

git clone https://github.com/YOUR_USER/AegisNexus.git
cd AegisNexus

# Frontend build
cd frontend-react && npm install --legacy-peer-deps && npm run build && cd ..

# Configure (all API keys optional — works without them)
cp .env.example .env

# Build and start
docker compose up --build -d

# Open http://localhost:8000
```

**That's it.** The platform runs with zero API keys — all modules gracefully degrade when keys are missing.

---

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌──────────────┐
│  React SPA  │────▶│  FastAPI     │────▶│  Celery      │
│  (frontend) │     │  (backend)   │     │  (worker+beat)│
└─────────────┘     └──────┬───────┘     └──────┬───────┘
                          │                     │
                          ▼                     ▼
                    ┌──────────┐        ┌──────────────┐
                    │  SQLite  │        │   RabbitMQ   │
                    │  (data/) │        │   (broker)   │
                    └──────────┘        └──────────────┘
```

- **Backend:** FastAPI (Python 3.11+)
- **Frontend:** React SPA (Vite)
- **Worker:** Celery (single worker with embedded beat scheduler)
- **Broker:** RabbitMQ
- **Database:** SQLite (file-based, no external DB server)
- **Cache:** In-memory (Python dict + TTL)

---

## Modules

| Module | Endpoint | Description | API Key Needed |
|---|---|---|---|
| **Phishing Detector** | `/api/v2/phishing` | URL scanning, SSL/domain analysis, HTML signal detection, screenshot analysis, multi-source threat intel | Optional |
| **Honeypot** | `/api/v2/honeypot` | IOC collection from PhishTank, URLhaus, ThreatFox, SpamHaus, AlienVault OTX | Optional |
| **Breach Intel** | `/api/v2/breach` | Breached account search via HIBP | 🔧 Maintenance |
| **Password Shield** | `/api/v2/shield` | Password strength via HIBP k-anonymity | None (keyless) |
| **AI Analyzer** | `/api/v2/ai` | ML-based phishing analysis with LLM fallback | Optional |
| **Victim Atlas** | `/api/v2/victim-atlas` | Victim profiling from news RSS + Gemini AI | Optional |
| **SMS Guard** | `/api/v2/sms-guard` | SMS phishing detection | None |
| **Risk Dashboard** | `/api/v2/risk` | Risk scoring & visualization | None |

---

## API Keys Guide

### No Key Required (Works Out of Box)

| Feature | How It Works |
|---|---|
| Phishing URL scanning | Local SSL/domain/HTML analysis + screenshot |
| Password Shield | HIBP k-anonymity API (public, no key needed) |
| AI Analyzer | sklearn TF-IDF fallback when no LLM key |
| Honeypot IOC | Public feeds (PhishTank, URLhaus, GitHub raw) |
| Victim Atlas | RSS news ingestion (basic mode) |

### Where to Get API Keys

| Service | What It Does | How to Get | Env Variable |
|---|---|---|---|
| **VirusTotal** | URL reputation & threat intel | [virustotal.com](https://www.virustotal.com/gui/my-apikey) — Free: 500 req/day | `VIRUSTOTAL_API_KEYS` |
| **Google Safe Browsing** | URL safety classification | [console.cloud.google.com](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com) — Free: 10K req/day | `GOOGLE_SAFE_BROWSING_KEYS` |
| **AbuseIPDB** | IP reputation check | [abuseipdb.com/register](https://www.abuseipdb.com/register) — Free: 1K req/day | `ABUSEIPDB_API_KEYS` |
| **AlienVault OTX** | Threat intelligence feed | [otx.alienvault.com/settings](https://otx.alienvault.com/settings) — Free | `ALIENVAULT_OTX_API_KEY` |
| **Abuse.ch** | URLhaus + ThreatFox malware feeds | [urlhaus.abuse.ch/api/](https://urlhaus.abuse.ch/api/) — Free | `ABUSE_API_KEY` |
| **SpamHaus** | DNSBL threat data | [spamhaus.org/registration](https://www.spamhaus.org/registration/) — Free | `SPAMHAUS_USERNAME` + `SPAMHAUS_PASSWORD` |
| **Groq** | LLM-powered phishing analysis | [console.groq.com/keys](https://console.groq.com/keys) — Free tier | `GROQ_API_KEY` |
| **Google Gemini** | Victim Atlas AI classification | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) — Free tier | `GEMINI_API_KEY` |
| **URLScan.io** | Website screenshot & analysis | [urlscan.io/user/api](https://urlscan.io/user/api/) — Free: 50 req/month | `URLSCAN_API_KEYS` |
| **HIBP** | Breached account search | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) | `HIBP_API_KEY` |

---

## Environment Variables

```bash
cp .env.example .env
```

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | Yes | `sqlite:///./data/aegis.db` | SQLite database path |
| `RABBITMQ_PASSWORD` | Yes | `changeme` | RabbitMQ password |
| `ADMIN_API_KEY` | Yes | — | Admin API key |
| `CORS_ALLOW_ORIGINS` | No | `http://localhost:8000,http://localhost:5173` | CORS origins |
| `GEMINI_API_KEY` | No | — | Google Gemini for Victim Atlas |
| `GROQ_API_KEY` | No | — | Groq LLM for phishing analysis |
| `VIRUSTOTAL_API_KEYS` | No | — | VirusTotal URL scanning |
| `GOOGLE_SAFE_BROWSING_KEYS` | No | — | Google Safe Browsing |
| `ABUSEIPDB_API_KEYS` | No | — | AbuseIPDB reputation |
| `ALIENVAULT_OTX_API_KEY` | No | — | AlienVault OTX feed |
| `ABUSE_API_KEY` | No | — | URLhaus/ThreatFox feeds |
| `SPAMHAUS_USERNAME` | No | — | SpamHaus DNSBL |
| `HIBP_API_KEY` | No | — | Have I Been Pwned |

---

## Background Tasks

The Celery beat scheduler runs these automatically:

| Task | Interval | Description |
|---|---|---|
| IOC feed refresh | Every 1h | Update threat intelligence feeds |
| Phishing feed refresh | Every 2h | Update phishing URL feeds |
| PhishTank DB sync | Every 12h | Sync PhishTank database |
| IP blacklist refresh | Daily 02:00 | Refresh IP blacklists |
| SpamHaus IOC fetch | Every 6h | Fetch SpamHaus indicators |
| ThreatFox IOC fetch | Every 4h | Fetch ThreatFox indicators |
| Victim Atlas ingest | Every 6h | Ingest news RSS feeds |
| Victim Atlas classify | Hourly | Classify pending cases |

---

## Pre-loaded Data

The database comes with threat intelligence data from production:

These are pre-loaded from the compressed backup (`backup.sql.gz.part.*`, ~143 MB split into 95 MB chunks) included in the repo.

To import the data (skip if you ran `docker compose up` — already done):

```bash
# The database at data/aegis.db already contains the data from the Compose setup.
# To re-import from scratch:
./scripts/restore_backup.sh
```

| Table | Records | Description |
|---|---|---|
| `phishing_urls` | 1,801,572 | Phishing URLs from PhishTank |
| `indicators_of_compromise` | 51,589 | IOCs from public threat feeds |
| `victim_cases` | 286 | Victim case profiles |
| `raw_documents` | 375 | News articles |
| `fraud_profiles` | 8 | Fraud type profiles |

---

## License

MIT
