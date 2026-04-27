# AegisNexus - Cybersecurity Platform

[![Deploy to Frankfurt](https://github.com/garmoths/AegisNexus/actions/workflows/deploy.yml/badge.svg)](https://github.com/garmoths/AegisNexus/actions)

**Live:** https://aegisnexus.dev

## Quick Start
- API docs: `docs/04-TEKNIK-DETAYLAR/API_INTEGRATION_GUIDE.md`
- Quick commands: `docs/04-TEKNIK-DETAYLAR/API_USAGE.md`
- Deployment checklist: `docs/00-ANA-DOKUMANLAR/PRODUCTION_DEPLOYMENT_CHECKLIST.md`

**API Base (Canonical):** `https://aegisnexus.dev/api/v2`

Legacy `v1` endpoints should be treated as compatibility-only and not used for new integrations.

## Modules
- 🎣 Phishing Detector (URL tarama + SSL/Domain analizi + Local Threat Intelligence - sıfır external API)
- 🕸️ Honeypot
- 📡 Breach Intelligence
- 🔐 Password Shield
- ⚡ Threat Responder

## Auto-Deploy
Every push to `main` deploys via GitHub Actions workflow.
