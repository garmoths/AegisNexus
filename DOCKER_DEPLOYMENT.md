# AegisNexus — Docker Deployment Guide

**Last updated:** July 2026 (tested on Apple Silicon Mac)  
**Platform:** Docker Desktop + docker compose v2  
**Minimum:** Docker 24+, 4GB RAM, 15GB disk

## Quick Start

```bash
# 1. Frontend build
cd frontend-react && npm install && npm run build && cd ..

# 2. Configure environment
cp .env.example .env

# 3. Build and start
docker compose up --build -d

# 4. Watch logs
docker compose logs -f api
```

## Access URLs

| Service | URL | Description |
|---|---|---|
| Main app | http://localhost:8000 | React SPA |
| API Docs | http://localhost:8000/docs | Swagger UI |
| RabbitMQ UI | http://localhost:15672 | Management console |

## Services

```
rabbitmq:3.13-management-alpine  → ports 5672, 15672
api (FastAPI)                    → port 8000
celery (worker + beat embed)     → queues: default, phishing
```

## Daily Commands

```bash
# Start
docker compose up -d

# Stop (data preserved)
docker compose down

# Logs
docker compose logs -f api
docker compose logs -f celery

# Rebuild after code changes
docker compose up --build -d

# Full reset (⚠️ deletes SQLite data)
docker compose down -v && rm -f data/aegis.db
```

## Troubleshooting

```bash
# API not starting
docker compose logs api --tail=50

# Celery tasks not running
docker compose exec celery celery -A app.celery_app:celery_app inspect active

# Playwright issues
docker compose exec celery playwright --version

# RabbitMQ check
docker compose exec rabbitmq rabbitmq-diagnostics ping
```

## Apple Silicon Notes

- Playwright uses ARM64 Chromium
- First build ~10 min, subsequent builds ~2 min (cached)
- No CUDA/CUDA runtime needed (CPU-only torch removed)
