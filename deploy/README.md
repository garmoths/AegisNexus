# AegisNexus — Server Setup Guide

## Prerequisites

```bash
# Docker & Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

## Installation

```bash
# Clone
git clone https://github.com/YOUR_USER/AegisNexus.git
cd AegisNexus

# Frontend build
cd frontend-react && npm install && npm run build && cd ..

# Environment
cp .env.example .env
# Edit .env with your API keys

# Start
docker compose up --build -d
```

## Update

```bash
git pull
cd frontend-react && npm run build && cd ..
docker compose up --build -d
```

## Nginx Reverse Proxy (Production)

```nginx
server {
    listen 443 ssl http2;
    server_name your-domain.com;

    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
