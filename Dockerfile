# syntax=docker/dockerfile:1.4
# ============================================================
# AegisNexus — Backend Image
# BuildKit cache mount kullanır → pip paketleri build'ler arası cache'lenir
# İlk build: ~15-20 dk (torch indirme)
# Sonraki build'ler: ~1-3 dk (pip cache + layer cache)
# Build: docker build --build-arg BUILDKIT_INLINE_CACHE=1 -t aegisnexus:latest .
# ============================================================
FROM python:3.11-slim-bookworm

# ── Ortam değişkenleri ──────────────────────────────────────
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# ── Sistem bağımlılıkları ───────────────────────────────────
# ⚠️  Debian Bookworm'da libasound2 → libasound2t64 oldu (önemli fix!)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools (psycopg2-binary, lxml derleme için)
    gcc \
    g++ \
    libpq-dev \
    libxml2-dev \
    libxslt1-dev \
    # Runtime kütüphaneler
    libpq5 \
    libxml2 \
    libxslt1.1 \
    curl \
    wget \
    ca-certificates \
    git \
    # Playwright / Chromium runtime (Debian Bookworm amd64 + arm64)
    libnss3 \
    libnspr4 \
    libdbus-1-3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    fonts-liberation \
    fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# ── libasound: Bookworm'da paket adı libasound2, Trixie'de libasound2t64 ──
# İkisinden biri mutlaka kurulur (Docker base değişse bile çalışır)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libasound2 \
    || apt-get install -y --no-install-recommends libasound2t64 \
    ; rm -rf /var/lib/apt/lists/*

WORKDIR /app

# pip güncelle
RUN pip install --upgrade pip

# ── KATMAN 1: Uygulama bağımlılıkları ───────────────────────
# torch/easyocr/transformers kaldırıldı → image ~5GB daha küçük.
# numpy + sklearn burada (yerel phishing modeli için).
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install -r requirements.txt

# ── KATMAN 2: Playwright Chromium ───────────────────────────
# PLAYWRIGHT_BROWSERS_PATH=/ms-playwright → sabit konum
# Cache mount: binary'ler build'ler arası yeniden indirilmez
RUN --mount=type=cache,target=/root/.cache/ms-playwright \
    playwright install chromium && \
    mkdir -p /ms-playwright && \
    cp -r /root/.cache/ms-playwright/. /ms-playwright/ 2>/dev/null || true

# Playwright binary'lerin gerçekten kurulduğunu doğrula
RUN test -d /ms-playwright || playwright install chromium

# ── KATMAN 4: Uygulama kodu ─────────────────────────────────
# En son katman — en sık değişir ama en hızlı kopyalanır
COPY . .

# Çalışma dizinleri oluştur
RUN mkdir -p /app/data /app/logs

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
