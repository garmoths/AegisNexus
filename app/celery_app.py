"""
AegisNexus — Merkezi Celery Uygulaması
========================================
Tüm modüller bu tek Celery instance'ını kullanır.

Broker : RabbitMQ  (RABBITMQ_URL env var)
Backend: rpc://    (RabbitMQ RPC — ayrı storage gerekmez)
Cache  : Redis     (redis_cache.py — YALNIZCA scan sonuçları, AI sayacı)

Queue'lar:
  phishing  → solo pool, 1 worker  (Playwright thread-safety gerektirir)
  default   → prefork pool, 2 worker (honeypot + victim_atlas arka plan görevleri)

Beat schedule tüm modüller için burada tek noktada tanımlıdır.
"""

import os
from celery import Celery
from celery.schedules import crontab

RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672//")
TIMEZONE = os.getenv("CELERY_TIMEZONE", "UTC")

celery_app = Celery(
    "aegisnexus",
    broker=RABBITMQ_URL,
    backend="rpc://",
    include=[
        "modules.phishing_detector.celery_tasks",
        "modules.honeypot.celery_tasks",
        "modules.victim_atlas.celery_tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=TIMEZONE,
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=False,
    worker_max_tasks_per_child=50,
    task_time_limit=600,
    task_soft_time_limit=480,

    # ── Queue yönlendirme ────────────────────────────────────────────────
    task_default_queue="default",
    task_routes={
        "modules.phishing_detector.celery_tasks.run_heavy_analysis": {"queue": "phishing"},
    },

    # ── Beat schedule — Lokal tek kullanıcı için hafifletildi ────────────────
    # Eski: Saat başı / minutely çalışan devasa istihbarat çekimleri
    # Yeni: Günde 1 kez veya haftada 1 kez (Sistemi ve RAM'i şişirmemesi için)
    beat_schedule={

        # ── Honeypot / IOC ────────────────────────────────────────────────
        "ioc-refresh": {
            "task": "modules.honeypot.celery_tasks.update_ioc_feeds",
            "schedule": int(os.getenv("CELERY_IOC_INTERVAL_SECONDS", "86400")),  # 24 saat
            "options": {"queue": "default"},
        },
        "phishing-feed-refresh": {
            "task": "modules.honeypot.celery_tasks.update_phishing_feeds",
            "schedule": int(os.getenv("CELERY_PHISHING_INTERVAL_SECONDS", "86400")), # 24 saat
            "options": {"queue": "default"},
        },
        "refresh-ip-blacklists": {
            "task": "modules.honeypot.celery_tasks.refresh_ip_blacklists",
            "schedule": crontab(minute=0, hour=2, day_of_week=0), # Haftada 1 (Pazar 02:00)
            "options": {"queue": "default"},
        },
        "spamhaus-ioc-refresh": {
            "task": "modules.honeypot.celery_tasks.fetch_spamhaus_iocs",
            "schedule": crontab(minute=30, hour=3), # Günde 1 (03:30)
            "options": {"queue": "default"},
        },
        "threatfox-ioc-refresh": {
            "task": "modules.honeypot.celery_tasks.fetch_threatfox_iocs",
            "schedule": crontab(minute=0, hour=4), # Günde 1 (04:00)
            "options": {"queue": "default"},
        },

        # ── PhishTank DB sync ─────────────────────────────────────────────
        "phishtank-db-sync": {
            "task": "modules.phishing_detector.celery_tasks.sync_phishtank_db",
            "schedule": crontab(minute=0, hour=5, day_of_week=0), # Haftada 1 (Pazar 05:00)
            "options": {"queue": "default"},
        },

        # ── Victim Atlas ──────────────────────────────────────────────────
        "victim-atlas-ingest": {
            "task": "modules.victim_atlas.celery_tasks.ingest_6h",
            "schedule": int(os.getenv("VICTIM_ATLAS_INGEST_INTERVAL", "86400")), # 24 saat
            "options": {"queue": "default"},
        },
        "victim-atlas-classify-daily": {
            "task": "modules.victim_atlas.celery_tasks.classify_pending",
            "schedule": crontab(minute=15, hour=6), # Günde 1 (06:15)
            "options": {"queue": "default"},
        },
        "victim-atlas-prune-nightly": {
            "task": "modules.victim_atlas.celery_tasks.prune_hotset",
            "schedule": crontab(minute=10, hour=4),
            "options": {"queue": "default"},
        },
        "victim-atlas-weekly-digest": {
            "task": "modules.victim_atlas.celery_tasks.weekly_digest",
            "schedule": crontab(minute=0, hour=8, day_of_week=1),
            "options": {"queue": "default"},
        },
        "fraud-profile-stats-update": {
            "task": "modules.victim_atlas.celery_tasks.update_fraud_profile_stats",
            "schedule": crontab(minute=30, hour=7), # Günde 1 (07:30)
            "options": {"queue": "default"},
        },
    },
)
