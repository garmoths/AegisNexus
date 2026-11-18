"""
AegisNexus — Merkezi Celery Uygulaması
========================================
Tüm modüller bu tek Celery instance'ını kullanır.

Broker : Yerel Redis (run.sh tarafından yönetilir; CELERY_BROKER_URL)
Backend: Redis (CELERY_RESULT_BACKEND)
Cache  : Shared SQLite file (scan sonuçları, AI sayacı)
Jobs   : Shared SQLite file under data/ (API/worker polling)

Queue'lar:
  phishing  → prefork pool, 1 worker  (Playwright thread-safety gerektirir)
  default   → prefork pool, 2 worker (honeypot + rapor PDF görevleri)

Beat schedule tüm modüller için burada tek noktada tanımlıdır.
"""

from celery import Celery
from celery.schedules import crontab

from app.config import get_settings

_settings = get_settings()
BROKER_URL = _settings.celery_broker_url
RESULT_BACKEND = _settings.result_backend
TIMEZONE = _settings.celery_timezone

celery_app = Celery(
    "aegisnexus",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
    include=[
        "modules.phishing_detector.celery_tasks",
        "modules.honeypot.celery_tasks",
        "app.workflow_tasks",
        "app.discovery.tasks",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone=TIMEZONE,
    enable_utc=True,
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    broker_connection_retry_on_startup=True,
    broker_connection_timeout=3,
    task_publish_retry=False,
    broker_transport_options={'visibility_timeout': 900},
    result_expires=3600,
    worker_max_tasks_per_child=50,
    task_time_limit=600,
    task_soft_time_limit=480,

    # ── Queue yönlendirme ────────────────────────────────────────────────
    task_default_queue="default",
    task_routes={
        "app.discovery.tasks.tick": {"queue": "phishing"},
        "modules.phishing_detector.celery_tasks.run_heavy_analysis": {"queue": "phishing"},
    },

    # Feed intervals are configurable; the UI reports actual freshness.
    beat_schedule={
        "discovery-tick": {"task": "app.discovery.tasks.tick", "schedule": 10.0, "options": {"queue": "phishing"}},
        'outbox-delivery': {'task': 'app.workflow_tasks.deliver_outbox', 'schedule': 30.0},
        'watchlist-check': {'task': 'app.workflow_tasks.check_watchlist', 'schedule': 3600.0},

        # ── Honeypot / IOC ────────────────────────────────────────────────
        "ioc-refresh": {
            "task": "modules.honeypot.celery_tasks.update_ioc_feeds",
            "schedule": _settings.celery_ioc_interval_seconds,  # saatlik
            "options": {"queue": "default"},
        },
        "phishing-feed-refresh": {
            "task": "modules.honeypot.celery_tasks.update_phishing_feeds",
            "schedule": _settings.celery_phishing_interval_seconds, # 6 saatte bir
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
            "schedule": crontab(minute=0, hour="*/6"), # 6 saatte bir
            "options": {"queue": "default"},
        },

    },
)
