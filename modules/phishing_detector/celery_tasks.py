"""
A2 — Phishing Detector Celery Async Pipeline
==============================================
Ağır analizi (Playwright + Gemini + threat intel) asenkron kuyruğa taşır.
Broker: Redis DB-1 (mevcut Redis, AMQP gerekmez).

Worker başlatmak için:
    celery -A modules.phishing_detector.celery_tasks.app worker \
           -Q phishing -c 2 --loglevel=info

Monitoring:
    celery -A modules.phishing_detector.celery_tasks.app flower
"""

from __future__ import annotations

import json
import logging
import os

from celery import Celery
from celery.signals import worker_process_init, worker_process_shutdown

from .redis_cache import redis_set_scan
from .url_normalize import normalize_url_record

logger = logging.getLogger(__name__)

# ── Celery app — Redis broker, DB-1 (cache DB-0 ile çakışmaz) ────────────
_BROKER = os.getenv("PHISHING_CELERY_BROKER", "redis://127.0.0.1:6379/1")
_BACKEND = os.getenv("PHISHING_CELERY_BACKEND", "redis://127.0.0.1:6379/1")

app = Celery("aegis_phishing", broker=_BROKER, backend=_BACKEND)

app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_soft_time_limit=240,   # 4 dk soft limit
    task_time_limit=270,        # 4.5 dk hard limit
    worker_max_tasks_per_child=50,  # Memory leak'e karşı
    task_acks_late=True,        # Hata durumunda yeniden kuyruğa alınır
)

# Job sonuçları Redis'te bu TTL ile saklanır (1 saat)
_JOB_TTL = int(os.getenv("PHISHING_JOB_TTL", "3600"))

# ── A3: Worker process sinyalleri — Playwright pool ───────────────────────


@worker_process_init.connect
def _init_playwright_pool(**kwargs):
    """Worker process başladığında Playwright browser'ı pre-warm et."""
    try:
        from .playwright_pool import init_pool
        init_pool()
        logger.info("[A3] Playwright pool hazır (worker process init)")
    except Exception as exc:
        logger.warning(f"[A3] Playwright pool init başarısız (lazy init devreye girer): {exc}")


@worker_process_shutdown.connect
def _close_playwright_pool(**kwargs):
    """Worker process kapanırken Playwright browser'ı temiz kapat."""
    try:
        from .playwright_pool import close_pool
        close_pool()
        logger.info("[A3] Playwright pool kapatıldı (worker process shutdown)")
    except Exception as exc:
        logger.warning(f"[A3] Playwright pool close hatası: {exc}")


def _get_redis():
    """Raw redis bağlantısı — job:{job_id} yazımı için."""
    import redis as _redis
    return _redis.Redis(
        host=os.getenv("REDIS_HOST", "127.0.0.1"),
        port=int(os.getenv("REDIS_PORT", "6379")),
        db=1,
        decode_responses=True,
        socket_connect_timeout=2,
        socket_timeout=2,
    )


@app.task(
    bind=True,
    max_retries=2,
    name="modules.phishing_detector.celery_tasks.run_heavy_analysis",
)
def run_heavy_analysis(self, url: str, job_id: str):
    """
    Playwright screenshot + Gemini + paralel threat intel + HTML derin analizi.
    Sonuç Redis'e `job:{job_id}` ve `scan:{url_hash}` olarak yazılır.
    """
    from app.database import SessionLocal
    from .scanner import calculate_safety_score

    db = SessionLocal()
    try:
        logger.info(f"[Celery] Ağır analiz başladı: {url} (job={job_id})")
        result = calculate_safety_score(url, db)
        result["job_id"] = job_id
        result["status"] = "complete"
        result["module"] = "01_phishing_detector"

        # 1. job:{job_id} → polling için (TTL: 1 saat)
        r = _get_redis()
        r.setex(f"job:{job_id}", _JOB_TTL, json.dumps(result, default=str))

        # 2. scan:{url_hash} → sonraki istekler için kalıcı cache
        norm = normalize_url_record(url)
        url_hash = norm.get("url_hash", "")
        if url_hash:
            redis_set_scan(url_hash, result)

        logger.info(f"[Celery] Analiz tamamlandı: {url} (job={job_id})")
        return result

    except Exception as exc:
        logger.error(f"[Celery] Analiz hatası {url}: {exc}")
        try:
            r = _get_redis()
            r.setex(
                f"job:{job_id}",
                _JOB_TTL,
                json.dumps({"status": "error", "job_id": job_id, "error": str(exc)}, default=str),
            )
        except Exception:
            pass
        raise self.retry(exc=exc, countdown=10)
    finally:
        db.close()
