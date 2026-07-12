"""
A2 — Phishing Detector Celery Async Pipeline
==============================================
Ağır analizi (Playwright + Gemini + threat intel) asenkron kuyruğa taşır.
Broker: RabbitMQ (app.celery_app üzerinden, RABBITMQ_URL env var).

Worker başlatmak için (systemd servisi tercih edilir):
    celery -A app.celery_app:celery_app worker -Q phishing -P solo -c 1 --loglevel=info

Monitoring:
    celery -A app.celery_app:celery_app flower
"""

from __future__ import annotations

import json
import logging
import os

from celery.signals import worker_process_init, worker_process_shutdown
from billiard.exceptions import SoftTimeLimitExceeded

from app.celery_app import celery_app as app
from .redis_cache import redis_set_scan
from .cache_db import set_celery_job
from .url_normalize import normalize_url_record

logger = logging.getLogger(__name__)

# Job sonuçları SQLite'ta bu TTL ile saklanır (1 saat)
_JOB_TTL = int(os.getenv("PHISHING_JOB_TTL", "3600"))

# ── A3: Worker process sinyalleri — Playwright pool ───────────────────────


@worker_process_init.connect
def _preload_worker_models(**kwargs):
    """Worker process başladığında tüm ağır modelleri preload et.

    SADECE phishing worker'da çalışır (CELERY_WORKER_TYPE=phishing).
    Default worker Playwright başlatmamalı — gereksiz RAM israfı.
    """
    if os.getenv("CELERY_WORKER_TYPE") != "phishing":
        return

    # 1. Playwright pool pre-warm
    try:
        from .playwright_pool import init_pool
        init_pool()
        logger.info("[A3] Playwright pool hazır (worker process init)")
    except Exception as exc:
        logger.warning(f"[A3] Playwright pool init başarısız (lazy init devreye girer): {exc}")

    # 2. EasyOCR + IP blacklist preload
    try:
        from .threat_intel_local import preload_models
        result = preload_models()
        logger.info(f"[A1] Preload modeller tamam: OCR={result['ocr_loaded']}, IP={result['ip_loaded']}, PW={result['playwright_loaded']}")
    except Exception as exc:
        logger.warning(f"[A1] Preload modeller başarısız (lazy init devreye girer): {exc}")


@worker_process_shutdown.connect
def _close_playwright_pool(**kwargs):
    """Worker process kapanırken Playwright browser'ı temiz kapat."""
    if os.getenv("CELERY_WORKER_TYPE") != "phishing":
        return
    try:
        from .playwright_pool import close_pool
        close_pool()
        logger.info("[A3] Playwright pool kapatıldı (worker process shutdown)")
    except Exception as exc:
        logger.warning(f"[A3] Playwright pool close hatası: {exc}")


def _get_redis():
    """Kaldırıldı — Redis yok. Geriye uyumluluk için no-op stub."""
    return None


@app.task(
    name="modules.phishing_detector.celery_tasks.sync_phishtank_db",
    max_retries=1,
)
def sync_phishtank_db():
    """PhishTank JSON DB'sini 12 saatte bir indir, PostgreSQL'e işle, dosya bırakma.

    Akış:
      1. HEAD isteğiyle ETag kontrol — değişmemişse hiç indirme yok.
      2. bz2 JSON indir (key varsa limitsiz, yoksa günlük birkaç kez izinli).
      3. URL'leri phishing_urls tablosuna import et.
      4. scanner.PHISHTANK_DB set'ini sıcak güncelle.
      Son indirilen ETag Redis'te saklanır (db=1, key=phishtank:etag).
    """
    import bz2
    import requests

    app_key = os.getenv("PHISHTANK_APP_KEY", "")
    pt_username = os.getenv("PHISHTANK_USERNAME", "aegisnexus")
    headers = {"User-Agent": f"phishtank/{pt_username}"}

    if app_key:
        url = f"http://data.phishtank.com/data/{app_key}/online-valid.json.bz2"
    else:
        url = "http://data.phishtank.com/data/online-valid.json.bz2"

    # ── 1. ETag kontrolü (SQLite threat_intel_cache — Redis yok) ────────────
    from .cache_db import read_threat_cache, write_threat_cache
    cached_etag_entry = read_threat_cache("phishtank:etag")
    cached_etag = cached_etag_entry.get("etag", "") if cached_etag_entry else ""

    try:
        head = requests.head(url, headers=headers, timeout=15)
        current_etag = head.headers.get("ETag", "")
    except Exception as exc:
        logger.warning(f"[PhishTank] HEAD isteği başarısız, devam ediliyor: {exc}")
        current_etag = ""

    if current_etag and current_etag == cached_etag:
        logger.info("[PhishTank] ETag değişmemiş, indirme atlandı.")
        return {"status": "skipped", "reason": "etag_unchanged"}

    # ── 2. bz2 indir ─────────────────────────────────────────────────────────
    try:
        resp = requests.get(url, headers=headers, timeout=120)
        resp.raise_for_status()
        raw = bz2.decompress(resp.content)
        data = __import__("json").loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.error(f"[PhishTank] İndirme/ayrıştırma hatası: {exc}")
        return {"status": "error", "error": str(exc)}

    if not isinstance(data, list) or not data:
        logger.warning("[PhishTank] Boş veya geçersiz JSON döndü.")
        return {"status": "error", "error": "empty_response"}

    # ── 3. DB import ──────────────────────────────────────────────────────────
    from app.database import SessionLocal
    from .fetch_all_sources import convert_to_phishtank_format, import_to_database

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()
    entries = [
        {
            "url": item.get("url", ""),
            "phish_id": item.get("phish_id"),
            "target": item.get("target", ""),
            "submission_time": item.get("submission_time", now),
            "verified": item.get("verified", "yes"),
            "online": item.get("online", "yes"),
            "status": "valid",
        }
        for item in data
        if item.get("url")
    ]

    db = SessionLocal()
    try:
        result = import_to_database(db, entries)
    finally:
        db.close()

    # ── 4. scanner.PHISHTANK_DB sıcak güncelle ───────────────────────────────
    try:
        from . import scanner as _scanner
        for e in entries:
            u = e["url"]
            domain = u.replace("https://", "").replace("http://", "").replace("www.", "").split("/")[0]
            _scanner.PHISHTANK_DB.add(domain)
        logger.info(f"[PhishTank] PHISHTANK_DB güncellendi: {len(_scanner.PHISHTANK_DB)} domain")
    except Exception as exc:
        logger.warning(f"[PhishTank] In-memory set güncelleme hatası: {exc}")

    # ── 5. ETag kaydet (SQLite — 2 gün TTL) ──────────────────────────────────
    if current_etag:
        try:
            write_threat_cache("phishtank:etag", {"etag": current_etag}, ttl_seconds=86400 * 2)
        except Exception:
            pass

    total = len(entries)
    added = result.get("added", 0)
    logger.info(f"[PhishTank] Sync tamamlandı: {total} URL işlendi, {added} yeni eklendi.")
    return {"status": "ok", "total": total, "added": added, "updated": result.get("updated", 0)}


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

        # 1. job:{job_id} → polling için (TTL: 1 saat, SQLite cross-process)
        set_celery_job(f"job:{job_id}", result, ttl_seconds=_JOB_TTL)

        # 2. scan:{url_hash} → sonraki istekler için kalıcı cache (in-memory, process-local)
        norm = normalize_url_record(url)
        url_hash = norm.get("url_hash", "")
        if url_hash:
            redis_set_scan(url_hash, result)

        logger.info(f"[Celery] Analiz tamamlandı: {url} (job={job_id})")
        return result

    except SoftTimeLimitExceeded as exc:
        logger.error(f"[Celery] Soft time limit aşıldı: {url} (job={job_id}) - {exc}")
        timeout_payload = {
            "status": "timeout",
            "job_id": job_id,
            "url": url,
            "risk_level": "unknown",
            "module": "01_phishing_detector",
            "error": "soft_time_limit_exceeded",
        }
        try:
            set_celery_job(f"job:{job_id}", timeout_payload, ttl_seconds=_JOB_TTL)
        except Exception as job_exc:
            logger.error(f"[Celery] Timeout sonucu yazılamadı (job={job_id}): {job_exc}")
        return timeout_payload
    except Exception as exc:
        logger.error(f"[Celery] Analiz hatası {url}: {exc}")
        try:
            set_celery_job(
                f"job:{job_id}",
                {"status": "error", "job_id": job_id, "error": str(exc)},
                ttl_seconds=_JOB_TTL,
            )
        except Exception as job_exc:
            logger.error(f"[Celery] Hata sonucu yazılamadı (job={job_id}): {job_exc}")
        raise self.retry(exc=exc, countdown=10)
    finally:
        db.close()
