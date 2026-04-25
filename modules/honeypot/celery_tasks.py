import os
from datetime import datetime, timezone
from typing import Dict, List

from celery import Celery
from dotenv import load_dotenv

from app.database import SessionLocal
from app.models import IndicatorOfCompromise
from modules.phishing_detector.fetch_all_sources import fetch_all_sources

from .ioc_collector import AlienVaultOTXCollector, IOCCollectorEngine, IOCSource, IOCRecord

load_dotenv()

BROKER_URL = os.getenv("CELERY_BROKER_URL", "amqp://guest:guest@localhost:5672//")
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "rpc://")
TIMEZONE = os.getenv("CELERY_TIMEZONE", "UTC")

app = Celery(
    "aegis_threat_intel",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
)

app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone=TIMEZONE,
    enable_utc=True,
    beat_schedule={
        "ioc-refresh": {
            "task": "modules.honeypot.celery_tasks.update_ioc_feeds",
            "schedule": int(os.getenv("CELERY_IOC_INTERVAL_SECONDS", "3600")),
        },
        "phishing-refresh": {
            "task": "modules.honeypot.celery_tasks.update_phishing_feeds",
            "schedule": int(os.getenv("CELERY_PHISHING_INTERVAL_SECONDS", "7200")),
        },
    },
)


def _persist_iocs(db, iocs: List[IOCRecord]) -> Dict[str, int]:
    inserted = 0
    updated = 0

    for ioc in iocs:
        value_hash = ioc.get_value_hash()
        existing = db.query(IndicatorOfCompromise).filter(
            IndicatorOfCompromise.ioc_value_hash == value_hash
        ).first()

        if existing:
            existing.last_seen = datetime.now(timezone.utc)
            existing.detection_count = max(existing.detection_count + 1, ioc.detection_count)
            existing.risk_score = max(existing.risk_score, ioc.risk_score)
            existing.confidence = max(existing.confidence, ioc.confidence)
            existing.updated_at = datetime.now(timezone.utc)
            updated += 1
            continue

        db.add(
            IndicatorOfCompromise(
                ioc_type=ioc.ioc_type,
                ioc_value=ioc.ioc_value,
                ioc_value_hash=value_hash,
                source=ioc.source,
                threat_type=ioc.threat_type,
                threat_tags=ioc.threat_tags or [],
                risk_score=ioc.risk_score,
                confidence=ioc.confidence,
                first_seen=ioc.first_seen,
                last_seen=ioc.last_seen,
                detection_count=ioc.detection_count,
                context=ioc.context,
                ioc_metadata=ioc.ioc_metadata,
                source_reference=ioc.source_reference,
                status="active",
            )
        )
        inserted += 1

    return {"inserted": inserted, "updated": updated}


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.fetch_urlhaus")
def fetch_urlhaus(self, limit: int = 500):
    db = SessionLocal()
    try:
        collector = IOCCollectorEngine()
        iocs = collector.collect_all(include_sources=[IOCSource.URLHAUS.value], limit=limit)
        persisted = _persist_iocs(db, iocs)
        db.commit()
        return {"status": "success", "collected": len(iocs), **persisted}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.fetch_otx")
def fetch_otx(self, limit: int = 100):
    db = SessionLocal()
    try:
        collector = AlienVaultOTXCollector()
        iocs = collector.fetch_recent_pulses(limit=limit)
        persisted = _persist_iocs(db, iocs)
        db.commit()
        return {"status": "success", "collected": len(iocs), **persisted}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=60)
    finally:
        db.close()


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.update_ioc_feeds")
def update_ioc_feeds(self):
    db = SessionLocal()
    try:
        raw_sources = os.getenv("CELERY_IOC_SOURCES", "abuse_urlhaus,abuse_phishtank,abuseipdb")
        sources = [s.strip() for s in raw_sources.split(",") if s.strip()]
        per_source_limit = int(os.getenv("CELERY_IOC_LIMIT_PER_SOURCE", "1000"))

        collector = IOCCollectorEngine()
        iocs = collector.collect_all(include_sources=sources, limit=per_source_limit)
        persisted = _persist_iocs(db, iocs)
        db.commit()

        return {
            "status": "success",
            "sources": sources,
            "collected": len(iocs),
            **persisted,
        }
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=90)
    finally:
        db.close()


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.update_phishing_feeds")
def update_phishing_feeds(self):
    db = SessionLocal()
    try:
        result = fetch_all_sources(db)
        return {"status": "success", **result}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=120)
    finally:
        db.close()


@app.task(name="modules.honeypot.celery_tasks.run_ioc_fetch")
def run_ioc_fetch():
    """Backward compatible orchestrator for legacy worker invocations."""
    urlhaus_job = fetch_urlhaus.delay()
    otx_job = fetch_otx.delay()
    return {"status": "queued", "urlhaus_task_id": urlhaus_job.id, "otx_task_id": otx_job.id}
