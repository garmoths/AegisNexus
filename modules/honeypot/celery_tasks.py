import logging
import os
from datetime import datetime, timezone
from typing import Dict, List

from app.celery_app import celery_app as app
from app.database import SessionLocal
from app.models import IndicatorOfCompromise
from modules.phishing_detector.fetch_all_sources import fetch_all_sources

from .ioc_collector import AlienVaultOTXCollector, IOCCollectorEngine, IOCSource, IOCRecord

logger = logging.getLogger(__name__)


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
        raw_sources = os.getenv("CELERY_IOC_SOURCES", "abuse_urlhaus,abuse_phishtank")
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


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.fetch_spamhaus_iocs")
def fetch_spamhaus_iocs(self):
    """Spamhaus Intel API'den XBL/CBL/DBL listelerini çekip IOC tablosuna yaz."""
    db = SessionLocal()
    try:
        from modules.phishing_detector.spamhaus_client import query_ip, query_domain
        from modules.phishing_detector.cache_db import read_threat_cache, write_threat_cache

        # Son 6 saatte taranan yüksek riskli domain'leri Spamhaus'ta sorgula
        from app.models import PhishingURL
        from modules.phishing_detector.cache_db import get_latest_phishing
        recent_phishing = get_latest_phishing(limit=200)

        inserted = 0
        updated = 0
        seen_domains = set()
        for url_record in recent_phishing:
            domain = url_record.get("domain", "")
            if not domain or domain in seen_domains:
                continue
            seen_domains.add(domain)

            # Domain sorgula
            cache_key = f"spamhaus:domain:{domain}"
            cached = read_threat_cache(cache_key)
            if not cached:
                result = query_domain(domain)
                if result.get("listed"):
                    existing = db.query(IndicatorOfCompromise).filter(
                        IndicatorOfCompromise.ioc_value == domain,
                        IndicatorOfCompromise.source == "spamhaus_dbl",
                    ).first()
                    if existing:
                        existing.last_seen = datetime.now(timezone.utc)
                        existing.detection_count += 1
                        existing.updated_at = datetime.now(timezone.utc)
                        updated += 1
                    else:
                        db.add(IndicatorOfCompromise(
                            ioc_type="domain",
                            ioc_value=domain,
                            ioc_value_hash=str(hash(domain)),
                            source="spamhaus_dbl",
                            threat_type="spam",
                            risk_score=85,
                            confidence=95,
                            first_seen=datetime.now(timezone.utc),
                            last_seen=datetime.now(timezone.utc),
                            detection_count=1,
                            status="active",
                        ))
                        inserted += 1

        db.commit()
        return {"status": "success", "spamhaus_inserted": inserted, "spamhaus_updated": updated}
    except Exception as exc:
        db.rollback()
        raise self.retry(exc=exc, countdown=120)
    finally:
        db.close()


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.fetch_threatfox_iocs")
def fetch_threatfox_iocs(self):
    """ThreatFox API'den son IOC'ları çekip IOC tablosuna yaz."""
    db = SessionLocal()
    try:
        from modules.phishing_detector.threatfox_client import get_recent_iocs
        limit = int(os.getenv("PHISHING_THREATFOX_LIMIT", "500"))
        iocs = get_recent_iocs(limit=limit)

        inserted = 0
        updated = 0
        for ioc in iocs:
            ioc_value = ioc.get("url", "")
            ioc_type = ioc.get("ioc_type", "domain")
            threat_type = ioc.get("threat_type", "phishing")
            malware = ioc.get("malware_family", "Unknown")
            confidence = ioc.get("confidence", 50)

            if not ioc_value:
                continue

            value_hash = str(hash(ioc_value))
            try:
                existing = db.query(IndicatorOfCompromise).filter(
                    IndicatorOfCompromise.ioc_value_hash == value_hash,
                    IndicatorOfCompromise.source == "threatfox",
                ).first()

                if existing:
                    existing.last_seen = datetime.now(timezone.utc)
                    existing.detection_count += 1
                    existing.risk_score = max(existing.risk_score, confidence)
                    existing.updated_at = datetime.now(timezone.utc)
                    updated += 1
                else:
                    db.add(IndicatorOfCompromise(
                        ioc_type=ioc_type,
                        ioc_value=ioc_value,
                        ioc_value_hash=value_hash,
                        source="threatfox",
                        threat_type=threat_type,
                        threat_tags=[malware] if malware else [],
                        risk_score=confidence,
                        confidence=confidence,
                        first_seen=datetime.now(timezone.utc),
                        last_seen=datetime.now(timezone.utc),
                        detection_count=1,
                        context={"malware_family": malware},
                        status="active",
                    ))
                    inserted += 1
                db.commit()
            except Exception:
                db.rollback()
                continue

        return {"status": "success", "threatfox_collected": len(iocs), "threatfox_inserted": inserted, "threatfox_updated": updated}
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
    threatfox_job = fetch_threatfox_iocs.delay()
    spamhaus_job = fetch_spamhaus_iocs.delay()
    return {"status": "queued", "urlhaus_task_id": urlhaus_job.id, "otx_task_id": otx_job.id, "threatfox_task_id": threatfox_job.id, "spamhaus_task_id": spamhaus_job.id}


@app.task(bind=True, max_retries=3, name="modules.honeypot.celery_tasks.refresh_ip_blacklists")
def refresh_ip_blacklists(self):
    """Celery beat ile günde 1 kez çalıştır - IP blacklist'leri güncelle"""
    try:
        import os
        import requests
        
        SAVE_DIR = "/opt/phishing/ip_lists"
        os.makedirs(SAVE_DIR, exist_ok=True)

        feeds = {
            "firehol_level1.netset": "https://iplists.firehol.org/files/firehol_level1.netset",
            "spamhaus_drop.txt":     "https://www.spamhaus.org/drop/drop.txt",
            "spamhaus_edrop.txt":    "https://www.spamhaus.org/drop/edrop.txt",
            "emerging_threats.txt":  "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        }

        for filename, feed_url in feeds.items():
            try:
                r = requests.get(feed_url, timeout=30)
                r.raise_for_status()
                with open(f"{SAVE_DIR}/{filename}", 'w') as f:
                    f.write(r.text)
                logger.info(f"Downloaded {filename}")
            except Exception as e:
                logger.error(f"Failed to download {filename}: {e}")

        # Memory'i de güncelle
        from modules.phishing_detector.threat_intel_local import load_ip_blacklists
        count = load_ip_blacklists(SAVE_DIR)
        logger.info(f"Loaded {count} IP/CIDR to memory")
        return f"{count} IP/CIDR loaded"
    except Exception as exc:
        logger.error(f"IP blacklist refresh failed: {exc}")
        raise self.retry(exc=exc, countdown=300)
