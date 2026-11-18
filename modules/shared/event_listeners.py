"""
modules/shared/event_listeners.py — Tüm event subscriber'larını kaydet.

app/main.py lifespan'ında register_event_listeners() çağrılır.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict

logger = logging.getLogger("aegis.event_listeners")


# ─────────────────────────────────────────────
# SUBSCRIBER: url.phishing_confirmed
# Publisher: ai_analyzer/router.py
# Action: PhishingURL tablosuna ekle
# ─────────────────────────────────────────────

def _on_url_phishing_confirmed(payload: Dict[str, Any]) -> None:
    url = payload.get("url", "")
    score = payload.get("score", 0)
    if not url:
        return
    try:
        from shared.utils.db import SessionLocal
        from app.models import PhishingURL

        db = SessionLocal()
        try:
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            existing = db.query(PhishingURL).filter_by(url_hash=url_hash).first()
            if not existing:
                entry = PhishingURL(
                    url=url[:2000],
                    url_hash=url_hash,
                    phish_id=f"ai-{url_hash[:16]}",
                    status="active",
                    online=True,
                    target="unknown",
                    submission_time=datetime.now(timezone.utc),
                )
                db.add(entry)
            db.commit()
            logger.info(f"[EventBus] url.phishing_confirmed persisted: {url[:60]}")
        finally:
            db.close()
    except Exception as exc:
        logger.error(f"[EventBus] _on_url_phishing_confirmed error: {exc}", exc_info=True)
        raise


# ─────────────────────────────────────────────
# SUBSCRIBER: honeypot.ioc_collected
# Publisher: honeypot/ioc_api.py
# Action: IndicatorOfCompromise blacklist güncellemesi
# ─────────────────────────────────────────────

def _on_honeypot_ioc_collected(payload: Dict[str, Any]) -> None:
    ioc_value = payload.get("value", "")
    ioc_type = payload.get("ioc_type", "url")
    risk_score = payload.get("risk_score", 75)
    source = payload.get("source", "honeypot")
    if not ioc_value:
        return
    try:
        from shared.utils.db import SessionLocal
        from app.models import IndicatorOfCompromise

        db = SessionLocal()
        try:
            val_hash = hashlib.sha256(ioc_value.encode()).hexdigest()
            existing = (
                db.query(IndicatorOfCompromise)
                .filter_by(ioc_value_hash=val_hash)
                .first()
            )
            if existing:
                existing.detection_count = (existing.detection_count or 0) + 1
                existing.last_seen = datetime.now(timezone.utc)
                existing.risk_score = max(existing.risk_score or 0, risk_score)
            else:
                entry = IndicatorOfCompromise(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value[:1000],
                    ioc_value_hash=val_hash,
                    source=source,
                    threat_type="phishing",
                    risk_score=min(int(risk_score), 100),
                    confidence=0.85,
                    first_seen=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    detection_count=1,
                    status="active",
                )
                db.add(entry)
            db.commit()
            logger.info(f"[EventBus] honeypot.ioc_collected persisted: {ioc_type}={ioc_value[:40]}")
        finally:
            db.close()
    except Exception as exc:
        logger.error(f"[EventBus] _on_honeypot_ioc_collected error: {exc}", exc_info=True)
        raise


# ─────────────────────────────────────────────
# KAYIT
# ─────────────────────────────────────────────

def register_event_listeners() -> None:
    """Tüm subscriber'ları event bus'a kaydet. app/main.py lifespan'ında çağrılır."""
    from modules.shared.events import subscribe

    subscribe("report.pdf_requested", _on_pdf_requested)
    subscribe("url.phishing_confirmed", _on_url_phishing_confirmed)
    subscribe("honeypot.ioc_collected", _on_honeypot_ioc_collected)

    logger.info("[EventBus] Tüm event listener'lar kayıt edildi")


def _on_pdf_requested(payload):
    from app.workflow_tasks import generate_report_pdf
    generate_report_pdf.run(payload['report_id'])

