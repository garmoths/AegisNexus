"""Honeypot / IOC business logic: persistence, statistics and search.

Routers stay thin (HTTP in, schema out); everything that touches the database
or the collector engines lives here so it can be tested without HTTP.
"""
from __future__ import annotations

import json
import logging
from datetime import UTC, date, datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.models import HoneypotEvent, IndicatorOfCompromise, PhishingURL

from .ioc_collector import IOCCollectorEngine, IOCRecord

logger = logging.getLogger(__name__)

RISK_BANDS: dict[str, tuple[int, int]] = {
    'critical': (95, 100),
    'high': (80, 94),
    'medium': (50, 79),
    'low': (1, 49),
}

# (label, min, max) — labels are shown as-is in the dashboard.
RISK_DISTRIBUTION = [
    ('Düşük (0-20)', 0, 20),
    ('Orta-Düşük (21-40)', 21, 40),
    ('Orta (41-60)', 41, 60),
    ('Orta-Yüksek (61-80)', 61, 80),
    ('Yüksek (81-100)', 81, 100),
]


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def client_ip(request: Request) -> str:
    """The peer address. X-Forwarded-For is not trusted: run uvicorn with
    ``--proxy-headers`` behind a reverse proxy instead of letting clients spoof it."""
    return request.client.host if request.client else 'unknown'


def record_event(db: Session, request: Request, path: str, note: str) -> None:
    db.add(HoneypotEvent(
        client_ip=client_ip(request),
        user_agent=request.headers.get('user-agent', '')[:500],
        path=path,
        referer=request.headers.get('referer', '')[:500] or None,
        note=note,
    ))
    db.commit()


def collect_note(source: str, count: int, tags: list[str]) -> str:
    return json.dumps({'source': source, 'ioc_count': count, 'tags': tags}, ensure_ascii=True)


# ── External IOC collection ───────────────────────────────────────────────

def persist_external_iocs(db: Session, engine: IOCCollectorEngine, iocs: list[IOCRecord]) -> int:
    """Cache IOCs in the collector, upsert them into the database and publish events."""
    stored = 0
    for ioc in iocs:
        engine.store_ioc(ioc)
        value_hash = ioc.get_value_hash()
        existing = db.query(IndicatorOfCompromise).filter_by(ioc_value_hash=value_hash).first()
        if existing is not None:
            existing.last_seen = ioc.last_seen
            existing.detection_count = (existing.detection_count or 0) + 1
            existing.risk_score = max(existing.risk_score, ioc.risk_score)
            continue
        db.add(IndicatorOfCompromise(
            ioc_type=ioc.ioc_type, ioc_value=ioc.ioc_value, ioc_value_hash=value_hash,
            source=ioc.source, threat_type=ioc.threat_type, threat_tags=ioc.threat_tags or [],
            risk_score=ioc.risk_score, confidence=ioc.confidence,
            first_seen=ioc.first_seen, last_seen=ioc.last_seen, detection_count=ioc.detection_count,
            context=ioc.context, ioc_metadata=ioc.ioc_metadata, source_reference=ioc.source_reference,
            status='active',
        ))
        stored += 1
    db.commit()

    try:
        from modules.shared.events import publish
        created_at = datetime.now(UTC).isoformat()
        for ioc in iocs:
            publish('honeypot.ioc_collected', {
                'ioc_type': ioc.ioc_type, 'value': ioc.ioc_value, 'risk_score': ioc.risk_score,
                'source': ioc.source or 'honeypot', 'created_at': created_at,
            }, durable=True)
    except Exception:
        logger.warning('Publishing honeypot.ioc_collected events failed (non-critical)', exc_info=True)
    return stored


def filtered_collected(engine: IOCCollectorEngine, *, ioc_type: str | None, threat_type: str | None,
                       min_risk_score: int, source: str | None) -> list[IOCRecord]:
    filters: dict[str, Any] = {}
    if ioc_type:
        filters['ioc_type'] = ioc_type
    if threat_type:
        filters['threat_type'] = threat_type
    if min_risk_score > 0:
        filters['min_risk_score'] = min_risk_score
    if source:
        filters['source'] = source
    return engine.list_iocs(filters=filters)


def stats_insights(stats: dict[str, Any]) -> dict[str, float]:
    total = max(1, stats.get('total_iocs', 0))
    return {
        'high_risk_percentage': round(stats.get('high_risk_count', 0) / total * 100, 2),
        'critical_percentage': round(stats.get('critical_count', 0) / total * 100, 2),
        'average_risk_score': round(stats.get('average_risk_score', 0), 2),
    }


# ── Database queries ──────────────────────────────────────────────────────

def search_iocs(db: Session, query: str, limit: int = 50) -> list[dict[str, Any]]:
    escaped = query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    rows = (db.query(IndicatorOfCompromise)
            .filter(IndicatorOfCompromise.ioc_value.ilike(f'%{escaped}%', escape='\\'))
            .limit(limit).all())
    return [{
        'id': r.id, 'type': r.ioc_type, 'value': r.ioc_value, 'threat_type': r.threat_type,
        'risk_score': r.risk_score, 'source': r.source, 'detection_count': r.detection_count,
        'first_seen': _iso(r.first_seen), 'last_seen': _iso(r.last_seen),
    } for r in rows]


def iocs_in_band(db: Session, level: str, limit: int) -> list[dict[str, Any]]:
    low, high = RISK_BANDS[level]
    rows = (db.query(IndicatorOfCompromise)
            .filter(IndicatorOfCompromise.risk_score >= low, IndicatorOfCompromise.risk_score <= high)
            .order_by(IndicatorOfCompromise.risk_score.desc()).limit(limit).all())
    return [{
        'value': r.ioc_value, 'type': r.ioc_type, 'threat_type': r.threat_type, 'risk_score': r.risk_score,
        'confidence': r.confidence, 'source': r.source, 'detection_count': r.detection_count,
    } for r in rows]


def _daily_counts(db: Session, column, days: int) -> dict[str, int]:
    """Counts per calendar day (UTC) for the last ``days`` days, in one GROUP BY.

    ``func.date`` is used on purpose: on SQLite ``CAST(x AS DATE)`` yields only the year.
    """
    since = _utcnow().date() - timedelta(days=days)
    day = func.date(column)
    rows = db.query(day, func.count()).filter(column >= datetime.combine(since, datetime.min.time())).group_by(day).all()
    return {str(d): c for d, c in rows}


def _top(db: Session, column, limit: int) -> list[tuple[Any, int]]:
    count = func.count().label('count')
    return db.query(column, count).filter(column.isnot(None)).group_by(column).order_by(desc('count')).limit(limit).all()


def ioc_statistics(db: Session) -> dict[str, Any]:
    total = db.query(func.count(IndicatorOfCompromise.id)).scalar() or 0
    today: date = _utcnow().date()
    per_day = _daily_counts(db, IndicatorOfCompromise.created_at, 7)
    weekly = [{'date': (today - timedelta(days=i)).isoformat(), 'count': per_day.get((today - timedelta(days=i)).isoformat(), 0)}
              for i in range(7, -1, -1)]

    distribution = []
    for label, low, high in RISK_DISTRIBUTION:
        count = db.query(func.count(IndicatorOfCompromise.id)).filter(
            IndicatorOfCompromise.risk_score >= low, IndicatorOfCompromise.risk_score <= high).scalar() or 0
        distribution.append({'range': label, 'count': count, 'percentage': round(count / total * 100, 2) if total else 0})

    high_risk = sum(b['count'] for b in distribution if 'Yüksek' in b['range'])
    medium_risk = sum(b['count'] for b in distribution if 'Orta' in b['range'] and 'Yüksek' not in b['range'])
    low_risk = sum(b['count'] for b in distribution if 'Düşük' in b['range'])
    now = _utcnow().isoformat()
    return {
        'stats': {'total_iocs': total, 'high_risk_count': high_risk, 'medium_risk_count': medium_risk,
                  'low_risk_count': low_risk, 'last_update': now},
        'total_records': total,
        'today_added': per_day.get(today.isoformat(), 0),
        'weekly_growth': weekly,
        'risk_distribution': distribution,
        'top_threats': [{'type': t, 'count': c} for t, c in _top(db, IndicatorOfCompromise.threat_type, 10)],
        'source_breakdown': [{'source': s, 'count': c} for s, c in _top(db, IndicatorOfCompromise.source, 10)],
        'last_updated': now,
    }


def phishing_statistics(db: Session) -> dict[str, Any]:
    total = db.query(func.count(PhishingURL.id)).scalar() or 0
    today = _utcnow().date().isoformat()
    daily_new = _daily_counts(db, PhishingURL.submission_time, 0).get(today, 0)
    recent = db.query(PhishingURL).order_by(desc(PhishingURL.submission_time)).limit(20).all()
    now = _utcnow().isoformat()
    return {
        'stats': {'total_urls': total, 'daily_new': daily_new, 'last_update': now},
        'total_urls': total,
        'daily_new': daily_new,
        'top_domains': [{'domain': d, 'count': c} for d, c in _top(db, PhishingURL.domain_norm, 20)],
        'recent_urls': [{
            'url': (r.url[:80] + '...') if r.url and len(r.url) > 80 else r.url,
            'domain': r.domain_norm, 'target': r.target, 'status': r.status, 'time': _iso(r.submission_time),
        } for r in recent],
        'threat_categories': [{'category': t, 'count': c} for t, c in _top(db, PhishingURL.target, 15)],
        'last_updated': now,
    }
