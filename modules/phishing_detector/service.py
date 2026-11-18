"""Phishing detector use cases: URL scans and their job lifecycle, the threat
database and per-user scan history. Routers translate HTTP to these calls."""
from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app import runtime_store as store
from app.errors import Conflict, ServiceUnavailable, Unprocessable
from app.models import APIKey, PhishingURL, PrivateScan
from app.outbound import UnsafeTarget, validate_url

from .cache_db import get_celery_job, get_phishing_stats, persist_scan_result, set_celery_job
from .redis_cache import redis_get_scan, redis_invalidate_scan, redis_set_scan
from .scanner import run_quick_checks
from .url_normalize import normalize_url_record

logger = logging.getLogger(__name__)

MODULE = '01_phishing_detector'
ACTIVE_JOB_STATES = ('queued', 'running', 'retrying')
SCORE_VERSION = 2
JOB_LEASE_SECONDS = 900
JOB_DEADLINE = timedelta(minutes=15)


def _utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


# ── URL scans ─────────────────────────────────────────────────────────────

def record_private_scan(db: Session, api_key: APIKey | None, url: str, result: dict[str, Any], job_id: str | None = None) -> None:
    """Add the scan to the caller's own history (anonymous scans are not stored per user)."""
    if not isinstance(api_key, APIKey):
        return
    job_id = job_id or str(uuid.uuid4())
    if db.query(PrivateScan).filter_by(user_id=api_key.user_id, job_id=job_id).first():
        return
    risk = int(result.get('risk_score', 100 - int(result.get('safety_score', result.get('score', 50)))))
    db.add(PrivateScan(user_id=api_key.user_id, job_id=job_id, url=url, risk_score=risk,
                       risk_level=str(result.get('risk_level', 'unknown'))))
    db.commit()


def start_scan(db: Session, api_key: APIKey | None, url: str, force_fresh: bool = False) -> dict[str, Any]:
    """Return a cached or quick verdict, or enqueue the full (browser + threat-intel) analysis.

    The response is either ``status='complete'`` with a verdict, or
    ``status='analyzing'`` with a ``job_id`` to poll via :func:`job_status`.
    One job per URL runs at a time; concurrent callers share it.
    """
    try:
        requested_url, _, _, _ = validate_url(url, resolve=False)
    except UnsafeTarget as exc:
        raise Unprocessable(str(exc), code='unsafe_target') from exc
    url_hash = normalize_url_record(requested_url).get('url_hash', '')

    if force_fresh:
        redis_invalidate_scan(url_hash)
    else:
        cached = redis_get_scan(url_hash)
        if cached and cached.get('score_version') == SCORE_VERSION:
            cached['cache'] = 'shared-hit'
            record_private_scan(db, api_key, requested_url, cached)
            return cached

    quick = run_quick_checks(requested_url, db)
    if quick.get('definitive'):
        quick.update(status='complete', module=MODULE)
        if not persist_scan_result(requested_url, quick):
            raise ServiceUnavailable('Tarama sonucu kaydedilemedi.')
        redis_set_scan(url_hash, quick)
        record_private_scan(db, api_key, requested_url, quick)
        return quick

    lease = 'analyzing:' + url_hash
    existing = store.get(lease)
    if existing:
        state = job_status(db, None, existing)
        if state.get('status') in ACTIVE_JOB_STATES:
            return {**quick, 'status': 'analyzing', 'job_state': state['status'], 'job_id': existing}
        store.delete(lease)

    job_id = str(uuid.uuid4())
    # The lease covers queue wait plus the hard task deadline, not just browser time.
    if not store.claim(lease, job_id, JOB_LEASE_SECONDS):
        return {**quick, 'status': 'analyzing', 'job_id': store.get(lease)}
    now = _utcnow()
    if not set_celery_job('job:' + job_id, {'status': 'queued', 'job_id': job_id, 'url': requested_url,
                                            'updated_at': now.isoformat(), 'deadline': (now + JOB_DEADLINE).isoformat()}):
        store.delete(lease)
        raise ServiceUnavailable('İş kaydedilemedi.')
    try:
        from .celery_tasks import run_heavy_analysis
        run_heavy_analysis.apply_async((requested_url, job_id), queue='phishing', task_id=job_id,
                                       expires=JOB_LEASE_SECONDS, retry=False)
    except Exception as exc:
        store.delete(lease)
        set_celery_job('job:' + job_id, {'status': 'failed', 'job_id': job_id, 'error': 'queue_unavailable'})
        # Never fall back to an unbounded scan inside the request.
        raise ServiceUnavailable('Analiz kuyruğu kullanılamıyor. Lütfen daha sonra tekrar deneyin.', code='queue_unavailable') from exc
    return {**quick, 'status': 'analyzing', 'job_state': 'queued', 'job_id': job_id, 'module': MODULE}


def job_status(db: Session, api_key: APIKey | None, job_id: str) -> dict[str, Any]:
    try:
        uuid.UUID(job_id)
    except ValueError as exc:
        raise Unprocessable('Geçersiz iş kimliği.', code='invalid_job_id') from exc
    result = get_celery_job('job:' + job_id)
    if result is None:
        return {'status': 'expired', 'job_id': job_id, 'message': 'İş bulunamadı veya saklama süresi doldu.'}
    if result.get('status') in ACTIVE_JOB_STATES:
        deadline = result.get('deadline')
        if deadline and _utcnow() > datetime.fromisoformat(deadline):
            result.update(status='timeout', error='job_deadline_exceeded')
            set_celery_job('job:' + job_id, result)
            if result.get('url'):
                store.delete('analyzing:' + normalize_url_record(result['url']).get('url_hash', ''))
    if result.get('status') == 'complete' and isinstance(api_key, APIKey):
        record_private_scan(db, api_key, result['url'], result, job_id)
    return result


def scan_history(db: Session, api_key: APIKey, *, limit: int, page: int, days: int) -> dict[str, Any]:
    query = db.query(PrivateScan).filter(PrivateScan.user_id == api_key.user_id,
                                         PrivateScan.created_at >= _utcnow() - timedelta(days=days))
    total = query.count()
    rows = query.order_by(PrivateScan.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
    data = [{'url': r.url, 'risk_score': r.risk_score, 'safety_score': 100 - r.risk_score, 'risk_level': r.risk_level,
             'checked_at': _iso(r.created_at), 'is_safe': r.risk_score <= 20} for r in rows]
    return {'data': data, 'history': data, 'total': total, 'page': page, 'total_pages': max(1, (total + limit - 1) // limit)}


# ── Threat database ───────────────────────────────────────────────────────

def _phishing_row(item: PhishingURL) -> dict[str, Any]:
    return {'id': item.id, 'url': item.url, 'domain': item.domain_norm or item.url, 'target': item.target or 'Phishing',
            'status': item.status or 'unknown', 'submission_time': _iso(item.submission_time), 'phish_id': item.phish_id}


def add_site(db: Session, url: str, target: str, status: str) -> str:
    normalized = normalize_url_record(url)
    if normalized.get('url_hash') and db.query(PhishingURL.id).filter_by(url_hash=normalized['url_hash']).first():
        raise Conflict('Bu URL zaten kayıtlı.', code='duplicate_url')
    phish_id = f'PHISH-{uuid.uuid4().hex[:12].upper()}'
    db.add(PhishingURL(phish_id=phish_id, url=normalized.get('canonical_url', url.strip()), url_hash=normalized.get('url_hash'),
                       domain_norm=normalized.get('domain_norm'), target=target, status=status,
                       online=status.upper() == 'ONLINE'))
    db.commit()
    logger.info('Phishing site added: %s', phish_id)
    return phish_id


def dashboard_stats(db: Session) -> dict[str, Any]:
    stats = get_phishing_stats()
    if not stats.get('total_urls'):
        stats = {'total_urls': db.query(func.count(PhishingURL.id)).scalar() or 0,
                 'phishing_count': stats.get('phishing_count', 0), 'safe_count': stats.get('safe_count', 0),
                 'today_scans': stats.get('today_scans', 0)}
    return stats


def latest_paged(db: Session, *, limit: int, page: int) -> dict[str, Any]:
    status_rank = case(
        (func.lower(PhishingURL.status).in_(['active', 'online']), 0),
        (func.lower(PhishingURL.status) == 'valid', 1),
        else_=2,
    )
    total = db.query(func.count(PhishingURL.id)).scalar() or 0
    items = (db.query(PhishingURL).order_by(status_rank.asc(), PhishingURL.id.desc())
             .offset((page - 1) * limit).limit(limit).all())
    return {'data': [_phishing_row(i) for i in items], 'page': page, 'total_pages': (total + limit - 1) // limit,
            'total': total, 'page_size': limit, 'module': MODULE}


def latest(db: Session, limit: int) -> dict[str, Any]:
    items = db.query(PhishingURL).order_by(PhishingURL.id.desc()).limit(limit).all()
    rows = [{**_phishing_row(i), 'risk_score': 85} for i in items]  # known phishing ⇒ high risk
    return {'latest': rows, 'limit': limit, 'total': db.query(func.count(PhishingURL.id)).scalar() or 0, 'module': MODULE}


def search(db: Session, text: str, *, limit: int, page: int) -> dict[str, Any]:
    """Substring search without COUNT(*): pagination is approximate (has-more)."""
    escaped = text.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_')
    rows = (db.query(PhishingURL).filter(PhishingURL.url.ilike(f'%{escaped}%', escape='\\'))
            .order_by(PhishingURL.id.desc()).offset((page - 1) * limit).limit(limit + 1).all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {'status': 'DANGER' if rows else 'SAFE', 'data': [_phishing_row(r) for r in rows], 'page': page,
            'total_pages': page + int(has_more) if rows else 0, 'total': (page - 1) * limit + len(rows) + int(has_more),
            'has_more': has_more, 'module': MODULE}
