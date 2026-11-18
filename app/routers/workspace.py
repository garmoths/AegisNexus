"""Owned feedback, watchlists, notifications and operational evidence."""
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from app import runtime_store as store
from app.auth import require_admin, resolve_api_key
from app.config import get_settings
from app.database import get_db
from app.models import AnalysisFeedback, APIKey, EventOutbox, IndicatorOfCompromise, UserNotification, UserReport, WatchItem
from app.outbound import validate_url

router = APIRouter(tags=['workspace'])


class FeedbackRequest(BaseModel):
    report_id: int | None = None
    url: str | None = Field(default=None, max_length=2048)
    expected_verdict: str = Field(pattern='^(safe|dangerous|uncertain)$')
    reason: str = Field(min_length=5, max_length=2000)


class FeedbackReview(BaseModel):
    status: str = Field(pattern='^(resolved|rejected)$')
    note: str = Field(min_length=5, max_length=2000)


@router.post('/feedback')
def feedback(body: FeedbackRequest, key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    if body.report_id and not db.query(UserReport).filter_by(id=body.report_id, user_id=key.user_id).first():
        raise HTTPException(404, 'Rapor bulunamadı.')
    if not body.report_id and not body.url:
        raise HTTPException(422, 'Rapor veya URL gerekli.')
    row = AnalysisFeedback(user_id=key.user_id, **body.model_dump())
    db.add(row)
    db.commit()
    return {'id': row.id, 'status': row.status}


@router.get('/feedback')
def my_feedback(key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    return {'data': [{'id': r.id, 'status': r.status, 'reason': r.reason, 'review_note': r.review_note}
                     for r in db.query(AnalysisFeedback).filter_by(user_id=key.user_id).order_by(AnalysisFeedback.id.desc()).limit(100)]}


@router.get('/admin/feedback')
def pending_feedback(key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    return {'data': [{'id': r.id, 'report_id': r.report_id, 'url': r.url, 'expected_verdict': r.expected_verdict,
                      'reason': r.reason, 'status': r.status} for r in db.query(AnalysisFeedback).filter_by(status='pending').limit(100)]}


@router.patch('/admin/feedback/{feedback_id}')
def review_feedback(feedback_id: int, body: FeedbackReview, key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    row = db.get(AnalysisFeedback, feedback_id)
    if row is None:
        raise HTTPException(404, 'Geri bildirim bulunamadı.')
    row.status, row.review_note = body.status, body.note
    db.commit()
    if row.url:
        from modules.phishing_detector.url_normalize import normalize_url_record
        store.delete('scan:' + normalize_url_record(row.url).get('url_hash', ''))
    return {'id': row.id, 'status': row.status}


class WatchRequest(BaseModel):
    kind: str = Field(default='domain', pattern='^domain$')
    value: str = Field(min_length=3, max_length=255)


@router.post('/watchlist')
def add_watch(body: WatchRequest, key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    value = body.value.strip().lower()
    try:
        normalized, host, _, _ = validate_url(value, resolve=False)
        if urlsplit(normalized).path != '/' or urlsplit(normalized).query:
            raise ValueError('Yalnızca alan adı girin.')
        value = host
    except ValueError as exc:
        raise HTTPException(422, 'Geçerli bir alan adı girin.') from exc
    row = db.query(WatchItem).filter_by(user_id=key.user_id, kind=body.kind, value=value).first()
    if row:
        row.is_active = True
    else:
        if db.query(WatchItem).filter_by(user_id=key.user_id, is_active=True).count() >= 20:
            raise HTTPException(409, 'En fazla 20 gösterge takip edebilirsiniz.')
        row = WatchItem(user_id=key.user_id, kind=body.kind, value=value)
        db.add(row)
    db.commit()
    return {'id': row.id, 'value': value}


@router.get('/watchlist')
def watchlist(key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    return {'data': [{'id': r.id, 'kind': r.kind, 'value': r.value, 'last_result': r.last_result,
                      'last_checked_at': r.last_checked_at, 'last_error': r.last_error}
        for r in db.query(WatchItem).filter_by(user_id=key.user_id, is_active=True).order_by(WatchItem.id.desc()).all()]}


@router.delete('/watchlist/{watch_id}')
def delete_watch(watch_id: int, key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    row = db.query(WatchItem).filter_by(id=watch_id, user_id=key.user_id).first()
    if row is None:
        raise HTTPException(404, 'Takip bulunamadı.')
    row.is_active = False
    db.commit()
    return {'status': 'disabled'}


@router.get('/notifications')
def notifications(key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    return {'data': [{'id': r.id, 'title': r.title, 'detail': r.detail, 'read_at': r.read_at, 'created_at': r.created_at}
                    for r in db.query(UserNotification).filter_by(user_id=key.user_id).order_by(UserNotification.id.desc()).limit(100)]}


@router.patch('/notifications/{notification_id}')
def read_notification(notification_id: int, key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    row = db.query(UserNotification).filter_by(id=notification_id, user_id=key.user_id).first()
    if row is None:
        raise HTTPException(404, 'Bildirim bulunamadı.')
    row.read_at = datetime.now(UTC)
    db.commit()
    return {'status': 'read'}


@router.get('/system/operations')
def operations(key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    from app.celery_app import celery_app
    broker: dict[str, Any] = {'available': False, 'queues': {}}
    try:
        with celery_app.connection_for_read(connect_timeout=2) as connection:
            connection.ensure_connection(max_retries=0)
            with connection.channel() as channel:
                for queue in ('default', 'phishing'):
                    _, messages, consumers = channel.queue_declare(queue=queue, passive=True)
                    broker['queues'][queue] = {'waiting': messages, 'consumers': consumers}
            broker['available'] = True
    except Exception:
        broker['error'] = 'broker_unavailable'
    return {'broker': broker, 'workers': list(store.entries('worker:').values()), 'tasks': store.entries('task:'),
            'outbox_pending': db.query(EventOutbox).filter(EventOutbox.processed_at.is_(None)).count(),
            'ioc_last_seen': db.query(func.max(IndicatorOfCompromise.last_seen)).scalar(),
            'schedule': [{'name': name, 'task': spec['task'], 'interval': str(spec['schedule'])}
                         for name, spec in celery_app.conf.beat_schedule.items()]}


@router.get('/telemetry/overview')
def telemetry(db: Session = Depends(get_db)):
    from app.models import URLAnalizHistory
    from modules.phishing_detector.cache_db import get_phishing_stats
    stats = get_phishing_stats()
    return {'data_source': 'local_observations', 'scanned_urls': stats.get('today_scans', 0),
            'active_iocs': db.query(IndicatorOfCompromise).filter_by(status='active').count(),
            'analyzed_urls': db.query(URLAnalizHistory).count(),
            'last_feed_at': db.query(func.max(IndicatorOfCompromise.last_seen)).scalar(),
            'measured_at': datetime.now(UTC).isoformat(), 'sla_percent': None, 'average_scan_seconds': None}


@router.get('/system/capabilities')
def capabilities():
    settings = get_settings()
    return {'modules': 3, 'demo_mode': settings.demo_mode, 'recovery_available': settings.recovery_mail_enabled}
