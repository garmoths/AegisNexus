"""Durable event delivery and user watch checks."""
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from celery.signals import heartbeat_sent, task_failure, task_postrun, task_prerun

from app import runtime_store as store
from app.celery_app import celery_app
from app.database import SessionLocal
from app.models import EventOutbox, IndicatorOfCompromise, UserNotification, UserReport, WatchItem


@celery_app.task(name='app.workflow_tasks.runtime_probe')
def runtime_probe():
    """Side-effect-free end-to-end queue probe for the local launcher."""
    return {'ok': True}


@task_prerun.connect
def task_started(sender=None, task_id=None, **kwargs):
    store.put('task:' + sender.name, {'state': 'running', 'task_id': task_id, 'started_at': datetime.now(UTC).isoformat()}, 604800)


@task_postrun.connect
def task_finished(sender=None, state=None, retval=None, **kwargs):
    value = store.get('task:' + sender.name, {})
    reported_error = isinstance(retval, dict) and retval.get('status') in ('error', 'failed')
    value.update(state='FAILURE' if reported_error else state, finished_at=datetime.now(UTC).isoformat())
    if state == 'SUCCESS' and not reported_error:
        value['last_success_at'] = value['finished_at']
    store.put('task:' + sender.name, value, 604800)


@task_failure.connect
def task_failed(sender=None, **kwargs):
    value = store.get('task:' + sender.name, {})
    value.update(state='FAILURE', last_error='task_failed', finished_at=datetime.now(UTC).isoformat())
    store.put('task:' + sender.name, value, 604800)


@heartbeat_sent.connect
def worker_heartbeat(sender=None, **kwargs):
    hostname = getattr(getattr(sender, 'eventer', None), 'hostname', 'worker')
    store.put('worker:' + str(hostname), {'hostname': hostname, 'seen_at': datetime.now(UTC).isoformat()}, 60)


@celery_app.task(name='app.workflow_tasks.deliver_outbox', acks_late=True)
def deliver_outbox():
    from modules.shared.event_listeners import register_event_listeners
    from modules.shared.events import publish
    register_event_listeners()
    processed = 0
    with SessionLocal() as db:
        ids = [r.id for r in db.query(EventOutbox).filter(EventOutbox.processed_at.is_(None), EventOutbox.attempts < 10).order_by(EventOutbox.id).limit(50)]
    for event_id in ids:
        lease = 'outbox:' + str(event_id)
        if not store.claim(lease, True, 120):
            continue
        try:
            with SessionLocal() as db:
                entry = db.get(EventOutbox, event_id)
                if entry is None or entry.processed_at:
                    continue
                try:
                    publish(entry.event, entry.payload, strict=True)
                    entry.processed_at = datetime.now(UTC)
                    entry.last_error = None
                    processed += 1
                except Exception:
                    entry.last_error = 'delivery_failed'
                entry.attempts += 1
                db.commit()
        finally:
            store.delete(lease)
    return {'processed': processed}


@celery_app.task(name='app.workflow_tasks.check_watchlist', acks_late=True)
def check_watchlist():
    from urllib.parse import urlsplit
    with SessionLocal() as db:
        ids = [r.id for r in db.query(WatchItem).filter_by(is_active=True).limit(1000)]
    checked = 0
    for item_id in ids:
        lease = 'watch:' + str(item_id)
        if not store.claim(lease, True, 120):
            continue
        try:
            with SessionLocal() as db:
                item = db.get(WatchItem, item_id)
                if item is None:
                    continue
                try:
                    if item.kind != 'domain':
                        raise ValueError('source_unavailable')
                    else:
                        candidates = db.query(IndicatorOfCompromise).filter(IndicatorOfCompromise.status == 'active',
                            IndicatorOfCompromise.ioc_type.in_(['domain', 'url']),
                            IndicatorOfCompromise.ioc_value.contains(item.value)).limit(2000).all()
                        hits = [c for c in candidates if (urlsplit(c.ioc_value if '://' in c.ioc_value else 'https://' + c.ioc_value).hostname or '').lower().rstrip('.') == item.value]
                        result: dict[str, Any] = {'risk_score': max([c.risk_score for c in hits], default=0), 'indicators': sorted(c.ioc_value_hash or str(c.id) for c in hits)}
                        # No feed observation is unknown, not a clean domain.
                        if db.query(IndicatorOfCompromise.id).filter(
                            IndicatorOfCompromise.last_seen >= datetime.now(UTC) - timedelta(hours=48)
                        ).first() is None:
                            raise ValueError('no_feed_data')
                    fingerprint = hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()
                    changed = item.last_fingerprint and item.last_fingerprint != fingerprint
                    if changed or (item.last_fingerprint is None and result['risk_score'] >= 60):
                        db.add(UserNotification(user_id=item.user_id, watch_id=item.id, title='Takip ettiğiniz göstergenin durumu değişti', detail={'value': item.value, **result}))
                    item.last_fingerprint, item.last_result, item.last_error = fingerprint, result, None
                    checked += 1
                except Exception:
                    item.last_error = 'source_unavailable'
                item.last_checked_at = datetime.now(UTC)
                db.commit()
        finally:
            store.delete(lease)
    return {'checked': checked}


@celery_app.task(bind=True, max_retries=2, name='app.workflow_tasks.generate_report_pdf')
def generate_report_pdf(self, report_id: int):
    """Render the PDF for an incident report (triggered by report.pdf_requested)."""
    from app.pdf_reports import generate_pdf
    with SessionLocal() as db:
        report = db.get(UserReport, report_id)
        if report is None:
            return {'status': 'not_found', 'report_id': report_id}
        try:
            report.pdf_path = generate_pdf(report)
            report.pdf_status = 'ready'
            db.commit()
            return {'status': 'success', 'report_id': report_id, 'pdf_path': report.pdf_path}
        except Exception:
            report.pdf_status = 'failed'
            db.commit()
            raise
