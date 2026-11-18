import uuid

from app import runtime_store as store
from app.celery_app import celery_app
from app.discovery.service import now
from app.discovery.worker import poll_sources, release, run_one, schedule_rechecks


def tick():
    token = uuid.uuid4().hex
    if not store.claim('crawler:tick', token, 600):
        return {'state': 'busy'}
    try:
        store.put('crawler:heartbeat', {'seen_at': now().isoformat(), 'state': 'running'}, 600)
        schedule_rechecks()
        poll_sources()
        result = run_one()
        store.put('crawler:heartbeat', {'seen_at': now().isoformat(), **result}, 600)
        return result
    finally:
        release('crawler:tick', token)


@celery_app.task(name='app.discovery.tasks.tick', soft_time_limit=240, time_limit=300)
def scheduled_tick():
    return tick()
