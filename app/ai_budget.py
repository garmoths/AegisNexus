"""Atomic provider-attempt budget shared by every API and worker process."""

from app.config import get_settings
from app.runtime_store import increment


def reserve_ai_call():
    limit = get_settings().ai_daily_limit
    count, accepted = increment('ai:daily', ttl=86400, limit=limit)
    if not accepted:
        raise RuntimeError('Günlük AI kullanım sınırı doldu.')
    return count
