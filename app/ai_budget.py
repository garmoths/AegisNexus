"""Atomic provider-attempt budget shared by every API and worker process."""
import os

from app.runtime_store import increment


def reserve_ai_call():
    limit = int(os.getenv('AI_DAILY_LIMIT', '14000'))
    count, accepted = increment('ai:daily', ttl=86400, limit=limit)
    if not accepted:
        raise RuntimeError('Günlük AI kullanım sınırı doldu.')
    return count
