"""Compatibility API backed by shared, expiring SQLite storage (no Redis server)."""
import os

from app import runtime_store as store

SCAN_CACHE_TTL = int(os.getenv('SCAN_CACHE_TTL', '21600'))
THREAT_INTEL_TTL = 21600
AI_DAILY_LIMIT = int(os.getenv('AI_DAILY_LIMIT', '14000'))


def redis_set_scan(url_hash, result):
    return store.put('scan:' + url_hash, result, SCAN_CACHE_TTL)


def redis_get_scan(url_hash):
    value = store.get('scan:' + url_hash)
    if value is not None:
        value['_cache_hit'] = True
    return value


def redis_invalidate_scan(url_hash):
    store.delete('scan:' + url_hash)
    return True


def redis_set_threat(key, data, ttl=THREAT_INTEL_TTL):
    return store.put('ti:' + key, data, ttl)


def redis_get_threat(key):
    value = store.get('ti:' + key)
    if value is not None:
        value['_cache_hit'] = True
    return value


def redis_get_ai_count():
    return store.get('ai:daily', 0)


def redis_incr_ai_counter():
    count, accepted = store.increment('ai:daily', limit=AI_DAILY_LIMIT)
    if not accepted:
        raise RuntimeError('Günlük AI kullanım sınırı doldu.')
    return count


def ai_limit_reached():
    return redis_get_ai_count() >= AI_DAILY_LIMIT


def redis_health():
    try:
        return {'available': True, 'backend': 'sqlite', 'keys': len(store.entries('')),
                'ai_daily_count': redis_get_ai_count(), 'ai_daily_limit': AI_DAILY_LIMIT}
    except Exception:
        return {'available': False, 'backend': 'sqlite'}
