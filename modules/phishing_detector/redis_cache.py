"""
In-Memory Cache Layer — Phishing Detector
==========================================
Eski Redis cache'in drop-in yerine. Aynı API'yi thread-safe
dict + TTL ile sağlar (celery worker ile API process'i ayrı olduğu
için sayaçlar process bazlı; bu kişisel proje için yeterli).

TTL'ler:
  SCAN_CACHE_TTL    : 30 gün  (tarama sonuçları)
  THREAT_INTEL_TTL  :  6 saat (Spamhaus, URLhaus vb. API cevapları)
  AI_DAY_TTL        : 24 saat (günlük AI API sayacı)
"""

import json
import logging
import os
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SCAN_CACHE_TTL = 60 * 60 * 24 * 30   # 30 gün
THREAT_INTEL_TTL = 60 * 60 * 6        # 6 saat
AI_DAILY_LIMIT = int(os.getenv("AI_DAILY_LIMIT", "14000"))

_lock = threading.Lock()
_store: Dict[str, tuple] = {}  # key → (value_json, expires_at)
_ai_counter = 0
_ai_expires_at = 0.0


def _now() -> float:
    return time.time()


def _get(key: str) -> Optional[str]:
    """Store'dan TTL-aware oku, süresi geçmişse sil."""
    with _lock:
        entry = _store.get(key)
        if entry is None:
            return None
        value, expires_at = entry
        if expires_at and expires_at < _now():
            _store.pop(key, None)
            return None
        return value


def _set(key: str, value: str, ttl: int) -> None:
    expires_at = _now() + ttl if ttl > 0 else 0
    with _lock:
        _store[key] = (value, expires_at)


def _delete(key: str) -> None:
    with _lock:
        _store.pop(key, None)


# ── Tarama sonucu cache ────────────────────────────────────────────────────

def redis_set_scan(url_hash: str, result: Dict[str, Any]) -> bool:
    _set(f"scan:{url_hash}", json.dumps(result, default=str), SCAN_CACHE_TTL)
    return True


def redis_get_scan(url_hash: str) -> Optional[Dict[str, Any]]:
    data = _get(f"scan:{url_hash}")
    if not data:
        return None
    try:
        result = json.loads(data)
        result["_redis_hit"] = True
        return result
    except Exception as e:
        logger.warning(f"redis_get_scan parse failed for {url_hash}: {e}")
        return None


def redis_invalidate_scan(url_hash: str) -> bool:
    _delete(f"scan:{url_hash}")
    return True


# ── Threat intel API cache ─────────────────────────────────────────────────

def redis_set_threat(key: str, data: Dict[str, Any], ttl: int = THREAT_INTEL_TTL) -> bool:
    _set(f"ti:{key}", json.dumps(data, default=str), ttl)
    return True


def redis_get_threat(key: str) -> Optional[Dict[str, Any]]:
    data = _get(f"ti:{key}")
    if not data:
        return None
    try:
        result = json.loads(data)
        result["_cache_hit"] = True
        return result
    except Exception as e:
        logger.warning(f"redis_get_threat parse failed for {key}: {e}")
        return None


# ── AI günlük sayacı ──────────────────────────────────────────────────

def redis_get_ai_count() -> int:
    global _ai_counter, _ai_expires_at
    with _lock:
        if _ai_expires_at and _ai_expires_at < _now():
            _ai_counter = 0
            _ai_expires_at = 0.0
        return _ai_counter


def redis_incr_ai_counter() -> int:
    global _ai_counter, _ai_expires_at
    with _lock:
        if _ai_expires_at and _ai_expires_at < _now():
            _ai_counter = 0
        _ai_counter += 1
        if _ai_counter == 1:
            _ai_expires_at = _now() + 86400
        return _ai_counter


def ai_limit_reached() -> bool:
    return redis_get_ai_count() >= AI_DAILY_LIMIT


# ── Sağlık kontrolü ───────────────────────────────────────────────────────

def redis_health() -> Dict[str, Any]:
    with _lock:
        size = len(_store)
    return {
        "available": True,
        "used_memory_human": f"{size} keys",
        "ai_daily_count": redis_get_ai_count(),
        "ai_daily_limit": AI_DAILY_LIMIT,
    }