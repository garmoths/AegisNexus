"""
Redis Cache Layer — Phishing Detector
======================================
Sıcak cache için Redis kullanır. Redis yoksa sessizce None döner,
SQLite fallback (cache_db.py) devreye girer.

TTL'ler:
  SCAN_CACHE_TTL    : 30 gün  (tarama sonuçları)
  THREAT_INTEL_TTL  :  6 saat (Spamhaus, URLhaus vb. API cevapları)
  AI_DAY_TTL    : 24 saat (günlük AI API sayacı)
"""

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

SCAN_CACHE_TTL   = 60 * 60 * 24 * 30   # 30 gün
THREAT_INTEL_TTL = 60 * 60 * 6          # 6 saat
AI_DAILY_LIMIT = int(os.getenv("AI_DAILY_LIMIT", "14000"))

_redis_client = None


def _get_redis():
    """Redis bağlantısını döner; kurulamıyorsa None döner (graceful fallback)."""
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    try:
        import redis
        host = os.getenv("REDIS_HOST", "127.0.0.1")
        port = int(os.getenv("REDIS_PORT", "6379"))
        client = redis.Redis(
            host=host,
            port=port,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        client.ping()
        _redis_client = client
        logger.info(f"Redis bağlantısı kuruldu: {host}:{port}")
        return _redis_client
    except Exception as e:
        logger.debug(f"Redis kullanılamıyor, SQLite fallback aktif: {e}")
        return None


# ── Tarama sonucu cache ────────────────────────────────────────────────────

def redis_set_scan(url_hash: str, result: Dict[str, Any]) -> bool:
    """Tarama sonucunu Redis'e yaz (30 gün TTL)."""
    r = _get_redis()
    if r is None:
        return False
    try:
        r.setex(f"scan:{url_hash}", SCAN_CACHE_TTL, json.dumps(result, default=str))
        return True
    except Exception as e:
        logger.warning(f"redis_set_scan failed for {url_hash}: {e}")
        return False


def redis_get_scan(url_hash: str) -> Optional[Dict[str, Any]]:
    """Tarama sonucunu Redis'ten oku. Cache miss veya hata → None."""
    r = _get_redis()
    if r is None:
        return None
    try:
        data = r.get(f"scan:{url_hash}")
        if data:
            result = json.loads(data)
            result["_redis_hit"] = True
            return result
        return None
    except Exception as e:
        logger.warning(f"redis_get_scan failed for {url_hash}: {e}")
        return None


def redis_invalidate_scan(url_hash: str) -> bool:
    """Belirli bir URL'nin cache'ini zorla sil (force_fresh için)."""
    r = _get_redis()
    if r is None:
        return False
    try:
        r.delete(f"scan:{url_hash}")
        return True
    except Exception as e:
        logger.warning(f"redis_invalidate_scan failed: {e}")
        return False


# ── Threat intel API cache ─────────────────────────────────────────────────

def redis_set_threat(key: str, data: Dict[str, Any], ttl: int = THREAT_INTEL_TTL) -> bool:
    """Threat intel API sonucunu Redis'e yaz (varsayılan 6 saat TTL)."""
    r = _get_redis()
    if r is None:
        return False
    try:
        r.setex(f"ti:{key}", ttl, json.dumps(data, default=str))
        return True
    except Exception as e:
        logger.warning(f"redis_set_threat failed for {key}: {e}")
        return False


def redis_get_threat(key: str) -> Optional[Dict[str, Any]]:
    """Threat intel sonucunu Redis'ten oku."""
    r = _get_redis()
    if r is None:
        return None
    try:
        data = r.get(f"ti:{key}")
        if data:
            result = json.loads(data)
            result["_cache_hit"] = True
            return result
        return None
    except Exception as e:
        logger.warning(f"redis_get_threat failed for {key}: {e}")
        return None


# ── AI günlük sayacı ──────────────────────────────────────────────────

def redis_get_ai_count() -> int:
    """Bugünkü AI API çağrı sayısını döner."""
    r = _get_redis()
    if r is None:
        return 0
    try:
        return int(r.get("ai:daily_count") or 0)
    except Exception:
        return 0


def redis_incr_ai_counter() -> int:
    """AI sayacını artır, 24 saat TTL uygula. Yeni değeri döner."""
    r = _get_redis()
    if r is None:
        return 0
    try:
        pipe = r.pipeline()
        pipe.incr("ai:daily_count")
        pipe.expire("ai:daily_count", 86400)
        results = pipe.execute()
        return int(results[0])
    except Exception as e:
        logger.warning(f"redis_incr_ai_counter failed: {e}")
        return 0


def ai_limit_reached() -> bool:
    """Günlük AI kotası dolmuşsa True döner."""
    return redis_get_ai_count() >= AI_DAILY_LIMIT


# ── Sağlık kontrolü ───────────────────────────────────────────────────────

def redis_health() -> Dict[str, Any]:
    """Redis bağlantı durumunu döner (monitoring için)."""
    r = _get_redis()
    if r is None:
        return {"available": False, "reason": "connection_failed"}
    try:
        r.ping()
        info = r.info("memory")
        return {
            "available": True,
            "used_memory_human": info.get("used_memory_human", "?"),
            "ai_daily_count": redis_get_ai_count(),
            "ai_daily_limit": AI_DAILY_LIMIT,
        }
    except Exception as e:
        return {"available": False, "reason": str(e)}
