"""
Tarayıcı önbelleği — ana veritabanında (data/aegis.db).
- scan_results: yeniden kullanılabilir son URL kararları (ScanResult)
- scan_events: kullanıcı tarama geçmişi (ScanEvent)
- Tehdit bulguları ana IOC tablosuna yazılır (IndicatorOfCompromise)
- API önbelleği ve iş durumları runtime_store'da (data/runtime.db)
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.config import get_settings

logger = logging.getLogger(__name__)

MAX_CACHE_ROWS = get_settings().threat_cache_max_rows
MAX_SCAN_EVENTS = get_settings().threat_scan_events_max_rows
_DB_INITIALIZED = False


def _db_path() -> Path:
    from app.database import DB_FILE
    return DB_FILE


def _ensure_initialized():
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    init_database()
    _DB_INITIALIZED = True


@contextmanager
def get_db_connection():
    """Ana veritabanına (data/aegis.db) ham sqlite3 bağlantısı."""
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_database():
    """Tarama tablolarını ORM tanımından oluştur (tek şema kaynağı: app/models.py)."""
    from app.database import engine
    from app.models import IndicatorOfCompromise, ScanEvent, ScanResult
    tables = [ScanResult.__table__, ScanEvent.__table__, IndicatorOfCompromise.__table__]
    ScanResult.metadata.create_all(engine, tables=tables)


def _prune_cache(cursor: sqlite3.Cursor):
    cursor.execute("""
        DELETE FROM scan_results
        WHERE id NOT IN (
            SELECT id FROM scan_results
            ORDER BY checked_at DESC, id DESC
            LIMIT ?
        )
    """, (MAX_CACHE_ROWS,))
    cursor.execute("""
        DELETE FROM scan_events
        WHERE id NOT IN (
            SELECT id FROM scan_events
            ORDER BY checked_at DESC, id DESC
            LIMIT ?
        )
    """, (MAX_SCAN_EVENTS,))


def write_phishing_url(
    url: str,
    risk_score: int,
    risk_level: str,
    is_safe: bool,
    sources: list[str],
    raw_data: dict | None = None,
    track_event: bool = True,
) -> bool:
    """URL tarama sonucunu veritabanına yaz"""
    try:
        risk_score = min(100, max(0, int(risk_score)))
        _ensure_initialized()
        parsed = urlparse(url)
        domain = (parsed.netloc or parsed.path or "").lower()
        if domain:
            domain = domain.split("/")[0]
        sources_json = json.dumps(sources) if sources else "[]"
        raw_data_json = json.dumps(raw_data) if raw_data is not None else None

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # UPSERT - varsa güncelle, yoksa oluştur
            cursor.execute("""
                INSERT INTO scan_results (url, domain, risk_score, risk_level, is_safe, sources, raw_data, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(url) DO UPDATE SET
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    is_safe = excluded.is_safe,
                    sources = excluded.sources,
                    raw_data = excluded.raw_data,
                    last_updated = CURRENT_TIMESTAMP,
                    checked_at = CURRENT_TIMESTAMP
            """, (url, domain, risk_score, risk_level, is_safe, sources_json, raw_data_json))

            if track_event:
                cursor.execute("""
                    INSERT INTO scan_events (url, domain, risk_score, risk_level, is_safe, sources, checked_at)
                    VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(url) DO UPDATE SET
                        risk_score = excluded.risk_score,
                        risk_level = excluded.risk_level,
                        is_safe = excluded.is_safe,
                        sources = excluded.sources,
                        checked_at = CURRENT_TIMESTAMP
                """, (url, domain, risk_score, risk_level, int(is_safe), sources_json))

            _prune_cache(cursor)

            conn.commit()
        if not is_safe and risk_score > 40:
            write_ioc('url', url, 'phishing', risk_score, 'detector', raw_data)
        logger.debug(f"Phishing URL cached: {url} (risk: {risk_score})")
        return True

    except Exception as e:
        logger.error(f"Failed to write phishing URL: {e}")
        return False

def write_ioc(ioc_type: str, ioc_value: str, threat_type: str, confidence: int,
              source: str, raw_data: dict | None = None) -> bool:
    """Tarama sırasında bulunan göstergeyi ana IOC tablosuna ekle/güncelle."""
    import hashlib

    from app.database import SessionLocal
    from app.models import IndicatorOfCompromise
    if not ioc_value:
        return False
    try:
        score = min(100, max(1, int(confidence or 50)))
        now = datetime.now(UTC)
        value_hash = hashlib.sha256(ioc_value.encode()).hexdigest()
        with SessionLocal() as db:
            row = db.query(IndicatorOfCompromise).filter_by(ioc_value_hash=value_hash).first()
            if row:
                row.detection_count = (row.detection_count or 0) + 1
                row.last_seen = now
                row.risk_score = max(row.risk_score or 0, score)
            else:
                db.add(IndicatorOfCompromise(
                    ioc_type=ioc_type, ioc_value=ioc_value[:1000], ioc_value_hash=value_hash,
                    source=source[:50], threat_type=str(threat_type or 'unknown')[:100], risk_score=score,
                    confidence=score / 100, first_seen=now, last_seen=now, detection_count=1, status='active',
                    ioc_metadata=raw_data if isinstance(raw_data, dict) else None))
            db.commit()
        return True
    except Exception as e:
        logger.error(f"Failed to write IOC: {e}")
        return False

def get_phishing_history(limit: int = 50, days: int = 30) -> list[dict]:
    """Son URL tarama geçmişini getir"""
    try:
        _ensure_initialized()
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT url, domain, risk_score, risk_level, is_safe, sources, checked_at
                FROM scan_results
                WHERE checked_at >= ?
                ORDER BY checked_at DESC
                LIMIT ?
            """, (cutoff_date.isoformat(), limit))

            results = []
            for row in cursor.fetchall():
                results.append({
                    'url': row['url'],
                    'domain': row['domain'],
                    'risk_score': row['risk_score'],
                    'risk_level': row['risk_level'],
                    'is_safe': bool(row['is_safe']),
                    'sources': json.loads(row['sources']) if row['sources'] else [],
                    'checked_at': row['checked_at']
                })

            return results

    except Exception as e:
        logger.error(f"Failed to get phishing history: {e}")
        return []

def get_latest_phishing(limit: int = 20) -> list[dict]:
    """Son phishing URL'leri getir"""
    try:
        _ensure_initialized()
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT url, domain, risk_score, checked_at, sources
                FROM scan_results
                WHERE is_safe = 0 AND risk_score > 40
                ORDER BY checked_at DESC
                LIMIT ?
            """, (limit,))

            results = []
            for row in cursor.fetchall():
                results.append({
                    'url': row['url'],
                    'domain': row['domain'],
                    'risk_score': row['risk_score'],
                    'submission_time': row['checked_at'],
                    'target': 'Phishing',  # Default target
                    'sources': json.loads(row['sources']) if row['sources'] else []
                })

            return results

    except Exception as e:
        logger.error(f"Failed to get latest phishing: {e}")
        return []

def get_threat_type_distribution(limit: int = 10000) -> dict[str, int]:
    _ensure_initialized()
    with get_db_connection() as conn:
        rows = conn.execute("""SELECT threat_type, COUNT(*) AS count
            FROM indicators_of_compromise WHERE last_seen >= datetime('now', '-30 days')
            GROUP BY threat_type ORDER BY count DESC LIMIT ?""", (max(1, min(limit, 10000)),)).fetchall()
    return {r['threat_type']: r['count'] for r in rows}


def get_phishing_stats() -> dict[str, Any]:
    """Phishing istatistiklerini getir"""
    try:
        _ensure_initialized()
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Toplam URL (cache havuzu): tüm bilinen URL sayısı
            cursor.execute("SELECT COUNT(*) as total FROM scan_results")
            total_urls = int(cursor.fetchone()['total'] or 0)

            # Dashboard metrikleri scan-event tabanlı olmalı (yanıltıcı olmasın):
            # phishing_count + safe_count + today_scans => kullanıcı tarama geçmişinden.
            cursor.execute("SELECT COUNT(*) as total FROM scan_events")
            event_total = int(cursor.fetchone()['total'] or 0)

            if event_total > 0:
                cursor.execute("SELECT COUNT(*) as count FROM scan_events WHERE is_safe = 0")
                phishing_count = int(cursor.fetchone()['count'] or 0)

                cursor.execute("SELECT COUNT(*) as count FROM scan_events WHERE is_safe = 1")
                safe_count = int(cursor.fetchone()['count'] or 0)

                today = datetime.now().date().isoformat()
                cursor.execute("SELECT COUNT(*) as count FROM scan_events WHERE date(checked_at) = ?", (today,))
                today_scans = int(cursor.fetchone()['count'] or 0)
            else:
                # Event hiç yoksa legacy cache tablosuna fallback
                cursor.execute("SELECT COUNT(*) as count FROM scan_results WHERE is_safe = 0")
                phishing_count = int(cursor.fetchone()['count'] or 0)

                cursor.execute("SELECT COUNT(*) as count FROM scan_results WHERE is_safe = 1")
                safe_count = int(cursor.fetchone()['count'] or 0)

                today = datetime.now().date().isoformat()
                cursor.execute("SELECT COUNT(*) as count FROM scan_results WHERE date(checked_at) = ?", (today,))
                today_scans = int(cursor.fetchone()['count'] or 0)

            return {
                'total_urls': total_urls,
                'phishing_count': phishing_count,
                'safe_count': safe_count,
                'today_scans': today_scans
            }

    except Exception as e:
        logger.error(f"Failed to get phishing stats: {e}")
        return {
            'total_urls': 0,
            'phishing_count': 0,
            'safe_count': 0,
            'today_scans': 0
        }

def cleanup_old_records(days: int = 90) -> int:
    """Eski kayıtları temizle"""
    try:
        _ensure_initialized()
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Eski phishing URL'leri sil
            cursor.execute("""
                DELETE FROM scan_results
                WHERE checked_at < ? AND is_safe = 1
            """, (cutoff_date.isoformat(),))

            deleted = cursor.rowcount
            conn.commit()

            logger.info(f"Cleaned up {deleted} old records")
            return deleted

    except Exception as e:
        logger.error(f"Failed to cleanup old records: {e}")
        return 0

def cleanup_empty_records(days: int = 30) -> int:
    """Risk_score=0 olan (hiç taratılmamış) kayıtları temizle"""
    try:
        _ensure_initialized()
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Önce silinecek kayıtları görüntüle
            cursor.execute("""
                SELECT COUNT(*) as count FROM scan_results
                WHERE risk_score = 0
                AND checked_at >= ?
            """, (cutoff_date.isoformat(),))
            count = cursor.fetchone()['count']
            logger.info(f"Found {count} unscanned records (risk_score=0) to clean up")

            # Kayıtları sil
            cursor.execute("""
                DELETE FROM scan_results
                WHERE risk_score = 0
                AND checked_at >= ?
            """, (cutoff_date.isoformat(),))

            deleted = cursor.rowcount
            conn.commit()

            logger.info(f"Cleaned up {deleted} unscanned phishing records")
            return deleted

    except Exception as e:
        logger.error(f"Failed to cleanup unscanned records: {e}")
        return 0

def analyze_records(days: int = 30) -> dict[str, Any]:
    """Kayıtları analiz et ve temizleme kriterlerine göre grupla"""
    try:
        _ensure_initialized()
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Toplam kayıt sayısı
            cursor.execute("SELECT COUNT(*) as total FROM scan_results WHERE checked_at >= ?", (cutoff_date.isoformat(),))
            total = cursor.fetchone()['total']

            # Kriter bazlı analiz
            cursor.execute("""
                SELECT
                    CASE
                        WHEN risk_score = 0 THEN 'unscanned'
                        WHEN (sources = '[]' OR sources IS NULL) THEN 'no_sources'
                        WHEN raw_data IS NULL THEN 'no_raw_data'
                        ELSE 'valid'
                    END as category,
                    COUNT(*) as count
                FROM scan_results
                WHERE checked_at >= ?
                GROUP BY category
            """, (cutoff_date.isoformat(),))

            categories = {row['category']: row['count'] for row in cursor.fetchall()}

            return {
                'total_records': total,
                'categories': categories,
                'days': days,
                'cutoff_date': cutoff_date.isoformat()
            }

    except Exception as e:
        logger.error(f"Failed to analyze records: {e}")
        return {
            'total_records': 0,
            'categories': {},
            'days': days,
            'error': str(e)
        }

def cleanup_records(criteria: dict[str, Any], dry_run: bool = False) -> dict[str, Any]:
    """Profesyonel cleanup fonksiyonu - kriter bazlı temizleme

    Args:
        criteria: {
            'days': int (default: 30),
            'unscanned': bool (risk_score=0),
            'no_sources': bool (sources boş),
            'no_raw_data': bool (raw_data boş)
        }
        dry_run: True ise sadece silinecekleri görüntüle, silme
    """
    try:
        _ensure_initialized()
        days = criteria.get('days', 30)
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            # WHERE clause oluştur
            conditions = ["checked_at >= ?"]
            params = [cutoff_date.isoformat()]

            if criteria.get('unscanned'):
                conditions.append("risk_score = 0")

            if criteria.get('no_sources'):
                conditions.append("(sources = '[]' OR sources IS NULL)")

            if criteria.get('no_raw_data'):
                conditions.append("raw_data IS NULL")

            where_clause = " AND ".join(conditions)

            # Önce silinecek kayıtları görüntüle
            cursor.execute(f"""
                SELECT COUNT(*) as count FROM scan_results
                WHERE {where_clause}
            """, params)
            count = cursor.fetchone()['count']

            if dry_run:
                logger.info(f"Dry run: Would delete {count} records")
                return {
                    'deleted': 0,
                    'would_delete': count,
                    'dry_run': True,
                    'criteria': criteria
                }

            # Kayıtları sil
            cursor.execute(f"""
                DELETE FROM scan_results
                WHERE {where_clause}
            """, params)

            deleted = cursor.rowcount
            conn.commit()

            logger.info(f"Cleaned up {deleted} records with criteria: {criteria}")
            return {
                'deleted': deleted,
                'would_delete': 0,
                'dry_run': False,
                'criteria': criteria
            }

    except Exception as e:
        logger.error(f"Failed to cleanup records: {e}")
        return {
            'deleted': 0,
            'error': str(e),
            'criteria': criteria
        }

def detect_skipped_urls(days: int = 30) -> list[dict]:
    """Sources dolu ama risk_score=0 olan URL'leri tespit et"""
    try:
        _ensure_initialized()
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT url, domain, risk_score, risk_level, sources, checked_at
                FROM scan_results
                WHERE risk_score = 0
                AND sources IS NOT NULL
                AND sources != '[]'
                AND checked_at >= ?
                ORDER BY checked_at DESC
            """, (cutoff_date.isoformat(),))

            results = []
            for row in cursor.fetchall():
                results.append({
                    'url': row['url'],
                    'domain': row['domain'],
                    'risk_score': row['risk_score'],
                    'risk_level': row['risk_level'],
                    'sources': json.loads(row['sources']) if row['sources'] else [],
                    'checked_at': row['checked_at']
                })

            logger.warning(f"Found {len(results)} URLs with sources but risk_score=0 (possibly skipped or failed)")
            return results

    except Exception as e:
        logger.error(f"Failed to detect skipped URLs: {e}")
        return []

# Veritabanını başlat
if __name__ == "__main__":
    init_database()
    logger.info("Cache database initialized")


def write_threat_cache(key: str, data: dict, ttl_seconds: int = 21600) -> bool:
    """Threat intel API sonucunu TTL ile önbelleğe yaz (runtime_store)."""
    from app import runtime_store
    payload = dict(data, _cached_at=datetime.now().isoformat())
    return bool(runtime_store.put('threat:' + key, payload, ttl_seconds))


def read_threat_cache(key: str) -> dict | None:
    """Önbellekteki threat intel sonucunu oku; süresi geçmişse None."""
    from app import runtime_store
    data = runtime_store.get('threat:' + key)
    if data is None:
        return None
    data["_cache_hit"] = True
    return data


# ── Celery job takibi (runtime_store — süreçler arası) ──────────────

def set_celery_job(job_id: str, payload: dict, ttl_seconds: int = 3600) -> bool:
    from app import runtime_store
    return bool(runtime_store.put('celery:' + job_id, payload, ttl_seconds))


def get_celery_job(job_id: str) -> dict | None:
    from app import runtime_store
    return runtime_store.get('celery:' + job_id)


def save_check_url_result(url: str, result: dict):
    return persist_scan_result(url, result)


def persist_scan_result(url: str, result: dict, track_event=True):
    """One score contract: risk rises with danger; score/safety_score rise with safety."""
    safety = min(100, max(0, int(result.get('safety_score', result.get('score', 50)))))
    result.update(safety_score=safety, score=safety, risk_score=100-safety, score_version=2)
    sources = [s.get('name', '') if isinstance(s, dict) else str(s) for s in result.get('sources', [])]
    return write_phishing_url(url, 100-safety, str(result.get('risk_level', 'unknown')),
                              safety >= 80, sources, result, track_event=track_event)


def get_scan_history(limit: int = 20, page: int = 1, days: int = 30) -> dict[str, Any]:
    """Paginated user scan history."""
    try:
        _ensure_initialized()
        page = max(page, 1)
        # Son tarananlar modülünde minimum 20 gösterim standardı
        limit = max(limit, 20)
        offset = (page - 1) * limit
        cutoff_date = datetime.now() - timedelta(days=days)

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT COUNT(*) AS total
                FROM scan_events
                WHERE checked_at >= ?
                """,
                (cutoff_date.isoformat(),),
            )
            total = int(cursor.fetchone()["total"])

            cursor.execute(
                """
                SELECT url, domain, risk_score, risk_level, is_safe, sources, checked_at
                FROM scan_events
                WHERE checked_at >= ?
                ORDER BY checked_at DESC, id DESC
                LIMIT ? OFFSET ?
                """,
                (cutoff_date.isoformat(), limit, offset),
            )

            items = []
            for row in cursor.fetchall():
                items.append(
                    {
                        "url": row["url"],
                        "domain": row["domain"],
                        "risk_score": row["risk_score"],
                        "risk_level": row["risk_level"],
                        "is_safe": bool(row["is_safe"]),
                        "sources": json.loads(row["sources"]) if row["sources"] else [],
                        "checked_at": row["checked_at"],
                    }
                )

            total_pages = (total + limit - 1) // limit if total else 0
            return {
                "data": items,
                "page": page,
                "limit": limit,
                "total": total,
                "total_pages": total_pages,
            }
    except Exception as e:
        logger.error(f"Failed to get scan history: {e}")
        return {"data": [], "page": 1, "limit": limit, "total": 0, "total_pages": 0}


def get_cached_scan_result(url: str, days: int = 30) -> dict[str, Any] | None:
    """Aynı URL son N günde tarandıysa cache sonucu döndür."""
    try:
        _ensure_initialized()
        normalized_url = (url or "").strip()
        if not normalized_url:
            return None

        cutoff_date = datetime.now() - timedelta(days=max(days, 1))

        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT url, risk_score, risk_level, is_safe, sources, raw_data, checked_at
                FROM scan_results
                WHERE url = ? AND checked_at >= ?
                ORDER BY checked_at DESC, id DESC
                LIMIT 1
                """,
                (normalized_url, cutoff_date.isoformat()),
            )
            row = cursor.fetchone()
            if not row:
                return None

            raw_data = None
            if row["raw_data"]:
                try:
                    raw_data = json.loads(row["raw_data"])
                except Exception:
                    raw_data = None

            if isinstance(raw_data, dict):
                cached = dict(raw_data)
                cached["url"] = cached.get("url") or row["url"]
                cached["risk_score"] = int(row["risk_score"] or 0)
                cached["safety_score"] = 100 - cached["risk_score"]
                cached["score"] = cached["safety_score"]
                cached["risk_level"] = cached.get("risk_level") or row["risk_level"] or "unknown"
                if "sources" not in cached:
                    cached["sources"] = json.loads(row["sources"]) if row["sources"] else []
            else:
                cached = {
                    "url": row["url"],
                    "risk_score": int(row["risk_score"] or 0),
                    "safety_score": 100 - int(row["risk_score"] or 0),
                    "score": 100 - int(row["risk_score"] or 0),
                    "risk_level": row["risk_level"] or "unknown",
                    "details": ["Son 30 gün cache sonucundan döndürüldü."],
                    "sources": json.loads(row["sources"]) if row["sources"] else [],
                }

            cached["cache_hit"] = True
            cached["cached_at"] = row["checked_at"]
            return cached
    except Exception as e:
        logger.error(f"Failed to get cached scan result: {e}")
        return None
