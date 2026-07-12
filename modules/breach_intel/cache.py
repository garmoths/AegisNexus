"""
HIBP Email Cache Database
Son aratılan emailleri 1 ay süreyle önbellekler (max 1000 kayıt)
"""
from __future__ import annotations

import json
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

CACHE_DB_PATH = Path(__file__).parent / "hibp_cache.db"
CACHE_TTL_DAYS = 30
MAX_CACHE_SIZE = 1000


def get_db_connection() -> sqlite3.Connection:
    """SQLite veritabanı bağlantısı oluştur"""
    conn = sqlite3.connect(str(CACHE_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_cache_db():
    """Cache veritabanını başlat"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS hibp_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            result TEXT NOT NULL,
            cached_at TIMESTAMP NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON hibp_cache(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_expires_at ON hibp_cache(expires_at)")
    conn.commit()
    conn.close()
    logger.info(f"HIBP cache database initialized: {CACHE_DB_PATH}")


def get_cached_result(email: str) -> Optional[Dict[str, Any]]:
    """Cache'ten sonuç getir (varsa ve süresi dolmamışsa)"""
    email = email.strip().lower()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT result FROM hibp_cache
        WHERE email = ? AND expires_at > datetime('now')
        """,
        (email,)
    )
    row = cursor.fetchone()
    conn.close()
    
    if row:
        logger.info(f"Cache hit for email: {email}")
        return json.loads(row["result"])
    
    logger.info(f"Cache miss for email: {email}")
    return None


def cache_result(email: str, result: Dict[str, Any]):
    """Sonucu cache'e kaydet"""
    email = email.strip().lower()
    now = datetime.utcnow()
    expires_at = now + timedelta(days=CACHE_TTL_DAYS)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Önce eski kayıt varsa sil
    cursor.execute("DELETE FROM hibp_cache WHERE email = ?", (email,))
    
    # Yeni kayıt ekle
    cursor.execute(
        """
        INSERT INTO hibp_cache (email, result, cached_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (email, json.dumps(result), now.isoformat(), expires_at.isoformat())
    )
    
    conn.commit()
    conn.close()
    logger.info(f"Cached result for email: {email} (expires: {expires_at.isoformat()})")
    
    # Cache boyutunu kontrol et ve temizle
    cleanup_cache()


def cleanup_cache():
    """
    Cache temizleme:
    1. Süresi dolmuş kayıtları sil
    2. 1000'den fazla kayıt varsa en eskileri sil (FIFO)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Süresi dolmuş kayıtları sil
    cursor.execute("DELETE FROM hibp_cache WHERE expires_at <= datetime('now')")
    deleted_expired = cursor.rowcount
    
    # Toplam kayıt sayısını kontrol et
    cursor.execute("SELECT COUNT(*) as count FROM hibp_cache")
    count = cursor.fetchone()["count"]
    
    if count > MAX_CACHE_SIZE:
        # En eski kayıtları sil
        to_delete = count - MAX_CACHE_SIZE
        cursor.execute(
            """
            DELETE FROM hibp_cache
            WHERE id IN (
                SELECT id FROM hibp_cache
                ORDER BY cached_at ASC
                LIMIT ?
            )
            """,
            (to_delete,)
        )
        deleted_old = cursor.rowcount
    else:
        deleted_old = 0
    
    conn.commit()
    conn.close()
    
    if deleted_expired > 0 or deleted_old > 0:
        logger.info(f"Cache cleanup: {deleted_expired} expired, {deleted_old} old entries removed")


def get_cache_stats() -> Dict[str, Any]:
    """Cache istatistiklerini getir"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) as total FROM hibp_cache")
    total = cursor.fetchone()["total"]
    
    cursor.execute("SELECT COUNT(*) as expired FROM hibp_cache WHERE expires_at <= datetime('now')")
    expired = cursor.fetchone()["expired"]
    
    cursor.execute("SELECT COUNT(*) as valid FROM hibp_cache WHERE expires_at > datetime('now')")
    valid = cursor.fetchone()["valid"]
    
    conn.close()
    
    return {
        "total_entries": total,
        "valid_entries": valid,
        "expired_entries": expired,
        "max_size": MAX_CACHE_SIZE,
        "ttl_days": CACHE_TTL_DAYS
    }


# Başlangıçta veritabanını başlat
init_cache_db()
