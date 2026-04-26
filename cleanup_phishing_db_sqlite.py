#!/usr/bin/env python3
"""Direct SQLite cleanup script"""
import sqlite3
from datetime import datetime, timedelta

DB_PATH = "/var/www/aegis_nexus/threat_intel_cache.db"

def cleanup_empty_records():
    """Kaynak bilgisi olmayan kayıtları temizle"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cutoff_date = datetime.now() - timedelta(days=30)
        
        # Önce silinecek kayıtları görüntüle
        cursor.execute("""
            SELECT COUNT(*) as count FROM phishing_urls
            WHERE (sources = '[]' OR sources IS NULL)
            AND checked_at >= ?
        """, (cutoff_date.isoformat(),))
        count = cursor.fetchone()[0]
        print(f"Found {count} empty source records to clean up")
        
        # Kayıtları sil
        cursor.execute("""
            DELETE FROM phishing_urls
            WHERE (sources = '[]' OR sources IS NULL)
            AND checked_at >= ?
        """, (cutoff_date.isoformat(),))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        print(f"Cleaned up {deleted} empty source phishing records")
        return deleted
        
    except Exception as e:
        print(f"Error: {e}")
        return 0

if __name__ == "__main__":
    cleanup_empty_records()
