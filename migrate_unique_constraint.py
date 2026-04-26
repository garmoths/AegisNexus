#!/usr/bin/env python3
"""Migrate database to add UNIQUE constraint and clean duplicates"""
import sqlite3

DB_PATH = "/var/www/aegis_nexus/threat_intel_cache.db"

def migrate_and_cleanup():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 1. Mevcut duplicate'leri temizle (en güncel olanı tut)
        cursor.execute("""
            DELETE FROM url_scan_events
            WHERE id NOT IN (
                SELECT MIN(id)
                FROM url_scan_events
                GROUP BY url
            )
        """)
        deleted = cursor.rowcount
        print(f"Deleted {deleted} duplicate url_scan_events records")
        
        # 2. Tabloyu yeniden oluştur (UNIQUE constraint eklemek için)
        cursor.execute("""
            CREATE TABLE url_scan_events_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL UNIQUE,
                domain TEXT NOT NULL,
                risk_score INTEGER DEFAULT 0,
                risk_level TEXT DEFAULT 'unknown',
                is_safe BOOLEAN DEFAULT FALSE,
                sources TEXT,
                checked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # 3. Verileri kopyala
        cursor.execute("""
            INSERT INTO url_scan_events_new (url, domain, risk_score, risk_level, is_safe, sources, checked_at)
            SELECT url, domain, risk_score, risk_level, is_safe, sources, checked_at
            FROM url_scan_events
        """)
        
        # 4. Eski tabloyu sil
        cursor.execute("DROP TABLE url_scan_events")
        
        # 5. Yeni tabloyu yeniden adlandır
        cursor.execute("ALTER TABLE url_scan_events_new RENAME TO url_scan_events")
        
        # 6. Index'leri yeniden oluştur
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_checked_at ON url_scan_events(checked_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_events_domain ON url_scan_events(domain)")
        
        conn.commit()
        conn.close()
        
        print("Migration completed successfully")
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    migrate_and_cleanup()
