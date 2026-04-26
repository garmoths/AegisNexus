#!/usr/bin/env python3
"""List all URLs in phishing database"""
import sqlite3

DB_PATH = "/var/www/aegis_nexus/threat_intel_cache.db"

def list_all_urls():
    """Tüm URL'leri listele"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, url, domain, risk_score, risk_level, is_safe, sources, checked_at
            FROM phishing_urls
            ORDER BY checked_at DESC
        """)
        
        print("All phishing URLs in database:")
        print("=" * 100)
        for row in cursor.fetchall():
            print(f"ID: {row[0]}")
            print(f"URL: {row[1]}")
            print(f"Domain: {row[2]}")
            print(f"Risk Score: {row[3]}")
            print(f"Risk Level: {row[4]}")
            print(f"Is Safe: {row[5]}")
            print(f"Sources: {row[6]}")
            print(f"Checked At: {row[7]}")
            print("-" * 100)
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    list_all_urls()
