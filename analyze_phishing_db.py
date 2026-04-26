#!/usr/bin/env python3
"""Analyze phishing database"""
import sqlite3
import json

DB_PATH = "/var/www/aegis_nexus/threat_intel_cache.db"

def analyze_db():
    """Database kayıtlarını analiz et"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Toplam kayıt sayısı
        cursor.execute("SELECT COUNT(*) as total FROM phishing_urls")
        total = cursor.fetchone()[0]
        print(f"Total records: {total}")
        
        # Sources durumları
        cursor.execute("""
            SELECT 
                CASE 
                    WHEN sources IS NULL THEN 'NULL'
                    WHEN sources = '[]' THEN 'Empty Array'
                    ELSE 'Has Sources'
                END as source_status,
                COUNT(*) as count
            FROM phishing_urls
            GROUP BY source_status
        """)
        print("\nSources status:")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]}")
        
        # Risk score dağılımı
        cursor.execute("""
            SELECT risk_score, COUNT(*) as count
            FROM phishing_urls
            GROUP BY risk_score
            ORDER BY risk_score
        """)
        print("\nRisk score distribution:")
        for row in cursor.fetchall():
            print(f"  {row[0]}: {row[1]}")
        
        # Son 5 kayıt örnek
        cursor.execute("""
            SELECT url, domain, risk_score, sources, checked_at
            FROM phishing_urls
            ORDER BY checked_at DESC
            LIMIT 5
        """)
        print("\nLast 5 records:")
        for row in cursor.fetchall():
            print(f"  URL: {row[0][:50]}...")
            print(f"  Domain: {row[1]}")
            print(f"  Risk: {row[2]}")
            print(f"  Sources: {row[3][:50] if row[3] else 'None'}...")
            print(f"  Checked: {row[4]}")
            print()
        
        conn.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    analyze_db()
