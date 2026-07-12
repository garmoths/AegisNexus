"""Mevcut PostgreSQL veritabanındaki tabloları listele.

Sunucuda çalıştır:
    python scripts/check_db_tables.py
"""
import os
import sys
from dotenv import load_dotenv

load_dotenv()

DB_URL = os.getenv("VICTIM_ATLAS_DATABASE_URL") or os.getenv("DATABASE_URL")

if not DB_URL:
    print("❌ DATABASE_URL bulunamadı. .env dosyasını kontrol et.")
    sys.exit(1)

print(f"📡 Bağlanıyor: {DB_URL[:40]}...")

try:
    from sqlalchemy import create_engine, text, inspect

    engine = create_engine(DB_URL)
    inspector = inspect(engine)

    tables = inspector.get_table_names()
    print(f"\n✅ Bağlantı başarılı — {len(tables)} tablo bulundu:\n")

    # Kategorilere ayır
    victim_atlas_tables = []
    auth_tables = []
    phishing_tables = []
    other_tables = []

    for t in sorted(tables):
        if t.startswith("victim_") or t in ("source_registry", "ingest_run", "case_tags", "evidence", "alert_subscriptions", "subscriptions", "user_reports"):
            victim_atlas_tables.append(t)
        elif t in ("users", "api_keys", "user_roles") or t.startswith("auth_"):
            auth_tables.append(t)
        elif "phishing" in t or "ioc" in t or "threat" in t or "url" in t:
            phishing_tables.append(t)
        else:
            other_tables.append(t)

    if phishing_tables:
        print("🔴 Mevcut Phishing/IOC Tabloları:")
        for t in phishing_tables:
            cols = [c["name"] for c in inspector.get_columns(t)]
            count = 0
            try:
                with engine.connect() as conn:
                    result = conn.execute(text(f'SELECT COUNT(*) FROM "{t}"'))
                    count = result.scalar()
            except Exception:
                pass
            print(f"   {t} ({count} satır, {len(cols)} kolon)")
        print()

    if victim_atlas_tables:
        print("🟢 Victim Atlas Tabloları (zaten var):")
        for t in victim_atlas_tables:
            count = 0
            try:
                with engine.connect() as conn:
                    result = conn.execute(text(f'SELECT COUNT(*) FROM "{t}"'))
                    count = result.scalar()
            except Exception:
                pass
            print(f"   {t} ({count} satır)")
        print()

    if auth_tables:
        print("🔵 Auth Tabloları:")
        for t in auth_tables:
            count = 0
            try:
                with engine.connect() as conn:
                    result = conn.execute(text(f'SELECT COUNT(*) FROM "{t}"'))
                    count = result.scalar()
            except Exception:
                pass
            print(f"   {t} ({count} satır)")
        print()

    if other_tables:
        print("⚪ Diğer Tablolar:")
        for t in other_tables:
            count = 0
            try:
                with engine.connect() as conn:
                    result = conn.execute(text(f'SELECT COUNT(*) FROM "{t}"'))
                    count = result.scalar()
            except Exception:
                pass
            print(f"   {t} ({count} satır)")
        print()

    # Victim Atlas tabloları eksik mi?
    required = {"victim_cases", "users", "api_keys", "user_reports", "subscriptions", "alert_subscriptions", "case_tags", "evidence", "source_registry", "ingest_run"}
    missing = required - set(tables)
    if missing:
        print(f"⚠️ Eksik tablolar: {', '.join(sorted(missing))}")
        print("   → 'alembic upgrade head' çalıştırarak oluşturabilirsin.")
    else:
        print("✅ Tüm Victim Atlas tabloları mevcut!")

except Exception as e:
    print(f"❌ Hata: {e}")
    print("\nSunucuda PostgreSQL çalıştığından emin ol:")
    print("  sudo systemctl status postgresql")
