"""
Çok kaynaklı phishing URL ingest — akış (stream) ve toplu INSERT.
Bellekte tüm veritabanını tutmaz; url_hash ile çakışma yoksayılır (PostgreSQL).
"""
from __future__ import annotations

import sys
import os
import time
from datetime import datetime, timezone
import requests
from sqlalchemy.dialects.postgresql import insert as pg_insert

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from app.database import SessionLocal, engine
from app import models
from app.url_normalize import normalize_url_record

# --- Beslemeler (Phishing.Database + abuse.ch + OpenPhish) ---
PHISHING_DB_SOURCES = {
    "phishing_db_links_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "phishing_db_domains_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "phishing_db_links_active_now": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt",
    "phishing_db_links_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
    "phishing_db_domains_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-NEW-today.txt",
    "phishing_db_ips_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-IPs-ACTIVE.txt",
    "urlhaus_online": "https://urlhaus.abuse.ch/downloads/text_online/",
    "openphish": "https://openphish.com/feed.txt",
}

BATCH_SIZE = 10_000
REQUEST_TIMEOUT = 180


def iter_feed_lines(url: str):
    """Büyük dosyaları tek seferde RAM'e almadan satır satır okur."""
    with requests.get(url, stream=True, timeout=REQUEST_TIMEOUT) as r:
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        for raw in r.iter_lines(decode_unicode=True):
            if not raw:
                continue
            line = raw.strip()
            if line and not line.startswith("#") and not line.startswith("//"):
                yield line


def _dedupe_rows(rows: list[dict]) -> list[dict]:
    return list({r["url_hash"]: r for r in rows}.values())


def _flush_postgres(db, rows: list[dict]) -> int:
    if not rows:
        return 0
    rows = _dedupe_rows(rows)
    stmt = pg_insert(models.PhishingURL).values(rows)
    stmt = stmt.on_conflict_do_nothing(index_elements=["url_hash"])
    res = db.execute(stmt)
    db.commit()
    return res.rowcount or 0


def _flush_sqlite(db, rows: list[dict]) -> int:
    """SQLite: küçük partlarda var olan hash'leri sorgula, sonra toplu ekle."""
    if not rows:
        return 0
    rows = _dedupe_rows(rows)
    hashes = [r["url_hash"] for r in rows]
    existing = {
        x[0]
        for x in db.query(models.PhishingURL.url_hash)
        .filter(models.PhishingURL.url_hash.in_(hashes))
        .all()
    }
    fresh = [r for r in rows if r["url_hash"] not in existing]
    if not fresh:
        return 0
    db.bulk_save_objects([models.PhishingURL(**r) for r in fresh])
    db.commit()
    return len(fresh)


def ingest_stream(name: str, url: str, source_tag: str) -> int:
    dialect = engine.dialect.name
    added = 0
    batch: list[dict] = []
    db = SessionLocal()
    models.Base.metadata.create_all(bind=engine)
    try:
        flush = _flush_postgres if dialect == "postgresql" else _flush_sqlite
        for line in iter_feed_lines(url):
            canon, uh, dn = normalize_url_record(line)
            if not uh or not canon:
                continue
            batch.append(
                {
                    "phish_id": "S" + uh[:20],
                    "url": canon,
                    "url_hash": uh,
                    "domain_norm": dn,
                    "status": "active",
                    "online": True,
                    "target": f"{source_tag}:{name}",
                    "submission_time": datetime.now(timezone.utc),
                }
            )
            if len(batch) >= BATCH_SIZE:
                added += flush(db, batch)
                batch = []
        if batch:
            added += flush(db, batch)
        return added
    except Exception as e:
        print(f"   [{name}] ingest hatası: {e}")
        db.rollback()
        return added
    finally:
        db.close()


def verileri_guncelle() -> int:
    print(f"\n{'=' * 60}")
    print(f"Güncelleme: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 60}")

    total_added = 0
    for name, url in PHISHING_DB_SOURCES.items():
        print(f"\n--- {name} ---")
        try:
            total_added += ingest_stream(name, url, "Phishing.DB")
        except Exception as e:
            print(f"   Kaynak atlandı: {e}")

    print(f"\n{'=' * 60}")
    print(f"Bu çalışmada eklenen satır (yaklaşım): {total_added:,}")
    print(f"{'=' * 60}\n")
    return total_added


if __name__ == "__main__":
    SAAT = 4
    print("Feed ingest döngüsü (Ctrl+C ile çık)")
    while True:
        verileri_guncelle()
        print(f"Bekleniyor: {SAAT} saat\n")
        time.sleep(SAAT * 3600)
