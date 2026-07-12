"""
Import PostgreSQL COPY-format dump into SQLite (data/aegis.db).

Usage:
  python scripts/import_pg_dump.py                          # uses backup.sql.gz
  python scripts/import_pg_dump.py /path/to/dump.sql.gz     # custom path
"""

import gzip
import re
import sqlite3
import sys
from pathlib import Path

DEFAULT_DUMP = Path(__file__).resolve().parent.parent / "backup.sql.gz"
FALLBACK_PARTS = list((Path(__file__).resolve().parent.parent).glob("backup.sql.gz.part.*"))
DB_PATH = Path(__file__).resolve().parent.parent / "data" / "aegis.db"

TABLES_TO_IMPORT = {
    "phishing_urls",
    "indicators_of_compromise",
    "victim_cases",
    "raw_documents",
    "fraud_profiles",
    "honeypot_events",
}

def convert_value(val, col_name):
    if val is None:
        return None
    if col_name in ("id", "source_id", "case_count", "detection_count", "risk_score", "severity_score", "confidence_score"):
        try:
            return int(val)
        except (ValueError, TypeError):
            return None
    if col_name in ("confidence", "avg_loss_try"):
        try:
            return float(val)
        except (ValueError, TypeError):
            return None
    if col_name in ("is_static", "is_hot", "is_published", "is_monitored", "online", "operator_alert_sent"):
        return 1 if val.lower() in ("t", "true", "1") else 0
    return val

def open_dump(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")

def find_dump():
    if len(sys.argv) > 1:
        return Path(sys.argv[1])
    if DEFAULT_DUMP.exists():
        return DEFAULT_DUMP
    if FALLBACK_PARTS:
        import subprocess
        import tempfile
        combined = Path(tempfile.mktemp(suffix=".sql.gz"))
        parts = sorted(FALLBACK_PARTS)
        print(f"Reassembling {len(parts)} backup parts...")
        with combined.open("wb") as out:
            for p in parts:
                out.write(p.read_bytes())
        print(f"Reassembled to {combined}")
        return combined
    return None

def main():
    dump_path = find_dump()
    if dump_path is None or not dump_path.exists():
        print("Error: No backup found. Run ./scripts/restore_backup.sh or place")
        print("  backup.sql.gz or backup.sql.gz.part.* in the repo root.")
        sys.exit(1)

    print(f"Reading dump: {dump_path}")
    print(f"Target DB: {DB_PATH}")

    with open_dump(dump_path) as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith("COPY public."):
            i += 1
            continue

        table = line.split()[1].replace("public.", "")
        if table not in TABLES_TO_IMPORT:
            i += 1
            continue

        col_match = re.search(r"\((.*)\)", line)
        columns = [c.strip() for c in col_match.group(1).split(",")]

        i += 1
        rows = []
        while i < len(lines):
            data_line = lines[i].rstrip("\n")
            i += 1
            if data_line == "\\.":
                break
            if data_line == "":
                continue
            values = [None if f == "\\N" else f for f in data_line.split("\t")]
            converted = [convert_value(v, columns[j]) for j, v in enumerate(values)]
            rows.append(tuple(converted))

        print(f"Importing {table}: {len(rows)} rows...")

        conn = sqlite3.connect(str(DB_PATH))
        conn.execute("PRAGMA journal_mode=OFF")
        conn.execute("PRAGMA synchronous=OFF")
        conn.execute("PRAGMA cache_size=-400000")

        placeholders = ",".join(["?" for _ in columns])
        col_names = ",".join(columns)
        sql = f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})"

        batch_size = 50000
        for start in range(0, len(rows), batch_size):
            batch = rows[start : start + batch_size]
            conn.executemany(sql, batch)
            conn.commit()
            print(f"  {table}: {start + len(batch)}/{len(rows)}")

        conn.close()

    print("All imports complete!")

if __name__ == "__main__":
    main()
