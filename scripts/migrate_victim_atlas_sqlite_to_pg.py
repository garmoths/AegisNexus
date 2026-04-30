#!/usr/bin/env python3
"""
Victim Atlas: SQLite → PostgreSQL veri taşıma script'i.

Kullanım:
    python scripts/migrate_victim_atlas_sqlite_to_pg.py [--sqlite-path PATH]

Varsayılan SQLite yolu: data/victim_atlas.db (proje kökünden göreceli)
PG bağlantısı: .env dosyasındaki DATABASE_URL kullanılır.
"""
import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

# Proje kökünü sys.path'e ekle
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.database import SessionLocal
from app.models import (
    IngestRun,
    RawDocument,
    SourceRegistry,
    VictimCase,
    VictimCaseEvidence,
)


def _parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None


def migrate_sources(sqlite_conn, pg_session):
    rows = sqlite_conn.execute("SELECT * FROM sources_registry").fetchall()
    cols = [d[0] for d in sqlite_conn.description]
    count = 0
    for row in rows:
        data = dict(zip(cols, row))
        existing = pg_session.query(SourceRegistry).filter_by(name=data["name"]).first()
        if existing:
            continue
        src = SourceRegistry(
            name=data["name"],
            base_url=data["base_url"],
            trust_tier=data["trust_tier"],
            enabled=bool(data.get("enabled", 1)),
            last_success_at=_parse_dt(data.get("last_success_at")),
            last_error=data.get("last_error"),
            created_at=_parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
            updated_at=_parse_dt(data.get("updated_at")) or datetime.now(timezone.utc),
        )
        pg_session.add(src)
        count += 1
    pg_session.commit()
    print(f"  sources_registry: {count} yeni kayıt taşındı")
    # ID mapping için tüm kaynakları döndür
    return {s.name: s.id for s in pg_session.query(SourceRegistry).all()}


def migrate_raw_documents(sqlite_conn, pg_session, source_id_map):
    rows = sqlite_conn.execute("SELECT * FROM raw_documents").fetchall()
    cols = [d[0] for d in sqlite_conn.description]
    count = 0
    id_map = {}  # sqlite_id → pg_id
    for row in rows:
        data = dict(zip(cols, row))
        existing = pg_session.query(RawDocument).filter_by(hash=data["hash"]).first()
        if existing:
            id_map[data["id"]] = existing.id
            continue
        doc = RawDocument(
            source_id=source_id_map.get(data["source_id"], data["source_id"]),
            external_id=data["external_id"],
            url=data["url"],
            title=data["title"],
            published_at=_parse_dt(data.get("published_at")),
            fetched_at=_parse_dt(data.get("fetched_at")) or datetime.now(timezone.utc),
            raw_text=data["raw_text"],
            lang=data.get("lang", "unknown"),
            hash=data["hash"],
        )
        pg_session.add(doc)
        pg_session.flush()
        id_map[data["id"]] = doc.id
        count += 1
    pg_session.commit()
    print(f"  raw_documents: {count} yeni kayıt taşındı")
    return id_map


def migrate_cases(sqlite_conn, pg_session):
    rows = sqlite_conn.execute("SELECT * FROM victim_cases").fetchall()
    cols = [d[0] for d in sqlite_conn.description]
    count = 0
    id_map = {}  # sqlite_id → pg_id
    for row in rows:
        data = dict(zip(cols, row))
        existing = pg_session.query(VictimCase).filter_by(case_slug=data["case_slug"]).first()
        if existing:
            id_map[data["id"]] = existing.id
            continue
        defense_steps = data.get("defense_steps_json", "[]")
        if isinstance(defense_steps, str):
            try:
                defense_steps = json.loads(defense_steps)
            except json.JSONDecodeError:
                defense_steps = []
        case = VictimCase(
            case_slug=data["case_slug"],
            case_title=data["case_title"],
            incident_period_start=_parse_dt(data.get("incident_period_start")),
            incident_period_end=_parse_dt(data.get("incident_period_end")),
            attack_method=data["attack_method"],
            loss_type=data["loss_type"],
            target_platform=data["target_platform"],
            critical_warning=data["critical_warning"],
            narrative_summary=data["narrative_summary"],
            defense_steps_json=defense_steps,
            confidence_score=int(data["confidence_score"]),
            severity_score=int(data["severity_score"]),
            first_seen=_parse_dt(data["first_seen"]) or datetime.now(timezone.utc),
            last_seen=_parse_dt(data["last_seen"]) or datetime.now(timezone.utc),
            is_hot=bool(data.get("is_hot", 1)),
            created_at=_parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
            updated_at=_parse_dt(data.get("updated_at")) or datetime.now(timezone.utc),
        )
        pg_session.add(case)
        pg_session.flush()
        id_map[data["id"]] = case.id
        count += 1
    pg_session.commit()
    print(f"  victim_cases: {count} yeni kayıt taşındı")
    return id_map


def migrate_evidence(sqlite_conn, pg_session, case_id_map, doc_id_map):
    rows = sqlite_conn.execute("SELECT * FROM victim_case_evidence").fetchall()
    cols = [d[0] for d in sqlite_conn.description]
    count = 0
    for row in rows:
        data = dict(zip(cols, row))
        pg_case_id = case_id_map.get(data["case_id"])
        pg_doc_id = doc_id_map.get(data["raw_document_id"])
        if not pg_case_id or not pg_doc_id:
            continue
        existing = pg_session.query(VictimCaseEvidence).filter_by(
            case_id=pg_case_id, raw_document_id=pg_doc_id
        ).first()
        if existing:
            continue
        ev = VictimCaseEvidence(
            case_id=pg_case_id,
            raw_document_id=pg_doc_id,
            evidence_snippet=data["evidence_snippet"],
            evidence_weight=float(data.get("evidence_weight", 1.0)),
            created_at=_parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
        )
        pg_session.add(ev)
        count += 1
    pg_session.commit()
    print(f"  victim_case_evidence: {count} yeni kayıt taşındı")


def migrate_ingest_runs(sqlite_conn, pg_session):
    rows = sqlite_conn.execute("SELECT * FROM ingest_runs").fetchall()
    cols = [d[0] for d in sqlite_conn.description]
    count = 0
    for row in rows:
        data = dict(zip(cols, row))
        errors = data.get("errors_json")
        if isinstance(errors, str):
            try:
                errors = json.loads(errors)
            except json.JSONDecodeError:
                errors = {}
        run = IngestRun(
            started_at=_parse_dt(data["started_at"]) or datetime.now(timezone.utc),
            finished_at=_parse_dt(data.get("finished_at")),
            status=data["status"],
            documents_fetched=int(data.get("documents_fetched", 0)),
            cases_created=int(data.get("cases_created", 0)),
            cases_updated=int(data.get("cases_updated", 0)),
            errors_json=errors,
            created_at=_parse_dt(data.get("created_at")) or datetime.now(timezone.utc),
        )
        pg_session.add(run)
        count += 1
    pg_session.commit()
    print(f"  ingest_runs: {count} kayıt taşındı")


def main():
    parser = argparse.ArgumentParser(description="Victim Atlas SQLite → PG taşıma")
    parser.add_argument("--sqlite-path", default=str(PROJECT_ROOT / "data" / "victim_atlas.db"),
                        help="SQLite veritabanı yolu")
    args = parser.parse_args()

    sqlite_path = Path(args.sqlite_path)
    if not sqlite_path.exists():
        print(f"SQLite dosyası bulunamadı: {sqlite_path}")
        print("Taşınacak veri yok, çıkılıyor.")
        return

    print(f"SQLite: {sqlite_path}")
    print("PostgreSQL: DATABASE_URL from .env")
    print()

    sqlite_conn = sqlite3.connect(str(sqlite_path))
    sqlite_conn.row_factory = sqlite3.Row

    pg_session = SessionLocal()

    try:
        print("1/5 — sources_registry")
        source_id_map = migrate_sources(sqlite_conn, pg_session)

        print("2/5 — raw_documents")
        doc_id_map = migrate_raw_documents(sqlite_conn, pg_session, source_id_map)

        print("3/5 — victim_cases")
        case_id_map = migrate_cases(sqlite_conn, pg_session)

        print("4/5 — victim_case_evidence")
        migrate_evidence(sqlite_conn, pg_session, case_id_map, doc_id_map)

        print("5/5 — ingest_runs")
        migrate_ingest_runs(sqlite_conn, pg_session)

        print("\nTaşıma tamamlandı!")
    except Exception as e:
        print(f"\nHata: {e}")
        pg_session.rollback()
        raise
    finally:
        sqlite_conn.close()
        pg_session.close()


if __name__ == "__main__":
    main()
