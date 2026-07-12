import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parents[2]
DEFAULT_DB_PATH = BASE_DIR / "data" / "victim_atlas.db"
DB_PATH = Path(os.getenv("VICTIM_ATLAS_DB_PATH", str(DEFAULT_DB_PATH)))
_DB_INITIALIZED = False


@contextmanager
def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_database() -> None:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sources_registry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                base_url TEXT NOT NULL,
                trust_tier TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_success_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS raw_documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_id INTEGER NOT NULL,
                external_id TEXT NOT NULL,
                url TEXT NOT NULL,
                title TEXT NOT NULL,
                published_at TEXT,
                fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                raw_text TEXT NOT NULL,
                lang TEXT DEFAULT 'unknown',
                hash TEXT NOT NULL,
                FOREIGN KEY(source_id) REFERENCES sources_registry(id),
                UNIQUE(source_id, external_id),
                UNIQUE(hash)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS victim_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_slug TEXT NOT NULL UNIQUE,
                case_title TEXT NOT NULL,
                incident_period_start TEXT,
                incident_period_end TEXT,
                attack_method TEXT NOT NULL,
                loss_type TEXT NOT NULL,
                target_platform TEXT NOT NULL,
                critical_warning TEXT NOT NULL,
                narrative_summary TEXT NOT NULL,
                defense_steps_json TEXT NOT NULL,
                confidence_score INTEGER NOT NULL,
                severity_score INTEGER NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_hot INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS victim_case_evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                raw_document_id INTEGER NOT NULL,
                evidence_snippet TEXT NOT NULL,
                evidence_weight REAL NOT NULL DEFAULT 1.0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(case_id) REFERENCES victim_cases(id),
                FOREIGN KEY(raw_document_id) REFERENCES raw_documents(id),
                UNIQUE(case_id, raw_document_id)
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                status TEXT NOT NULL,
                documents_fetched INTEGER NOT NULL DEFAULT 0,
                cases_created INTEGER NOT NULL DEFAULT 0,
                cases_updated INTEGER NOT NULL DEFAULT 0,
                errors_json TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_attack_method ON victim_cases(attack_method)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_loss_type ON victim_cases(loss_type)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_last_seen ON victim_cases(last_seen)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_cases_hot ON victim_cases(is_hot)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_raw_source_published ON raw_documents(source_id, published_at)")
        conn.commit()


def ensure_initialized() -> None:
    global _DB_INITIALIZED
    if _DB_INITIALIZED:
        return
    init_database()
    _DB_INITIALIZED = True


def upsert_source(name: str, base_url: str, trust_tier: str, enabled: bool = True) -> int:
    ensure_initialized()
    now = datetime.utcnow().isoformat()
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO sources_registry (name, base_url, trust_tier, enabled, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                base_url=excluded.base_url,
                trust_tier=excluded.trust_tier,
                enabled=excluded.enabled,
                updated_at=excluded.updated_at
            """,
            (name, base_url, trust_tier, 1 if enabled else 0, now, now),
        )
        conn.commit()
        row = cur.execute("SELECT id FROM sources_registry WHERE name = ?", (name,)).fetchone()
        return int(row["id"])


def mark_source_success(source_id: int) -> None:
    now = datetime.utcnow().isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE sources_registry
            SET last_success_at = ?, last_error = NULL, updated_at = ?
            WHERE id = ?
            """,
            (now, now, source_id),
        )
        conn.commit()


def mark_source_error(source_id: int, message: str) -> None:
    now = datetime.utcnow().isoformat()
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE sources_registry
            SET last_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (message[:500], now, source_id),
        )
        conn.commit()


def start_ingest_run() -> int:
    ensure_initialized()
    started = datetime.utcnow().isoformat()
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO ingest_runs (started_at, status) VALUES (?, ?)",
            (started, "running"),
        )
        conn.commit()
        return int(cur.lastrowid)


def finish_ingest_run(
    run_id: int,
    status: str,
    documents_fetched: int,
    cases_created: int,
    cases_updated: int,
    errors: Dict[str, Any],
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            UPDATE ingest_runs
            SET finished_at = ?, status = ?, documents_fetched = ?, cases_created = ?,
                cases_updated = ?, errors_json = ?
            WHERE id = ?
            """,
            (
                datetime.utcnow().isoformat(),
                status,
                int(documents_fetched),
                int(cases_created),
                int(cases_updated),
                json.dumps(errors, ensure_ascii=True),
                run_id,
            ),
        )
        conn.commit()


def upsert_raw_document(
    source_id: int,
    external_id: str,
    url: str,
    title: str,
    published_at: Optional[str],
    raw_text: str,
    lang: str,
    doc_hash: str,
) -> Tuple[Optional[int], bool]:
    ensure_initialized()
    with get_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO raw_documents (
                    source_id, external_id, url, title, published_at, raw_text, lang, hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (source_id, external_id, url, title, published_at, raw_text, lang, doc_hash),
            )
            conn.commit()
            return int(cur.lastrowid), True
        except sqlite3.IntegrityError:
            row = cur.execute(
                """
                SELECT id FROM raw_documents
                WHERE source_id = ? AND external_id = ?
                """,
                (source_id, external_id),
            ).fetchone()
            if not row:
                row = cur.execute(
                    "SELECT id FROM raw_documents WHERE hash = ?",
                    (doc_hash,),
                ).fetchone()
            return (int(row["id"]) if row else None), False


def upsert_case(case: Dict[str, Any]) -> Tuple[int, bool]:
    ensure_initialized()
    now = datetime.utcnow().isoformat()
    with get_connection() as conn:
        cur = conn.cursor()
        row = cur.execute(
            "SELECT id FROM victim_cases WHERE case_slug = ?",
            (case["case_slug"],),
        ).fetchone()

        if row:
            case_id = int(row["id"])
            cur.execute(
                """
                UPDATE victim_cases
                SET case_title = ?, incident_period_start = ?, incident_period_end = ?,
                    attack_method = ?, loss_type = ?, target_platform = ?,
                    critical_warning = ?, narrative_summary = ?, defense_steps_json = ?,
                    confidence_score = ?, severity_score = ?, last_seen = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    case["case_title"],
                    case.get("incident_period_start"),
                    case.get("incident_period_end"),
                    case["attack_method"],
                    case["loss_type"],
                    case["target_platform"],
                    case["critical_warning"],
                    case["narrative_summary"],
                    json.dumps(case["defense_steps"], ensure_ascii=True),
                    int(case["confidence_score"]),
                    int(case["severity_score"]),
                    case["last_seen"],
                    now,
                    case_id,
                ),
            )
            conn.commit()
            return case_id, False

        cur.execute(
            """
            INSERT INTO victim_cases (
                case_slug, case_title, incident_period_start, incident_period_end,
                attack_method, loss_type, target_platform, critical_warning, narrative_summary,
                defense_steps_json, confidence_score, severity_score, first_seen, last_seen,
                is_hot, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case["case_slug"],
                case["case_title"],
                case.get("incident_period_start"),
                case.get("incident_period_end"),
                case["attack_method"],
                case["loss_type"],
                case["target_platform"],
                case["critical_warning"],
                case["narrative_summary"],
                json.dumps(case["defense_steps"], ensure_ascii=True),
                int(case["confidence_score"]),
                int(case["severity_score"]),
                case["first_seen"],
                case["last_seen"],
                1,
                now,
                now,
            ),
        )
        conn.commit()
        return int(cur.lastrowid), True


def add_case_evidence(case_id: int, raw_document_id: int, snippet: str, evidence_weight: float = 1.0) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO victim_case_evidence (case_id, raw_document_id, evidence_snippet, evidence_weight)
            VALUES (?, ?, ?, ?)
            """,
            (case_id, raw_document_id, snippet[:500], float(evidence_weight)),
        )
        conn.commit()


def prune_hot_set(limit: int = 1000) -> Dict[str, int]:
    ensure_initialized()
    safe_limit = max(1, int(limit))
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE victim_cases SET is_hot = 0")
        cur.execute(
            """
            UPDATE victim_cases
            SET is_hot = 1
            WHERE id IN (
                SELECT id FROM victim_cases
                ORDER BY confidence_score DESC, severity_score DESC, last_seen DESC, id DESC
                LIMIT ?
            )
            """,
            (safe_limit,),
        )
        conn.commit()
        hot = cur.execute("SELECT COUNT(*) AS c FROM victim_cases WHERE is_hot = 1").fetchone()["c"]
        total = cur.execute("SELECT COUNT(*) AS c FROM victim_cases").fetchone()["c"]
        return {"hot_count": int(hot), "total_cases": int(total)}


def get_cases(
    page: int = 1,
    limit: int = 20,
    attack_method: Optional[str] = None,
    loss_type: Optional[str] = None,
    severity_min: int = 0,
    confidence_min: int = 60,
    q: Optional[str] = None,
    hot_set_only: bool = True,
) -> Dict[str, Any]:
    ensure_initialized()
    page = max(1, int(page))
    limit = max(1, min(int(limit), 100))
    offset = (page - 1) * limit

    where = ["confidence_score >= ?", "severity_score >= ?"]
    params: list[Any] = [int(confidence_min), int(severity_min)]

    if hot_set_only:
        where.append("is_hot = 1")
    if attack_method:
        where.append("attack_method = ?")
        params.append(attack_method)
    if loss_type:
        where.append("loss_type = ?")
        params.append(loss_type)
    if q:
        where.append("(case_title LIKE ? OR narrative_summary LIKE ? OR critical_warning LIKE ?)")
        wildcard = f"%{q.strip()}%"
        params.extend([wildcard, wildcard, wildcard])

    where_sql = " AND ".join(where)
    with get_connection() as conn:
        cur = conn.cursor()
        total = cur.execute(
            f"SELECT COUNT(*) AS c FROM victim_cases WHERE {where_sql}",
            tuple(params),
        ).fetchone()["c"]
        rows = cur.execute(
            f"""
            SELECT id, case_slug, case_title, incident_period_start, incident_period_end,
                   attack_method, loss_type, target_platform, critical_warning,
                   confidence_score, severity_score, first_seen, last_seen
            FROM victim_cases
            WHERE {where_sql}
            ORDER BY confidence_score DESC, severity_score DESC, last_seen DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params + [limit, offset]),
        ).fetchall()

    data = []
    for row in rows:
        data.append({k: row[k] for k in row.keys()})
    total_pages = (int(total) + limit - 1) // limit if total else 0
    return {
        "data": data,
        "page": page,
        "limit": limit,
        "total": int(total),
        "total_pages": total_pages,
    }


def get_case(case_id: int) -> Optional[Dict[str, Any]]:
    ensure_initialized()
    with get_connection() as conn:
        cur = conn.cursor()
        row = cur.execute(
            """
            SELECT id, case_slug, case_title, incident_period_start, incident_period_end,
                   attack_method, loss_type, target_platform, critical_warning,
                   narrative_summary, defense_steps_json, confidence_score, severity_score,
                   first_seen, last_seen
            FROM victim_cases
            WHERE id = ?
            """,
            (int(case_id),),
        ).fetchone()
        if not row:
            return None

        evidence = cur.execute(
            """
            SELECT r.url, r.title, r.published_at, e.evidence_snippet, e.evidence_weight
            FROM victim_case_evidence e
            JOIN raw_documents r ON r.id = e.raw_document_id
            WHERE e.case_id = ?
            ORDER BY e.id DESC
            LIMIT 10
            """,
            (int(case_id),),
        ).fetchall()

    payload = {k: row[k] for k in row.keys()}
    payload["defense_steps"] = json.loads(payload.pop("defense_steps_json") or "[]")
    payload["evidence"] = [{k: item[k] for k in item.keys()} for item in evidence]
    return payload


def get_stats() -> Dict[str, Any]:
    ensure_initialized()
    with get_connection() as conn:
        cur = conn.cursor()
        total_cases = cur.execute("SELECT COUNT(*) AS c FROM victim_cases").fetchone()["c"]
        hot_cases = cur.execute("SELECT COUNT(*) AS c FROM victim_cases WHERE is_hot = 1").fetchone()["c"]
        high_conf = cur.execute(
            "SELECT COUNT(*) AS c FROM victim_cases WHERE confidence_score >= 80"
        ).fetchone()["c"]
        by_method_rows = cur.execute(
            """
            SELECT attack_method, COUNT(*) AS c
            FROM victim_cases
            GROUP BY attack_method
            ORDER BY c DESC
            """
        ).fetchall()
        by_loss_rows = cur.execute(
            """
            SELECT loss_type, COUNT(*) AS c
            FROM victim_cases
            GROUP BY loss_type
            ORDER BY c DESC
            """
        ).fetchall()

    return {
        "total_cases": int(total_cases),
        "hot_cases": int(hot_cases),
        "high_confidence_cases": int(high_conf),
        "attack_method_distribution": {r["attack_method"]: int(r["c"]) for r in by_method_rows},
        "loss_type_distribution": {r["loss_type"]: int(r["c"]) for r in by_loss_rows},
    }


def get_ingest_health() -> Dict[str, Any]:
    ensure_initialized()
    with get_connection() as conn:
        cur = conn.cursor()
        last_run = cur.execute(
            """
            SELECT id, started_at, finished_at, status, documents_fetched, cases_created, cases_updated, errors_json
            FROM ingest_runs
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        sources = cur.execute(
            """
            SELECT name, trust_tier, enabled, last_success_at, last_error
            FROM sources_registry
            ORDER BY name ASC
            """
        ).fetchall()

    run_payload = None
    if last_run:
        run_payload = {k: last_run[k] for k in last_run.keys()}
        run_payload["errors"] = json.loads(run_payload.pop("errors_json") or "{}")
    return {
        "last_run": run_payload,
        "sources": [{k: row[k] for k in row.keys()} for row in sources],
    }
