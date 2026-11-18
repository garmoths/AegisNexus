"""Shared SQLite coordination for API/worker cache, quotas and job leases."""
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path


def path():
    return Path(os.getenv('RUNTIME_DB_PATH', str(Path(__file__).resolve().parents[1] / 'data/runtime.db')))


@contextmanager
def connection():
    database = path()
    database.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(database, timeout=15, isolation_level=None)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA busy_timeout=15000')
        db.execute('CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL, expires REAL NOT NULL)')
        db.execute('CREATE INDEX IF NOT EXISTS kv_expiry ON kv(expires)')
        yield db
    finally:
        db.close()


def get(key, default=None):
    with connection() as db:
        row = db.execute('SELECT value FROM kv WHERE key=? AND expires>?', (key, time.time())).fetchone()
    return json.loads(row['value']) if row else default


def put(key, value, ttl=3600):
    with connection() as db:
        db.execute('DELETE FROM kv WHERE expires<=?', (time.time(),))
        db.execute('INSERT OR REPLACE INTO kv VALUES (?,?,?)', (key, json.dumps(value, default=str), time.time() + ttl))
    return True


def delete(key):
    with connection() as db:
        db.execute('DELETE FROM kv WHERE key=?', (key,))


def claim(key, value, ttl):
    """Atomic SET-if-absent, with an expiring lease shared across processes."""
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM kv WHERE expires<=?', (time.time(),))
        changed = db.execute('INSERT OR IGNORE INTO kv VALUES (?,?,?)', (key, json.dumps(value), time.time() + ttl)).rowcount
        db.commit()
        return bool(changed)


def increment(key, ttl=86400, limit=None):
    """Atomic bounded counter. Returns (count, accepted), without consuming rejected quota."""
    with connection() as db:
        db.execute('BEGIN IMMEDIATE')
        now = time.time()
        db.execute('DELETE FROM kv WHERE expires<=?', (now,))
        row = db.execute('SELECT value, expires FROM kv WHERE key=?', (key,)).fetchone()
        count = int(json.loads(row['value'])) if row else 0
        accepted = limit is None or count < limit
        if accepted:
            count += 1
            db.execute('INSERT OR REPLACE INTO kv VALUES (?,?,?)', (key, json.dumps(count), row['expires'] if row else now + ttl))
        db.commit()
        return count, accepted


def entries(prefix):
    with connection() as db:
        rows = db.execute('SELECT key,value FROM kv WHERE key LIKE ? AND expires>?', (prefix + '%', time.time())).fetchall()
    return {r['key']: json.loads(r['value']) for r in rows}
