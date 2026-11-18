"""Tek veritabanı: SQLite (varsayılan data/aegis.db).

Tüm uygulama verisi ve tarayıcı önbelleği bu dosyada tutulur; şema app/models.py'de,
sürüm geçmişi alembic/versions altındadır. Kısa ömürlü önbellek ve iş kilitleri ayrı
bir dosyada (app/runtime_store.py → data/runtime.db) durur.
"""
import pathlib

from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import get_settings

SQLALCHEMY_DATABASE_URL = get_settings().database_url

DB_FILE = pathlib.Path(SQLALCHEMY_DATABASE_URL.replace('sqlite:///', '', 1)).resolve()
DB_FILE.parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={'check_same_thread': False, 'timeout': 30})


@event.listens_for(engine, 'connect')
def sqlite_pragmas(connection, _):
    connection.execute('PRAGMA foreign_keys=ON')
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('PRAGMA busy_timeout=30000')
    connection.execute('PRAGMA synchronous=NORMAL')


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    """FastAPI dependency — DB session yield eder."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
