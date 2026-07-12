from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Veritabanı bağlantı adresi
# Öncelik: VICTIM_ATLAS_DATABASE_URL → DATABASE_URL → SQLite fallback (kişisel proje)
SQLALCHEMY_DATABASE_URL = os.getenv(
    "VICTIM_ATLAS_DATABASE_URL",
    os.getenv("DATABASE_URL", "sqlite:///./data/aegis.db"),
)

_is_sqlite = SQLALCHEMY_DATABASE_URL.startswith("sqlite")

if _is_sqlite:
    # SQLite: pool parametreleri desteklenmez, thread paylaşımı için check_same_thread=False
    import pathlib
    # SQLite dosyasının dizininin var olduğundan emin ol
    if SQLALCHEMY_DATABASE_URL.startswith("sqlite:///"):
        db_file = SQLALCHEMY_DATABASE_URL.replace("sqlite:///", "", 1)
        if db_file and db_file != ":memory:":
            pathlib.Path(db_file).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        connect_args={"check_same_thread": False},
    )
else:
    _pool_size = int(os.getenv("DB_POOL_SIZE", "5"))
    _max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "2"))
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL,
        pool_pre_ping=True,
        pool_size=_pool_size,
        max_overflow=_max_overflow,
    )

# Oturum oluşturucu
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency — DB session yield eder."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Modeller için temel sınıf
Base = declarative_base()