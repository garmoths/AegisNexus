from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
import os
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Veritabanı bağlantı adresi (Senin ayarlarına göre)
# Eğer .env dosyasında bulamazsa varsayılan olarak bunu kullanacak:
SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://enes@localhost/phishing_db")

_pool_size = int(os.getenv("DB_POOL_SIZE", "5"))
_max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "2"))

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    pool_pre_ping=True,
    pool_size=_pool_size,
    max_overflow=_max_overflow,
)

# Oturum oluşturucu (İşte hata veren SessionLocal bu!)
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
