"""
Database Utilities - Veritabanı Yardımcıları
"""
from app.database import SessionLocal


def get_db():
    """Dependency injection için veritabanı session'ı"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


__all__ = ["get_db", "SessionLocal"]
