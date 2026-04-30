"""
Phishing URL Model - Ortak Model
"""
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Boolean, DateTime

from app.database import Base


class PhishingURL(Base):
    """Phishing URL veritabanı modeli"""
    __tablename__ = "phishing_urls"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, index=True)
    phish_id = Column(String, unique=True, index=True)
    url = Column(String)
    url_hash = Column(String(64), unique=True, index=True, nullable=True)
    domain = Column(String(512), index=True, nullable=True)
    domain_norm = Column(String(512), index=True, nullable=True)
    status = Column(String)
    online = Column(Boolean)
    target = Column(String)
    reported_by = Column(String(50), nullable=True)
    reason = Column(String(50), nullable=True)
    user_reported = Column(Boolean, default=False, index=True)
    report_count = Column(Integer, default=0)
    last_reported_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    submission_time = Column(DateTime, default=datetime.utcnow)
