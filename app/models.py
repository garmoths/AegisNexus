from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from app.database import Base
from datetime import datetime


class PhishingURL(Base):
    __tablename__ = "phishing_urls"

    id = Column(Integer, primary_key=True, index=True)
    phish_id = Column(String, unique=True, index=True)
    url = Column(String)
    url_hash = Column(String(64), unique=True, index=True, nullable=True)
    domain_norm = Column(String(512), index=True, nullable=True)
    status = Column(String)
    online = Column(Boolean)
    target = Column(String)
    submission_time = Column(DateTime, default=datetime.utcnow)


class WhitelistDomain(Base):
    """Güvenilir şirketlerin domain whitelist'i"""
    __tablename__ = "whitelist_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(512), unique=True, index=True)
    domain_norm = Column(String(512), index=True)  # Normalize edilmiş
    category = Column(String(100), index=True)  # Banks, Gaming, Film, Gov, Tech, E-commerce, etc.
    company_name = Column(String(256))
    country = Column(String(100), nullable=True)
    trusted_level = Column(String(20), default="high")  # high, medium
    verified = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class HoneypotEvent(Base):
    """Yalnızca bu sunucuya gelen istekler — eğitim/demonstrasyon tuzak sayfası ziyaretleri."""

    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String(128), index=True)
    user_agent = Column(String(512))
    path = Column(String(256))
    referer = Column(String(512), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
