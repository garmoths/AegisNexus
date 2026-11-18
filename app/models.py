"""ORM models. The schema itself is versioned in alembic/versions."""
from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import DynamicMapped, Mapped, mapped_column, relationship

from app.database import Base


class PhishingURL(Base):
    __tablename__ = "phishing_urls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    phish_id: Mapped[str | None] = mapped_column(String, unique=True, index=True)
    url: Mapped[str | None] = mapped_column(String)
    url_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True, nullable=True)
    domain_norm: Mapped[str | None] = mapped_column(String(512), index=True, nullable=True)
    status: Mapped[str | None] = mapped_column(String)
    online: Mapped[bool | None] = mapped_column(Boolean)
    target: Mapped[str | None] = mapped_column(String)
    submission_time: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))



class ScanResult(Base):
    """Tarayıcının yeniden kullanılabilir URL kararı (son tarama sonucu, sınırlı sayıda tutulur)."""
    __tablename__ = "scan_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer, default=0, index=True)
    risk_level: Mapped[str | None] = mapped_column(String(20), default='unknown')
    is_safe: Mapped[bool | None] = mapped_column(Boolean, default=False)
    sources: Mapped[str | None] = mapped_column(Text)  # JSON dizi
    raw_data: Mapped[str | None] = mapped_column(Text)  # Tam tarama sonucu JSON
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.current_timestamp(), index=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.current_timestamp())
    last_updated: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.current_timestamp())


class ScanEvent(Base):
    """Kullanıcıların son taradığı URL'ler (geçmiş listesi, URL başına tek satır)."""
    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(512), index=True, nullable=False)
    risk_score: Mapped[int | None] = mapped_column(Integer, default=0)
    risk_level: Mapped[str | None] = mapped_column(String(20), default='unknown')
    is_safe: Mapped[bool | None] = mapped_column(Boolean, default=False, index=True)
    sources: Mapped[str | None] = mapped_column(Text)
    checked_at: Mapped[datetime | None] = mapped_column(DateTime, server_default=func.current_timestamp(), index=True)

class WhitelistDomain(Base):
    """Güvenilir şirketlerin domain whitelist'i"""
    __tablename__ = "whitelist_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain: Mapped[str | None] = mapped_column(String(512), unique=True, index=True)
    domain_norm: Mapped[str | None] = mapped_column(String(512), index=True)  # Normalize edilmiş
    category: Mapped[str | None] = mapped_column(String(100), index=True)  # Banks, Gaming, Film, Gov, Tech, E-commerce, etc.
    company_name: Mapped[str | None] = mapped_column(String(256))
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    trusted_level: Mapped[str | None] = mapped_column(String(20), default="high")  # high, medium
    verified: Mapped[bool | None] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))


class HoneypotEvent(Base):
    """Yalnızca bu sunucuya gelen istekler — eğitim/demonstrasyon tuzak sayfası ziyaretleri."""

    __tablename__ = "honeypot_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    client_ip: Mapped[str | None] = mapped_column(String(128), index=True)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    path: Mapped[str | None] = mapped_column(String(256))
    referer: Mapped[str | None] = mapped_column(String(512), nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class IndicatorOfCompromise(Base):
    """
    IOC Collector - Enterprise-grade Indicator Storage.
    Stores all indicators (IP, Domain, URL, Hash) from multiple sources.
    Used by: Honeypot IOC Collector, Operator Gateway, Cyber Guardian.
    """
    __tablename__ = "indicators_of_compromise"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, index=True)

    # Core IOC data
    ioc_type: Mapped[str] = mapped_column(String(20), index=True, nullable=False)  # 'ip', 'domain', 'url', 'hash'
    ioc_value: Mapped[str] = mapped_column(String(1000), index=True, nullable=False)  # The actual value (normalized)
    ioc_value_hash: Mapped[str | None] = mapped_column(String(64), unique=True, index=True)  # SHA256 of value (for dedup)

    # Source tracking
    source: Mapped[str] = mapped_column(String(50), index=True, nullable=False)  # 'abuse_urlhaus', 'abuse_phishtank', 'abuseipdb', 'honeypot'
    source_reference: Mapped[str | None] = mapped_column(String(500), nullable=True)  # URL/ID to original report

    # Threat classification
    threat_type: Mapped[str] = mapped_column(String(100), index=True, nullable=False)  # 'phishing', 'malware', 'botnet', 'spam', 'c2'
    threat_tags: Mapped[Any | None] = mapped_column(JSON, nullable=True, default=[])  # ['zeus', 'dridex', 'emotet'] etc.

    # Scoring & confidence
    risk_score: Mapped[int] = mapped_column(Integer, index=True, nullable=False)  # 1-100 (calculated)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)  # 0.0-1.0 from source

    # Timeline & frequency
    first_seen: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False, default=lambda: datetime.now(UTC))
    last_seen: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False, default=lambda: datetime.now(UTC))
    detection_count: Mapped[int | None] = mapped_column(Integer, default=1)  # How many times we've seen this

    # Enrichment data
    context: Mapped[Any | None] = mapped_column(JSON, nullable=True)  # {'country': 'CN', 'asn': 'AS12345', 'owner': 'XYZ Corp'}
    ioc_metadata: Mapped[Any | None] = mapped_column(JSON, nullable=True)  # Extra data from source API

    # Operator tracking
    operator_alert_sent: Mapped[bool | None] = mapped_column(Boolean, default=False, index=True)
    operator_alert_timestamp: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Status & lifecycle
    status: Mapped[str | None] = mapped_column(String(50), default='active', index=True)  # 'active', 'resolved', 'false_positive', 'archived'
    is_monitored: Mapped[bool | None] = mapped_column(Boolean, default=True, index=True)  # Whether to continue monitoring

    # Timestamps
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

    # Indexes for performance
    __table_args__ = (
        Index('ix_ioc_type_value', 'ioc_type', 'ioc_value'),
        Index('ix_source_timestamp', 'source', 'created_at'),
        Index('ix_risk_score_timestamp', 'risk_score', 'created_at'),
        Index('ix_threat_type', 'threat_type'),
    )


class URLAnalizHistory(Base):
    """
    URL Analiz Geçmişi - AI Analyzer tarafından yapılan analizlerin kaydı.
    """
    __tablename__ = "url_analiz_history"

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, ForeignKey('users.id'), index=True, nullable=True)

    # Analiz edilen URL
    url: Mapped[str] = mapped_column(String(2000), index=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(512), index=True, nullable=False)

    # Analiz sonucu
    risk_level: Mapped[str] = mapped_column(String(20), index=True, nullable=False)  # 'safe', 'low', 'medium', 'high'
    is_phishing: Mapped[bool | None] = mapped_column(Boolean, index=True, default=False)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0.0-1.0

    # Analiz detayları
    analysis_result: Mapped[Any | None] = mapped_column(JSON, nullable=True)  # Tüm analiz sonuçları
    llm_analysis: Mapped[str | None] = mapped_column(Text, nullable=True)  # LLM analizi metni
    url_checks: Mapped[Any | None] = mapped_column(JSON, nullable=True)  # URL kontrolleri sonuçları

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, index=True, nullable=False, default=lambda: datetime.now(UTC))


# =========================================================
# KULLANICI, RAPOR VE İŞ AKIŞI MODELLERİ
# =========================================================


class UserRole(str, enum.Enum):
    free = "free"
    premium = "premium"
    corporate = "corporate"
    admin = "admin"


class User(Base):
    """Platform kullanıcısı — API key tabanlı auth, şifresiz."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.free, index=True, nullable=False)
    is_active: Mapped[bool | None] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)

    # Relationships
    api_keys: DynamicMapped[APIKey] = relationship("APIKey", back_populates="user", lazy="dynamic")
    reports: DynamicMapped[UserReport] = relationship("UserReport", back_populates="user", lazy="dynamic")


class APIKey(Base):
    """Kullanıcı API anahtarları — X-API-Key header ile auth."""
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)  # SHA256 of raw key
    key_prefix: Mapped[str] = mapped_column(String(8), index=True, nullable=False)  # İlk 8 karakter (tanımlama için)
    label: Mapped[str | None] = mapped_column(String(100), nullable=True)  # "Kişisel", "Kurumsal API" vb.
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.free, index=True, nullable=False)
    rate_limit_tier: Mapped[str | None] = mapped_column(String(20), default="free", index=True)  # free/premium/corporate/admin
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool | None] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="api_keys")


class UserReport(Base):
    """Kullanıcının kendi anlattığı olayın Gemini analiz sonucu."""
    __tablename__ = "user_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    user_description: Mapped[str] = mapped_column(Text, nullable=False)
    ai_analysis: Mapped[Any | None] = mapped_column(JSON, nullable=True)  # Gemini analiz sonucu
    protection_plan: Mapped[str | None] = mapped_column(Text, nullable=True)  # 5 maddelik korunma planı
    pdf_path: Mapped[str | None] = mapped_column(String(500), nullable=True)
    pdf_status: Mapped[str] = mapped_column(String(20), nullable=False, default='pending')
    status: Mapped[str] = mapped_column(String(20), nullable=False, default='open')
    action_steps: Mapped[Any] = mapped_column(JSON, nullable=False, default=list)
    updated_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    report_quota_month: Mapped[str | None] = mapped_column(String(7), nullable=True)  # "2026-04" gibi, quota takibi için
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="reports")


# =========================================================
# OTURUM, KURTARMA VE İŞ AKIŞI
# =========================================================


class UserSession(Base):
    __tablename__ = 'user_sessions'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    api_key_id: Mapped[int] = mapped_column(Integer, ForeignKey('api_keys.id'), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class RecoveryToken(Base):
    __tablename__ = 'recovery_tokens'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class PDFDownload(Base):
    __tablename__ = 'pdf_downloads'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    report_id: Mapped[int] = mapped_column(Integer, ForeignKey('user_reports.id'), nullable=False)
    month: Mapped[str] = mapped_column(String(7), nullable=False, index=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    __table_args__ = (Index('ix_pdf_month_unique', 'user_id', 'report_id', 'month', unique=True),)


class EventOutbox(Base):
    __tablename__ = 'event_outbox'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    event: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[Any] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))
    processed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(250), nullable=True)


class AnalysisFeedback(Base):
    __tablename__ = 'analysis_feedback'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    report_id: Mapped[int | None] = mapped_column(Integer, ForeignKey('user_reports.id'), nullable=True)
    url: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    expected_verdict: Mapped[str] = mapped_column(String(30), nullable=False)
    reason: Mapped[str] = mapped_column(String(2000), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default='pending', nullable=False)
    review_note: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class WatchItem(Base):
    __tablename__ = 'watch_items'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(20), nullable=False)
    value: Mapped[str] = mapped_column(String(2000), nullable=False)
    last_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    last_result: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(250), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    __table_args__ = (Index('ix_watch_owner_value', 'user_id', 'kind', 'value', unique=True),)


class UserNotification(Base):
    __tablename__ = 'user_notifications'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    watch_id: Mapped[int | None] = mapped_column(Integer, ForeignKey('watch_items.id'), nullable=True)
    title: Mapped[str] = mapped_column(String(250), nullable=False)
    detail: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    read_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC))


class PrivateScan(Base):
    __tablename__ = 'private_scans'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    job_id: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    risk_level: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime, default=lambda: datetime.now(UTC), index=True)
    __table_args__ = (Index('ix_private_scan_job', 'user_id', 'job_id', unique=True),)


class CrawlCandidate(Base):
    __tablename__ = 'crawl_candidates'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(String(4096), nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    host: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(120), nullable=False)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    state: Mapped[str] = mapped_column(String(24), default='pending', nullable=False, index=True)
    depth: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    root_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    lease_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True, index=True)
    risk: Mapped[int | None] = mapped_column(Integer, nullable=True)
    coverage: Mapped[str] = mapped_column(String(24), default='unknown', nullable=False)
    last_error: Mapped[str | None] = mapped_column(String(120), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)


class CrawlObservation(Base):
    __tablename__ = 'crawl_observations'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[int] = mapped_column(Integer, ForeignKey('crawl_candidates.id'), nullable=False, index=True)
    attempt_token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    final_url: Mapped[str] = mapped_column(String(4096), nullable=False)
    http_status: Mapped[int] = mapped_column(Integer, nullable=False)
    live: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    html_path: Mapped[str | None] = mapped_column(String(250), nullable=True)
    screenshot_path: Mapped[str | None] = mapped_column(String(250), nullable=True)
    features: Mapped[Any] = mapped_column(JSON, nullable=False)
    assessment: Mapped[Any] = mapped_column(JSON, nullable=False)
    fetched_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)


class CrawlReview(Base):
    __tablename__ = 'crawl_reviews'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    candidate_id: Mapped[int] = mapped_column(Integer, ForeignKey('crawl_candidates.id'), nullable=False, index=True)
    observation_id: Mapped[int | None] = mapped_column(Integer, ForeignKey('crawl_observations.id'), nullable=True)
    decision: Mapped[str] = mapped_column(String(24), nullable=False)
    note: Mapped[str] = mapped_column(String(2000), nullable=False)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC), nullable=False)


class CrawlSource(Base):
    __tablename__ = 'crawl_sources'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    url: Mapped[str] = mapped_column(String(4096), nullable=False)
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(120), nullable=True)
    added_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class CrawlSettings(Base):
    __tablename__ = 'crawl_settings'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    browser_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    daily_limit: Mapped[int] = mapped_column(Integer, default=1000, nullable=False)
    browser_limit: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    excluded_hosts: Mapped[Any] = mapped_column(JSON, default=list, nullable=False)
