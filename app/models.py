import enum
from datetime import UTC, datetime

from sqlalchemy import JSON, BigInteger, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import relationship

from app.database import Base


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
    submission_time = Column(DateTime, default=lambda: datetime.now(UTC))



class ScanResult(Base):
    """Tarayıcının yeniden kullanılabilir URL kararı (son tarama sonucu, sınırlı sayıda tutulur)."""
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=True, nullable=False)
    domain = Column(String(512), index=True, nullable=False)
    risk_score = Column(Integer, default=0, index=True)
    risk_level = Column(String(20), default='unknown')
    is_safe = Column(Boolean, default=False)
    sources = Column(Text)  # JSON dizi
    raw_data = Column(Text)  # Tam tarama sonucu JSON
    checked_at = Column(DateTime, server_default=func.current_timestamp(), index=True)
    created_at = Column(DateTime, server_default=func.current_timestamp())
    last_updated = Column(DateTime, server_default=func.current_timestamp())


class ScanEvent(Base):
    """Kullanıcıların son taradığı URL'ler (geçmiş listesi, URL başına tek satır)."""
    __tablename__ = "scan_events"

    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=True, nullable=False)
    domain = Column(String(512), index=True, nullable=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(String(20), default='unknown')
    is_safe = Column(Boolean, default=False, index=True)
    sources = Column(Text)
    checked_at = Column(DateTime, server_default=func.current_timestamp(), index=True)

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
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))


class HoneypotEvent(Base):
    """Yalnızca bu sunucuya gelen istekler — eğitim/demonstrasyon tuzak sayfası ziyaretleri."""

    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String(128), index=True)
    user_agent = Column(String(512))
    path = Column(String(256))
    referer = Column(String(512), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class IndicatorOfCompromise(Base):
    """
    IOC Collector - Enterprise-grade Indicator Storage.
    Stores all indicators (IP, Domain, URL, Hash) from multiple sources.
    Used by: Honeypot IOC Collector, Operator Gateway, Cyber Guardian.
    """
    __tablename__ = "indicators_of_compromise"

    id = Column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, index=True)

    # Core IOC data
    ioc_type = Column(String(20), index=True, nullable=False)  # 'ip', 'domain', 'url', 'hash'
    ioc_value = Column(String(1000), index=True, nullable=False)  # The actual value (normalized)
    ioc_value_hash = Column(String(64), unique=True, index=True)  # SHA256 of value (for dedup)

    # Source tracking
    source = Column(String(50), index=True, nullable=False)  # 'abuse_urlhaus', 'abuse_phishtank', 'abuseipdb', 'honeypot'
    source_reference = Column(String(500), nullable=True)  # URL/ID to original report

    # Threat classification
    threat_type = Column(String(100), index=True, nullable=False)  # 'phishing', 'malware', 'botnet', 'spam', 'c2'
    threat_tags = Column(JSON, nullable=True, default=[])  # ['zeus', 'dridex', 'emotet'] etc.

    # Scoring & confidence
    risk_score = Column(Integer, index=True, nullable=False)  # 1-100 (calculated)
    confidence = Column(Float, nullable=False)  # 0.0-1.0 from source

    # Timeline & frequency
    first_seen = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(UTC))
    last_seen = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(UTC))
    detection_count = Column(Integer, default=1)  # How many times we've seen this

    # Enrichment data
    context = Column(JSON, nullable=True)  # {'country': 'CN', 'asn': 'AS12345', 'owner': 'XYZ Corp'}
    ioc_metadata = Column(JSON, nullable=True)  # Extra data from source API

    # Operator tracking
    operator_alert_sent = Column(Boolean, default=False, index=True)
    operator_alert_timestamp = Column(DateTime, nullable=True)

    # Status & lifecycle
    status = Column(String(50), default='active', index=True)  # 'active', 'resolved', 'false_positive', 'archived'
    is_monitored = Column(Boolean, default=True, index=True)  # Whether to continue monitoring

    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))

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

    id = Column(BigInteger().with_variant(Integer, 'sqlite'), primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=True)

    # Analiz edilen URL
    url = Column(String(2000), index=True, nullable=False)
    domain = Column(String(512), index=True, nullable=False)

    # Analiz sonucu
    risk_level = Column(String(20), index=True, nullable=False)  # 'safe', 'low', 'medium', 'high'
    is_phishing = Column(Boolean, index=True, default=False)
    confidence = Column(Float, nullable=True)  # 0.0-1.0

    # Analiz detayları
    analysis_result = Column(JSON, nullable=True)  # Tüm analiz sonuçları
    llm_analysis = Column(Text, nullable=True)  # LLM analizi metni
    url_checks = Column(JSON, nullable=True)  # URL kontrolleri sonuçları

    # Timestamps
    created_at = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(UTC))


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

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(256), nullable=True)
    role = Column(SAEnum(UserRole), default=UserRole.free, index=True, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), index=True)

    # Relationships
    api_keys = relationship("APIKey", back_populates="user", lazy="dynamic")
    reports = relationship("UserReport", back_populates="user", lazy="dynamic")


class APIKey(Base):
    """Kullanıcı API anahtarları — X-API-Key header ile auth."""
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    key_hash = Column(String(64), unique=True, index=True, nullable=False)  # SHA256 of raw key
    key_prefix = Column(String(8), index=True, nullable=False)  # İlk 8 karakter (tanımlama için)
    label = Column(String(100), nullable=True)  # "Kişisel", "Kurumsal API" vb.
    role = Column(SAEnum(UserRole), default=UserRole.free, index=True, nullable=False)
    rate_limit_tier = Column(String(20), default="free", index=True)  # free/premium/corporate/admin
    last_used_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))

    # Relationships
    user = relationship("User", back_populates="api_keys")


class UserReport(Base):
    """Kullanıcının kendi anlattığı olayın Gemini analiz sonucu."""
    __tablename__ = "user_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    user_description = Column(Text, nullable=False)
    ai_analysis = Column(JSON, nullable=True)  # Gemini analiz sonucu
    protection_plan = Column(Text, nullable=True)  # 5 maddelik korunma planı
    pdf_path = Column(String(500), nullable=True)
    pdf_status = Column(String(20), nullable=False, default='pending')
    status = Column(String(20), nullable=False, default='open')
    action_steps = Column(JSON, nullable=False, default=list)
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC), onupdate=lambda: datetime.now(UTC))
    report_quota_month = Column(String(7), nullable=True)  # "2026-04" gibi, quota takibi için
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), index=True)

    # Relationships
    user = relationship("User", back_populates="reports")


# =========================================================
# VICTIM ATLAS — POSTGRESQL ORM (SQLite'dan taşındı)
# =========================================================


class UserSession(Base):
    __tablename__ = 'user_sessions'
    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    api_key_id = Column(Integer, ForeignKey('api_keys.id'), nullable=False)
    expires_at = Column(DateTime, nullable=False)


class RecoveryToken(Base):
    __tablename__ = 'recovery_tokens'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String(64), unique=True, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)


class PDFDownload(Base):
    __tablename__ = 'pdf_downloads'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    report_id = Column(Integer, ForeignKey('user_reports.id'), nullable=False)
    month = Column(String(7), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    __table_args__ = (Index('ix_pdf_month_unique', 'user_id', 'report_id', 'month', unique=True),)


class EventOutbox(Base):
    __tablename__ = 'event_outbox'
    id = Column(Integer, primary_key=True)
    event = Column(String(100), nullable=False)
    payload = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))
    processed_at = Column(DateTime, nullable=True)
    attempts = Column(Integer, default=0, nullable=False)
    last_error = Column(String(250), nullable=True)


class AnalysisFeedback(Base):
    __tablename__ = 'analysis_feedback'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    report_id = Column(Integer, ForeignKey('user_reports.id'), nullable=True)
    url = Column(String(2000), nullable=True)
    expected_verdict = Column(String(30), nullable=False)
    reason = Column(String(2000), nullable=False)
    status = Column(String(20), default='pending', nullable=False)
    review_note = Column(String(2000), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class WatchItem(Base):
    __tablename__ = 'watch_items'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    kind = Column(String(20), nullable=False)
    value = Column(String(2000), nullable=False)
    last_fingerprint = Column(String(64), nullable=True)
    last_result = Column(JSON, nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    last_error = Column(String(250), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    __table_args__ = (Index('ix_watch_owner_value', 'user_id', 'kind', 'value', unique=True),)


class UserNotification(Base):
    __tablename__ = 'user_notifications'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    watch_id = Column(Integer, ForeignKey('watch_items.id'), nullable=True)
    title = Column(String(250), nullable=False)
    detail = Column(JSON, nullable=True)
    read_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC))


class PrivateScan(Base):
    __tablename__ = 'private_scans'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), index=True, nullable=False)
    job_id = Column(String(64), nullable=False)
    url = Column(String(2048), nullable=False)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), index=True)
    __table_args__ = (Index('ix_private_scan_job', 'user_id', 'job_id', unique=True),)


class CrawlCandidate(Base):
    __tablename__ = 'crawl_candidates'
    id = Column(Integer, primary_key=True)
    url = Column(String(4096), nullable=False)
    url_hash = Column(String(64), nullable=False, unique=True)
    host = Column(String(253), nullable=False, index=True)
    source = Column(String(120), nullable=False)
    reason = Column(String(500), nullable=False)
    state = Column(String(24), default='pending', nullable=False, index=True)
    depth = Column(Integer, default=0, nullable=False)
    root_id = Column(Integer, nullable=True, index=True)
    attempts = Column(Integer, default=0, nullable=False)
    lease_token = Column(String(64), nullable=True)
    lease_until = Column(DateTime, nullable=True)
    next_attempt_at = Column(DateTime, nullable=True, index=True)
    risk = Column(Integer, nullable=True)
    coverage = Column(String(24), default='unknown', nullable=False)
    last_error = Column(String(120), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)


class CrawlObservation(Base):
    __tablename__ = 'crawl_observations'
    id = Column(Integer, primary_key=True)
    candidate_id = Column(Integer, ForeignKey('crawl_candidates.id'), nullable=False, index=True)
    attempt_token = Column(String(64), nullable=False, unique=True)
    final_url = Column(String(4096), nullable=False)
    http_status = Column(Integer, nullable=False)
    live = Column(Boolean, default=True, nullable=False)
    truncated = Column(Boolean, default=False, nullable=False)
    content_hash = Column(String(64), nullable=False, index=True)
    html_path = Column(String(250), nullable=True)
    screenshot_path = Column(String(250), nullable=True)
    features = Column(JSON, nullable=False)
    assessment = Column(JSON, nullable=False)
    fetched_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)


class CrawlReview(Base):
    __tablename__ = 'crawl_reviews'
    id = Column(Integer, primary_key=True)
    candidate_id = Column(Integer, ForeignKey('crawl_candidates.id'), nullable=False, index=True)
    observation_id = Column(Integer, ForeignKey('crawl_observations.id'), nullable=True)
    decision = Column(String(24), nullable=False)
    note = Column(String(2000), nullable=False)
    actor = Column(String(120), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(UTC), nullable=False)


class CrawlSource(Base):
    __tablename__ = 'crawl_sources'
    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    url = Column(String(4096), nullable=False)
    kind = Column(String(24), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    last_checked_at = Column(DateTime, nullable=True)
    last_error = Column(String(120), nullable=True)
    added_count = Column(Integer, default=0, nullable=False)


class CrawlSettings(Base):
    __tablename__ = 'crawl_settings'
    id = Column(Integer, primary_key=True)
    enabled = Column(Boolean, default=False, nullable=False)
    browser_enabled = Column(Boolean, default=False, nullable=False)
    daily_limit = Column(Integer, default=1000, nullable=False)
    browser_limit = Column(Integer, default=100, nullable=False)
    excluded_hosts = Column(JSON, default=list, nullable=False)
