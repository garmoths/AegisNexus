from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, JSON, Index, BigInteger, ForeignKey, Enum as SAEnum
from sqlalchemy.orm import relationship
from app.database import Base
from datetime import datetime, timezone
import enum


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
    submission_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))


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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class HoneypotEvent(Base):
    """Yalnızca bu sunucuya gelen istekler — eğitim/demonstrasyon tuzak sayfası ziyaretleri."""

    __tablename__ = "honeypot_events"

    id = Column(Integer, primary_key=True, index=True)
    client_ip = Column(String(128), index=True)
    user_agent = Column(String(512))
    path = Column(String(256))
    referer = Column(String(512), nullable=True)
    note = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class IndicatorOfCompromise(Base):
    """
    IOC Collector - Enterprise-grade Indicator Storage.
    Stores all indicators (IP, Domain, URL, Hash) from multiple sources.
    Used by: Honeypot IOC Collector, Operator Gateway, Cyber Guardian.
    """
    __tablename__ = "indicators_of_compromise"

    id = Column(BigInteger, primary_key=True, index=True)
    
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
    first_seen = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(timezone.utc))
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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    
    # Indexes for performance
    __table_args__ = (
        Index('ix_ioc_type_value', 'ioc_type', 'ioc_value'),
        Index('ix_source_timestamp', 'source', 'created_at'),
        Index('ix_risk_score_timestamp', 'risk_score', 'created_at'),
        Index('ix_threat_type', 'threat_type'),
    )


class OperatorAPIKey(Base):
    """
    Operator credentials for receiving IOC alerts.
    Used by Cyber Guardian SMS integration.
    """
    __tablename__ = "operator_api_keys"
    
    id = Column(Integer, primary_key=True, index=True)
    operator_name = Column(String(100), unique=True, index=True, nullable=False)  # 'Turk Telekom', 'Vodafone', 'Türkcell'
    api_key = Column(String(255), unique=True, index=True, nullable=False)
    
    # Communication settings
    webhook_url = Column(String(500), nullable=True)  # Push webhook for realtime alerts
    email = Column(String(255), nullable=True)  # For daily reports
    sms_number = Column(String(20), nullable=True)  # SMS notification number
    
    # Configuration
    min_risk_score = Column(Integer, default=80)  # Only alert if >= this score
    alert_frequency = Column(String(50), default='realtime')  # 'realtime', 'daily', 'weekly'
    threat_types_filter = Column(JSON, nullable=True, default=[])  # ['phishing', 'malware'] or [] for all
    
    # Status
    active = Column(Boolean, default=True, index=True)
    is_verified = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    last_alert_sent = Column(DateTime, nullable=True)


class IOCOperatorAlert(Base):
    """
    Tracking which IOCs were sent to which operators.
    Used for delivery confirmation, retry logic, and audit trail.
    """
    __tablename__ = "ioc_operator_alerts"
    
    id = Column(BigInteger, primary_key=True, index=True)
    
    # References
    ioc_id = Column(BigInteger, index=True, nullable=False)  # Foreign key to IndicatorOfCompromise
    operator_id = Column(Integer, index=True, nullable=False)  # Foreign key to OperatorAPIKey
    
    # Delivery tracking
    alert_sent_at = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(timezone.utc))
    delivery_status = Column(String(50), default='pending')  # 'sent', 'delivered', 'failed', 'bounced'
    delivery_timestamp = Column(DateTime, nullable=True)
    
    # Response tracking
    webhook_response_code = Column(Integer, nullable=True)  # HTTP status
    webhook_response_body = Column(Text, nullable=True)  # Error message if failed
    retry_count = Column(Integer, default=0)


class URLAnalizHistory(Base):
    """
    URL Analiz Geçmişi - AI Analyzer tarafından yapılan analizlerin kaydı.
    """
    __tablename__ = "url_analiz_history"
    
    id = Column(BigInteger, primary_key=True, index=True)
    
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
    created_at = Column(DateTime, index=True, nullable=False, default=lambda: datetime.now(timezone.utc))


# =========================================================
# SİBER MAĞDURİYET ATLASI — YENİ MODELLER
# =========================================================


class UserRole(str, enum.Enum):
    free = "free"
    premium = "premium"
    corporate = "corporate"
    admin = "admin"


class AttackMethod(str, enum.Enum):
    phishing = "phishing"
    smishing = "smishing"
    vishing = "vishing"
    fake_app = "fake_app"
    social_engineering = "social_engineering"
    sahte_mobil_uygulama = "sahte_mobil_uygulama"
    banka_taklit = "banka_taklit"
    malware_assisted = "malware_assisted"
    other = "other"


class LossType(str, enum.Enum):
    bank_account = "bank_account"
    identity = "identity"
    credit_card = "credit_card"
    crypto_wallet = "crypto_wallet"
    social_media = "social_media"
    device_compromise = "device_compromise"
    corporate_account = "corporate_account"
    ecommerce = "ecommerce"
    other = "other"


class User(Base):
    """Platform kullanıcısı — API key tabanlı auth, şifresiz."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(256), nullable=True)
    role = Column(SAEnum(UserRole), default=UserRole.free, index=True, nullable=False)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    api_keys = relationship("APIKey", back_populates="user", lazy="dynamic")
    reports = relationship("UserReport", back_populates="user", lazy="dynamic")
    subscriptions = relationship("Subscription", back_populates="user", lazy="dynamic")
    alert_subscriptions = relationship("AlertSubscription", back_populates="user", lazy="dynamic")


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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = relationship("User", back_populates="api_keys")


class CaseTag(Base):
    """Vaka etiketleri — çoktan çoğa ilişki."""
    __tablename__ = "case_tags"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("victim_cases.id"), index=True, nullable=False)
    tag = Column(String(100), index=True, nullable=False)

    __table_args__ = (
        Index('ix_case_tag_unique', 'case_id', 'tag', unique=True),
    )


class UserReport(Base):
    """Kullanıcının kendi anlattığı olayın Gemini analiz sonucu."""
    __tablename__ = "user_reports"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    case_id = Column(Integer, ForeignKey("victim_cases.id"), index=True, nullable=True)
    user_description = Column(Text, nullable=False)
    ai_analysis = Column(JSON, nullable=True)  # Gemini analiz sonucu
    protection_plan = Column(Text, nullable=True)  # 5 maddelik korunma planı
    pdf_path = Column(String(500), nullable=True)
    report_quota_month = Column(String(7), nullable=True)  # "2026-04" gibi, quota takibi için
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    user = relationship("User", back_populates="reports")


class Subscription(Base):
    """Kullanıcı abonelik durumu."""
    __tablename__ = "subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    plan = Column(SAEnum(UserRole), default=UserRole.free, nullable=False)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    payment_ref = Column(String(255), nullable=True)  # İyzico reference (stub)

    # Relationships
    user = relationship("User", back_populates="subscriptions")


class AlertSubscription(Base):
    """Kullanıcının uyarı abonelik tercihleri."""
    __tablename__ = "alert_subscriptions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), index=True, nullable=False)
    region = Column(String(100), index=True, nullable=True)  # Türkiye ili
    attack_method = Column(String(50), index=True, nullable=True)
    is_active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Relationships
    user = relationship("User", back_populates="alert_subscriptions")


# =========================================================
# VICTIM ATLAS — POSTGRESQL ORM (SQLite'dan taşındı)
# =========================================================


class SourceRegistry(Base):
    """Victim Atlas veri kaynakları kayıt defteri."""
    __tablename__ = "sources_registry"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), unique=True, index=True, nullable=False)
    base_url = Column(String(500), nullable=False)
    trust_tier = Column(String(20), nullable=False)  # tier1, tier2
    enabled = Column(Boolean, default=True, index=True)
    last_success_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class RawDocument(Base):
    """Victim Atlas ham belge deposu — RSS/scrape kaynaklarından çekilen metinler."""
    __tablename__ = "raw_documents"

    id = Column(Integer, primary_key=True, index=True)
    source_id = Column(Integer, ForeignKey("sources_registry.id"), index=True, nullable=False)
    external_id = Column(String(2000), nullable=False)
    url = Column(String(2000), nullable=False)
    title = Column(String(500), nullable=False)
    published_at = Column(DateTime, nullable=True)
    fetched_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    raw_text = Column(Text, nullable=False)
    lang = Column(String(10), default="unknown")
    hash = Column(String(64), unique=True, index=True, nullable=False)

    __table_args__ = (
        Index('ix_raw_source_external', 'source_id', 'external_id', unique=True),
        Index('ix_raw_source_published', 'source_id', 'published_at'),
    )


class VictimCase(Base):
    """Victim Atlas vaka kayıtları — Gemini ile sınıflandırılmış dolandırıcılık vakaları."""
    __tablename__ = "victim_cases"

    id = Column(Integer, primary_key=True, index=True)
    case_slug = Column(String(200), unique=True, index=True, nullable=False)
    case_title = Column(String(500), nullable=False)
    incident_period_start = Column(DateTime, nullable=True)
    incident_period_end = Column(DateTime, nullable=True)
    attack_method = Column(String(50), index=True, nullable=False)
    loss_type = Column(String(50), index=True, nullable=False)
    target_platform = Column(String(50), nullable=False)
    critical_warning = Column(Text, nullable=False)
    narrative_summary = Column(Text, nullable=False)
    defense_steps_json = Column(JSON, nullable=False)
    confidence_score = Column(Integer, nullable=False)
    severity_score = Column(Integer, nullable=False)
    region = Column(String(100), index=True, nullable=True)  # Türkiye ili
    is_hot = Column(Boolean, default=True, index=True)
    is_published = Column(Boolean, default=True, index=True)
    first_seen = Column(DateTime, nullable=False)
    last_seen = Column(DateTime, index=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    tags = relationship("CaseTag", backref="case", lazy="dynamic")
    evidence = relationship("VictimCaseEvidence", backref="case", lazy="dynamic")
    reports = relationship("UserReport", backref="case", lazy="dynamic")

    __table_args__ = (
        Index('ix_cases_attack_method', 'attack_method'),
        Index('ix_cases_loss_type', 'loss_type'),
        Index('ix_cases_last_seen', 'last_seen'),
        Index('ix_cases_hot', 'is_hot'),
    )


class VictimCaseEvidence(Base):
    """Vaka-delil ilişkisi — hangi ham belge hangi vakayı destekliyor."""
    __tablename__ = "victim_case_evidence"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("victim_cases.id"), index=True, nullable=False)
    raw_document_id = Column(Integer, ForeignKey("raw_documents.id"), index=True, nullable=False)
    evidence_snippet = Column(Text, nullable=False)
    evidence_weight = Column(Float, default=1.0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('ix_evidence_unique', 'case_id', 'raw_document_id', unique=True),
    )


class IngestRun(Base):
    """Victim Atlas ingest çalışma geçmişi."""
    __tablename__ = "ingest_runs"

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, nullable=False)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(20), nullable=False)  # running, success, error
    documents_fetched = Column(Integer, default=0)
    cases_created = Column(Integer, default=0)
    cases_updated = Column(Integer, default=0)
    errors_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class CaseComment(Base):
    """Victim Atlas vaka yorumları — anonim kullanıcı deneyimleri."""
    __tablename__ = "case_comments"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("victim_cases.id"), index=True, nullable=False)
    nickname = Column(String(60), nullable=False)
    text = Column(Text, nullable=False)
    upvotes = Column(Integer, default=0, nullable=False)
    ip_hash = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index('ix_comment_case_created', 'case_id', 'created_at'),
    )


class FraudProfile(Base):
    """Bilinen dolandırıcılık profilleri — statik seed + Victim Atlas'tan dinamik istatistik."""
    __tablename__ = "fraud_profiles"

    id            = Column(Integer, primary_key=True, index=True)
    slug          = Column(String(80), unique=True, index=True, nullable=False)
    name_tr       = Column(String(200), nullable=False)
    description   = Column(Text, nullable=False)
    attack_method = Column(String(50), index=True, nullable=True)
    keywords      = Column(JSON, nullable=False, default=list)
    indicators    = Column(JSON, nullable=False, default=list)
    is_static     = Column(Boolean, default=True)
    case_count    = Column(Integer, default=0)
    avg_loss_try  = Column(Float, nullable=True)
    severity      = Column(String(20), default="high")
    created_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at    = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                           onupdate=lambda: datetime.now(timezone.utc))
