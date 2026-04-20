from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, Float, JSON, Index, BigInteger
from app.database import Base
from datetime import datetime, timezone


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
