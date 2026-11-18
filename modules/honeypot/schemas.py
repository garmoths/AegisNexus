"""Request and response models for the honeypot / IOC API (``/api/v2/honeypot``)."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

RiskLevel = Literal['critical', 'high', 'medium', 'low']


# ── Requests ──────────────────────────────────────────────────────────────

class HoneypotInteractionRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=64)
    action: str = Field(min_length=1, max_length=50, description='page_load, login_attempt, otp_request, password_reset')
    payload: dict[str, Any] | None = None


class HoneypotCreateRequest(BaseModel):
    decoy_type: str = Field('bank_login', max_length=50, description='bank_login, social_login, shopping_login')


class IOCCollectRequest(BaseModel):
    source: str = Field('external', max_length=50)
    payload: dict[str, Any] | None = None
    raw_text: str | None = Field(None, max_length=200_000)
    tags: list[str] | None = Field(None, max_length=50)


class IOCCollectorFetchRequest(BaseModel):
    sources: list[str] | None = Field(None, description='Restrict to these source ids; all configured sources when omitted')
    limit_per_source: int = Field(100, ge=1, le=5000)


# ── Responses ─────────────────────────────────────────────────────────────

class ModuleResponse(BaseModel):
    status: Literal['success'] = 'success'
    module: str = '02_honeypot'


class SessionCreated(BaseModel):
    session_id: str
    decoy_page: str
    decoy_type: str
    module: str = '02_honeypot'


class DecoyTypes(BaseModel):
    decoy_types: list[str]
    module: str = '02_honeypot'
    description: str


class IOCCollected(ModuleResponse):
    collected_count: int
    collected: list[dict[str, Any]]


class IOCList(ModuleResponse):
    data: list[dict[str, Any]]


class ExternalFetchResult(ModuleResponse):
    module: str = '02_honeypot_ioc_collector'
    collected: int
    persisted: int
    stats: dict[str, Any]
    samples: list[dict[str, Any]]


class CollectedIOCPage(ModuleResponse):
    module: str = '02_honeypot_ioc_collector'
    total: int
    returned: int
    offset: int
    limit: int
    iocs: list[dict[str, Any]]


class AdvancedStats(ModuleResponse):
    module: str = '02_honeypot_ioc_collector'
    statistics: dict[str, Any]
    insights: dict[str, float]


class IOCSearchHit(BaseModel):
    id: int
    type: str
    value: str
    threat_type: str
    risk_score: int
    source: str
    detection_count: int | None
    first_seen: str | None
    last_seen: str | None


class IOCSearchResult(ModuleResponse):
    module: str = '02_honeypot_ioc_collector'
    query: str
    found: int
    results: list[IOCSearchHit]


class RiskBandIOC(BaseModel):
    value: str
    type: str
    threat_type: str
    risk_score: int
    confidence: float
    source: str
    detection_count: int | None


class ScoreRange(BaseModel):
    min: int
    max: int


class RiskBandResult(ModuleResponse):
    module: str = '02_honeypot_ioc_collector'
    risk_level: RiskLevel
    score_range: ScoreRange
    found: int
    iocs: list[RiskBandIOC]


class DailyCount(BaseModel):
    date: str
    count: int


class RiskBucket(BaseModel):
    range: str
    count: int
    percentage: float


class TypeCount(BaseModel):
    type: str
    count: int


class SourceCount(BaseModel):
    source: str
    count: int


class IOCSummary(BaseModel):
    total_iocs: int
    high_risk_count: int
    medium_risk_count: int
    low_risk_count: int
    last_update: str


class IOCStatistics(BaseModel):
    status: Literal['success'] = 'success'
    stats: IOCSummary
    total_records: int
    today_added: int
    weekly_growth: list[DailyCount]
    risk_distribution: list[RiskBucket]
    top_threats: list[TypeCount]
    source_breakdown: list[SourceCount]
    last_updated: str


class PhishingSummary(BaseModel):
    total_urls: int
    daily_new: int
    last_update: str


class DomainCount(BaseModel):
    domain: str | None
    count: int


class CategoryCount(BaseModel):
    category: str | None
    count: int


class RecentPhishingURL(BaseModel):
    url: str | None
    domain: str | None
    target: str | None
    status: str | None
    time: str | None


class PhishingStatistics(BaseModel):
    status: Literal['success'] = 'success'
    stats: PhishingSummary
    total_urls: int
    daily_new: int
    top_domains: list[DomainCount]
    recent_urls: list[RecentPhishingURL]
    threat_categories: list[CategoryCount]
    last_updated: str
