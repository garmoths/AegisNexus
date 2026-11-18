"""Request and response models for the phishing detector API (``/api/v2/phishing``).

Scan verdicts (``/check-url``, ``/result/{job_id}``) are produced by the scoring
pipeline and documented in the endpoint descriptions; their shape evolves with
the scorer, so they are returned as plain JSON objects.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

MODULE = '01_phishing_detector'


class URLCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048, examples=['https://example.com/login'])
    force_fresh: bool = Field(False, description='Ignore the shared cache and rescan')


class SiteAddRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    target: str = Field(min_length=1, max_length=200, description='Impersonated brand, e.g. "PayPal"')
    status: str = Field('ONLINE', max_length=20)


class SiteAdded(BaseModel):
    status: Literal['success'] = 'success'
    message: str = 'Site başarıyla veritabanına eklendi!'
    id: str
    module: str = MODULE


class PhishingRow(BaseModel):
    id: int
    url: str | None
    domain: str | None
    target: str
    status: str
    submission_time: str | None
    phish_id: str | None = None


class LatestRow(PhishingRow):
    risk_score: int


class LatestPage(BaseModel):
    data: list[PhishingRow]
    page: int
    total_pages: int
    total: int
    page_size: int
    module: str = MODULE


class LatestPhishing(BaseModel):
    latest: list[LatestRow]
    limit: int
    total: int
    module: str = MODULE


class PhishingSearch(BaseModel):
    status: Literal['DANGER', 'SAFE']
    data: list[PhishingRow]
    page: int
    total_pages: int
    total: int
    has_more: bool
    module: str = MODULE


class ScanHistoryRow(BaseModel):
    url: str
    risk_score: int
    safety_score: int
    risk_level: str
    checked_at: str | None
    is_safe: bool


class ScanHistory(BaseModel):
    data: list[ScanHistoryRow]
    history: list[ScanHistoryRow] = Field(description='Deprecated alias of data')
    total: int
    page: int
    total_pages: int


class StatsResponse(BaseModel):
    stats: dict[str, Any]
    module: str = MODULE


class ThreatTypes(BaseModel):
    types: dict[str, int]
    module: str = MODULE


class FetchAllResult(BaseModel):
    status: Literal['success'] = 'success'
    message: str
    data: dict[str, Any]
    module: str = MODULE


class SkippedURLs(BaseModel):
    skipped: list[dict[str, Any]]
    count: int
    days: int
    module: str = MODULE


class CleanupAnalysis(BaseModel):
    analysis: dict[str, Any]
    module: str = MODULE


class CleanupResult(BaseModel):
    result: dict[str, Any]
    module: str = MODULE
