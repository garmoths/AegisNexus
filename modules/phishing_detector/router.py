"""Phishing detector endpoints (``/api/v2/phishing``).

Public: scan a URL, poll a scan job, read the threat database.
Authenticated: your own scan history. Admin: add sites, pull feeds, maintenance.
Business logic lives in :mod:`modules.phishing_detector.service`.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth import require_admin, resolve_api_key, resolve_optional_api_key
from app.database import get_db
from app.models import APIKey

from . import service
from .cache_db import get_phishing_stats, get_threat_type_distribution
from .fetch_all_sources import fetch_all_sources
from .redis_cache import redis_health
from .schemas import (
    CleanupAnalysis,
    CleanupResult,
    FetchAllResult,
    LatestPage,
    LatestPhishing,
    PhishingSearch,
    ScanHistory,
    SiteAdded,
    SiteAddRequest,
    SkippedURLs,
    StatsResponse,
    ThreatTypes,
    URLCheckRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["phishing"])
MODULE = service.MODULE


# ── Scans ─────────────────────────────────────────────────────────────────

@router.post("/check-url", summary="Scan a URL",
             description="Returns a verdict (`status: complete`) from cache or quick checks, or enqueues a full "
                         "analysis and returns `status: analyzing` with a `job_id` to poll at `/result/{job_id}`.")
def check_url(request: URLCheckRequest, db: Session = Depends(get_db),
              api_key: APIKey | None = Depends(resolve_optional_api_key)) -> dict[str, Any]:
    return service.start_scan(db, api_key, request.url, request.force_fresh)


@router.get("/result/{job_id}", summary="Poll a scan job",
            description="`status` is one of queued, running, retrying, complete, failed, timeout or expired.")
def get_job_result(job_id: str, api_key: APIKey | None = Depends(resolve_optional_api_key),
                   db: Session = Depends(get_db)) -> dict[str, Any]:
    return service.job_status(db, api_key, job_id)


@router.get('/history', response_model=ScanHistory, include_in_schema=False)
@router.get('/scan-history', response_model=ScanHistory, summary="Your own scan history")
def get_scan_history_paged(limit: int = Query(20, ge=1, le=100), page: int = Query(1, ge=1), days: int = Query(30, ge=1, le=365),
                           api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    return service.scan_history(db, api_key, limit=limit, page=page, days=days)


# ── Threat database (public, read-only) ───────────────────────────────────

@router.get("/stats", response_model=StatsResponse, summary="Dashboard counters")
def get_stats(db: Session = Depends(get_db)):
    return StatsResponse(stats=service.dashboard_stats(db))


@router.get("/latest-paged", response_model=LatestPage, summary="Known phishing URLs, active first")
def get_latest(limit: int = Query(20, ge=1, le=100), page: int = Query(1, ge=1), db: Session = Depends(get_db)):
    return service.latest_paged(db, limit=limit, page=page)


@router.get("/latest", response_model=LatestPhishing, summary="Most recently added phishing URLs")
def get_latest_phishing_urls(limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db)):
    return service.latest(db, limit)


@router.get("/search", response_model=PhishingSearch, summary="Substring search in the phishing database")
def search_urls(url: str = Query(min_length=1, max_length=2048), limit: int = Query(20, ge=1, le=100),
                page: int = Query(1, ge=1), db: Session = Depends(get_db)):
    return service.search(db, url, limit=limit, page=page)


@router.get("/threat-types", response_model=ThreatTypes, summary="Threat type distribution")
def get_threat_types_distribution():
    return ThreatTypes(types=get_threat_type_distribution())


# ── Administration ────────────────────────────────────────────────────────

@router.post("/add-site", response_model=SiteAdded, status_code=201, summary="Add a phishing site (admin)")
def add_site(item: SiteAddRequest, db: Session = Depends(get_db), _: APIKey = Depends(require_admin)):
    return SiteAdded(id=service.add_site(db, item.url, item.target, item.status))


@router.post("/fetch-all", response_model=FetchAllResult, summary="Pull every phishing feed now (admin)")
def fetch_all_phishing_data(db: Session = Depends(get_db), _: APIKey = Depends(require_admin)):
    try:
        result = fetch_all_sources(db)
    except Exception as exc:
        logger.exception('fetch-all failed')
        raise HTTPException(502, 'Phishing kaynakları çekilemedi.') from exc
    return FetchAllResult(message=f"Tum kaynaklardan {result['total_added']} yeni veri eklendi", data=result)


@router.get("/cache-health", summary="Cache, database and browser-pool health (admin)")
def get_cache_health(_: APIKey = Depends(require_admin)) -> dict[str, Any]:
    from .playwright_pool import is_healthy as pw_healthy
    sqlite_stats = get_phishing_stats()
    return {
        "cache": redis_health(),
        "sqlite": {"available": True, "total_urls": sqlite_stats.get("total_urls", 0),
                   "today_scans": sqlite_stats.get("today_scans", 0)},
        "playwright_pool": {"browser_alive": pw_healthy()},
        "module": MODULE,
    }


@router.get("/skipped-urls", response_model=SkippedURLs, summary="Scans with sources but a zero score (admin)")
def get_skipped_urls(days: int = Query(30, ge=1, le=365), _: APIKey = Depends(require_admin)):
    from .cache_db import detect_skipped_urls
    skipped = detect_skipped_urls(days=days)
    return SkippedURLs(skipped=skipped, count=len(skipped), days=days)


@router.get("/cleanup/analyze", response_model=CleanupAnalysis, summary="Preview cache cleanup (admin)")
def analyze_cleanup(days: int = Query(30, ge=1, le=3650), _: APIKey = Depends(require_admin)):
    from .cache_db import analyze_records
    return CleanupAnalysis(analysis=analyze_records(days=days))


@router.post("/cleanup", response_model=CleanupResult, summary="Delete stale cache records (admin)")
def perform_cleanup(days: int = Query(30, ge=1, le=3650), unscanned: bool = True, no_sources: bool = False,
                    no_raw_data: bool = False, dry_run: bool = False, _: APIKey = Depends(require_admin)):
    from .cache_db import cleanup_records
    criteria = {'days': days, 'unscanned': unscanned, 'no_sources': no_sources, 'no_raw_data': no_raw_data}
    return CleanupResult(result=cleanup_records(criteria, dry_run=dry_run))
