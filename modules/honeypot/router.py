"""Honeypot and IOC endpoints (``/api/v2/honeypot``).

The decoy page keeps scammers busy and records *that* they interacted, never what
they typed into credential fields. IOC endpoints expose the collected indicators.
Business logic lives in :mod:`modules.honeypot.service`.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.auth import require_admin
from app.models import APIKey
from shared.utils.db import get_db

from . import service
from .engine import honeypot_engine
from .ioc_collector import IOCCollectorEngine
from .schemas import (
    AdvancedStats,
    CollectedIOCPage,
    DecoyTypes,
    ExternalFetchResult,
    HoneypotCreateRequest,
    HoneypotInteractionRequest,
    IOCCollected,
    IOCCollectorFetchRequest,
    IOCCollectRequest,
    IOCList,
    IOCSearchResult,
    IOCStatistics,
    PhishingStatistics,
    RiskBandResult,
    RiskLevel,
    SessionCreated,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["honeypot"])
ioc_engine = IOCCollectorEngine()

_DECOY_TEMPLATE = (Path(__file__).parent / 'templates' / 'bank_decoy.html').read_text(encoding='utf-8')
_SESSION_ID = re.compile(r'^[A-Za-z0-9_-]{1,64}$')


# ── Decoy sessions ────────────────────────────────────────────────────────

@router.get("/decoy", response_class=HTMLResponse, summary="Decoy bank login page")
def honeypot_decoy_page(request: Request, db: Session = Depends(get_db)):
    session = honeypot_engine.create_session(service.client_ip(request), request.headers.get('user-agent', ''), 'bank_login')
    if not _SESSION_ID.match(session.session_id):
        raise HTTPException(500, 'Geçersiz oturum kimliği.')
    service.record_event(db, request, '/api/v2/honeypot/decoy', f'session_id:{session.session_id}')
    return HTMLResponse(_DECOY_TEMPLATE.replace('__SESSION_ID__', session.session_id))


@router.post("/session/create", response_model=SessionCreated, summary="Start a decoy session")
def create_honeypot_session(req: HoneypotCreateRequest, request: Request, db: Session = Depends(get_db)):
    session = honeypot_engine.create_session(service.client_ip(request), request.headers.get('user-agent', ''), req.decoy_type)
    service.record_event(db, request, '/api/v2/honeypot/session/create',
                         f'session_id:{session.session_id},decoy:{req.decoy_type}')
    return SessionCreated(session_id=session.session_id, decoy_type=req.decoy_type,
                          decoy_page=f'/api/v2/honeypot/decoy?session={session.session_id}')


@router.post("/interaction", summary="Record a decoy interaction and return a stalling response")
def record_interaction(req: HoneypotInteractionRequest, request: Request, db: Session = Depends(get_db)):
    result = honeypot_engine.process_interaction(req.session_id, req.action, req.payload)
    service.record_event(db, request, '/api/v2/honeypot/interaction',
                         f"session_id:{req.session_id},action:{req.action},"
                         f"threat_score:{result.get('threat_score', 0)},ioc:{result.get('ioc_detected', 0)}")
    return {**result, 'module': '02_honeypot'}


@router.get("/stats", summary="Time wasted by scammers and estimated impact")
def get_honeypot_stats(session_id: str | None = None):
    stats = honeypot_engine.get_session_stats(session_id)
    stats['module'] = '02_honeypot'
    stats['social_impact'] = {
        'description': 'Dolandırıcıların bu sayfada harcadığı her dakika, gerçek bir vatandaşın dolandırılmasını önler',
        'formula': '1 saat zaman kaybı = 12 potansiyel kurban kurtarıldı',
        'estimated_money_saved_tl': stats.get('estimated_money_saved_try', 0),
    }
    return stats


@router.post("/session/close", summary="Close a decoy session and return its report")
def close_honeypot_session(session_id: str):
    return {**honeypot_engine.close_session(session_id), 'module': '02_honeypot'}


@router.get("/decoy-types", response_model=DecoyTypes)
def get_decoy_types():
    return DecoyTypes(decoy_types=list(honeypot_engine.DECOY_TEMPLATES.keys()),
                      description='Her tuzak türü farklı dolandırıcı profiline hitap eder')


# ── IOC collection ────────────────────────────────────────────────────────

@router.post("/ioc/collect", response_model=IOCCollected, summary="Extract IOCs from a payload or free text")
def collect_ioc_data(req: IOCCollectRequest, request: Request, db: Session = Depends(get_db)):
    context = {'client_ip': service.client_ip(request), 'user_agent': request.headers.get('user-agent', '')[:500],
               'tags': req.tags or []}
    collected = honeypot_engine.collect_iocs(source=req.source, payload=req.payload, raw_text=req.raw_text or '', context=context)
    service.record_event(db, request, '/api/v2/ioc/collect', service.collect_note(req.source, len(collected), req.tags or []))
    return IOCCollected(collected_count=len(collected), collected=collected)


@router.get("/ioc/list", response_model=IOCList, summary="IOCs extracted by the honeypot")
def list_collected_iocs(ioc_type: str | None = None, limit: int = Query(100, ge=1, le=1000), min_count: int = Query(1, ge=1)):
    return IOCList(data=honeypot_engine.list_iocs(ioc_type=ioc_type, limit=limit, min_count=min_count))


@router.post("/ioc/fetch-external", response_model=ExternalFetchResult, summary="Pull IOCs from external feeds (admin)")
def fetch_external_iocs(req: IOCCollectorFetchRequest, db: Session = Depends(get_db), _: APIKey = Depends(require_admin)):
    try:
        collected = ioc_engine.collect_all(include_sources=req.sources, limit=req.limit_per_source)
    except Exception as exc:
        logger.exception('External IOC collection failed')
        raise HTTPException(502, 'Harici IOC kaynaklarına ulaşılamadı.') from exc
    stored = service.persist_external_iocs(db, ioc_engine, collected)
    logger.info('External IOC collection: %d collected, %d new', len(collected), stored)
    return ExternalFetchResult(collected=len(collected), persisted=stored, stats=ioc_engine.get_stats(),
                               samples=[ioc.to_dict() for ioc in collected[:10]])


@router.get("/ioc/list-collected", response_model=CollectedIOCPage, summary="Collector cache with filters")
def list_collected_iocs_advanced(
    ioc_type: str | None = None,
    threat_type: str | None = None,
    min_risk_score: int = Query(0, ge=0, le=100),
    source: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    iocs = service.filtered_collected(ioc_engine, ioc_type=ioc_type, threat_type=threat_type,
                                      min_risk_score=min_risk_score, source=source)
    page = iocs[offset:offset + limit]
    return CollectedIOCPage(total=len(iocs), returned=len(page), offset=offset, limit=limit,
                            iocs=[ioc.to_dict() for ioc in page])


@router.get("/ioc/stats-advanced", response_model=AdvancedStats)
def get_ioc_stats_advanced():
    stats = ioc_engine.get_stats()
    return AdvancedStats(statistics=stats, insights=service.stats_insights(stats))


@router.get("/ioc/search", response_model=IOCSearchResult, summary="Substring search over stored IOC values")
def search_ioc(q: str = Query(min_length=2, max_length=500), db: Session = Depends(get_db)):
    results = service.search_iocs(db, q)
    return IOCSearchResult(query=q, found=len(results), results=results)


@router.get("/ioc/by-risk-score", response_model=RiskBandResult, summary="Stored IOCs in a risk band")
def get_iocs_by_risk_level(level: RiskLevel, limit: int = Query(100, ge=1, le=1000), db: Session = Depends(get_db)):
    low, high = service.RISK_BANDS[level]
    iocs = service.iocs_in_band(db, level, limit)
    return RiskBandResult(risk_level=level, score_range={'min': low, 'max': high},
                          found=len(iocs), iocs=iocs)


# ── Dashboards ────────────────────────────────────────────────────────────

@router.get("/ioc/stats", response_model=IOCStatistics, summary="IOC dashboard aggregates")
def get_ioc_statistics(db: Session = Depends(get_db)):
    return service.ioc_statistics(db)


@router.get("/phishing/stats", response_model=PhishingStatistics, summary="Phishing URL dashboard aggregates")
def get_phishing_statistics(db: Session = Depends(get_db)):
    return service.phishing_statistics(db)
