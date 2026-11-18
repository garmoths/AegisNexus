"""
01 - Phishing Detector Module Router
Tehdit veritabanı, URL tarama ve analiz endpointleri
"""
import logging
import uuid
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app import runtime_store as store
from app.auth import resolve_api_key, resolve_optional_api_key
from app.models import APIKey, PhishingURL, PrivateScan
from app.outbound import UnsafeTarget, validate_url
from app.security import require_admin_api_key
from shared.utils.db import get_db

from .cache_db import (
    get_latest_phishing,
    get_phishing_stats,
    get_threat_type_distribution,
    persist_scan_result,
)
from .fetch_all_sources import fetch_all_sources
from .redis_cache import (
    redis_get_scan,
    redis_health,
    redis_invalidate_scan,
    redis_set_scan,
)
from .scanner import run_quick_checks
from .url_normalize import normalize_url_record

logger = logging.getLogger(__name__)

router = APIRouter(tags=["01-phishing-detector"])

class SiteAddRequest(BaseModel):
    url: str
    target: str
    status: str


class URLCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    force_fresh: bool = False


class URLCheckResponse(BaseModel):
    status: str
    score: float
    threat_level: str
    details: dict


@router.post("/add-site")
def add_site(
    item: SiteAddRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_api_key),
):
    """Yeni phishing sitesi ekle"""
    if not item.url or not item.target:
        raise HTTPException(status_code=400, detail="URL ve Hedef boş olamaz")

    phish_id_gen = f"PHISH-{uuid.uuid4().hex[:12].upper()}"

    normalized = normalize_url_record(item.url)
    stored_url = normalized.get("canonical_url", item.url.strip())

    new_site = PhishingURL(
        phish_id=phish_id_gen,
        url=stored_url,
        url_hash=normalized.get("url_hash"),
        domain_norm=normalized.get("domain_norm"),
        target=item.target,
        status=item.status,
        online=True if item.status == "ONLINE" else False,
    )

    try:
        db.add(new_site)
        db.commit()
        db.refresh(new_site)
        logger.info(f"Yeni phishing sitesi eklendi: {phish_id_gen}")
        return {
            "status": "success",
            "message": "Site başarıyla veritabanına eklendi!",
            "id": phish_id_gen,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Sitesi ekleme hatası: {str(e)}")
        raise HTTPException(status_code=500, detail="Kayıt hatası")


@router.post("/check-url")
def check_url(request: URLCheckRequest, db: Session = Depends(get_db), api_key: APIKey | None = Depends(resolve_optional_api_key)):
    try:
        requested_url, _, _, _ = validate_url(request.url, resolve=False)
    except UnsafeTarget as exc:
        raise HTTPException(422, str(exc))
    norm = normalize_url_record(requested_url)
    url_hash = norm.get('url_hash', '')
    if request.force_fresh:
        redis_invalidate_scan(url_hash)
    else:
        cached = redis_get_scan(url_hash)
        if cached and cached.get('score_version') == 2:
            cached['cache'] = 'shared-hit'
            record_private_scan(db, api_key, requested_url, cached)
            return cached
    quick = run_quick_checks(requested_url, db)
    if quick.get('definitive'):
        quick.update(status='complete', module='01_phishing_detector')
        if not persist_scan_result(requested_url, quick):
            raise HTTPException(503, 'Tarama sonucu kaydedilemedi.')
        redis_set_scan(url_hash, quick)
        record_private_scan(db, api_key, requested_url, quick)
        return quick
    # The lease covers queue wait plus the hard task deadline, not just browser time.
    existing = store.get('analyzing:' + url_hash)
    if existing:
        state = get_job_result(existing, None, db)
        if state.get('status') in ('queued', 'running', 'retrying'):
            return {**quick, 'status': 'analyzing', 'job_state': state['status'], 'job_id': existing}
        store.delete('analyzing:' + url_hash)
    job_id = str(uuid.uuid4())
    if not store.claim('analyzing:' + url_hash, job_id, 900):
        return {**quick, 'status': 'analyzing', 'job_id': store.get('analyzing:' + url_hash)}
    from .cache_db import set_celery_job
    stored = set_celery_job('job:' + job_id, {'status': 'queued', 'job_id': job_id, 'url': requested_url,
                                  'updated_at': datetime.utcnow().isoformat(), 'deadline': (datetime.utcnow() + timedelta(minutes=15)).isoformat()})
    if not stored:
        store.delete('analyzing:' + url_hash)
        raise HTTPException(503, 'İş kaydedilemedi.')
    try:
        from .celery_tasks import run_heavy_analysis
        run_heavy_analysis.apply_async((requested_url, job_id), queue='phishing', task_id=job_id,
                                      expires=900, retry=False)
    except Exception:
        store.delete('analyzing:' + url_hash)
        set_celery_job('job:' + job_id, {'status': 'failed', 'job_id': job_id, 'error': 'queue_unavailable'})
        # Do not run an unbounded scan inside the request when the worker is unavailable.
        raise HTTPException(503, 'Analiz kuyruğu kullanılamıyor. Lütfen daha sonra tekrar deneyin.')
    return {**quick, 'status': 'analyzing', 'job_state': 'queued', 'job_id': job_id, 'module': '01_phishing_detector'}


@router.get("/result/{job_id}")
def get_job_result(job_id: str, api_key: APIKey | None = Depends(resolve_optional_api_key), db: Session = Depends(get_db)):
    from .cache_db import get_celery_job, set_celery_job
    try:
        uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(422, 'Geçersiz iş kimliği.')
    result = get_celery_job('job:' + job_id)
    if result is None:
        return {'status': 'expired', 'job_id': job_id, 'message': 'İş bulunamadı veya saklama süresi doldu.'}
    if result.get('status') in ('queued', 'running', 'retrying'):
        deadline = result.get('deadline')
        if deadline and datetime.utcnow() > datetime.fromisoformat(deadline):
            result.update(status='timeout', error='job_deadline_exceeded')
            set_celery_job('job:' + job_id, result)
            if result.get('url'):
                store.delete('analyzing:' + normalize_url_record(result['url']).get('url_hash', ''))
    if result.get('status') == 'complete' and isinstance(api_key, APIKey):
        record_private_scan(db, api_key, result['url'], result, job_id)
    return result


def record_private_scan(db, api_key, url, result, job_id=None):
    if not isinstance(api_key, APIKey):
        return
    job_id = job_id or str(uuid.uuid4())
    if db.query(PrivateScan).filter_by(user_id=api_key.user_id, job_id=job_id).first():
        return
    risk = int(result.get('risk_score', 100-int(result.get('safety_score', result.get('score', 50)))))
    db.add(PrivateScan(user_id=api_key.user_id, job_id=job_id, url=url, risk_score=risk, risk_level=str(result.get('risk_level', 'unknown'))))
    db.commit()


@router.get("/cache-health")
def get_cache_health():
    """Redis ve SQLite cache durumunu döner (monitoring)."""
    from .cache_db import get_phishing_stats
    sqlite_stats = get_phishing_stats()
    from .playwright_pool import is_healthy as pw_healthy
    return {
        "cache": redis_health(),
        "sqlite": {
            "available": True,
            "total_urls": sqlite_stats.get("total_urls", 0),
            "today_scans": sqlite_stats.get("today_scans", 0),
        },
        "playwright_pool": {
            "browser_alive": pw_healthy(),
        },
        "module": "01_phishing_detector",
    }


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Dashboard istatistikleri (cache + tarama metrikleri)."""
    try:
        # Try cache_db first
        cache_stats = get_phishing_stats()
        if cache_stats["total_urls"] > 0:
            return {
                "stats": cache_stats,
                "module": "01_phishing_detector"
            }

        # Fallback to SQLAlchemy (yalnızca total_urls için)
        count = db.query(PhishingURL).count()
        return {
            "stats": {
                "total_urls": count,
                "phishing_count": cache_stats.get("phishing_count", 0),
                "safe_count": cache_stats.get("safe_count", 0),
                "today_scans": cache_stats.get("today_scans", 0)
            },
            "module": "01_phishing_detector"
        }
    except Exception:
        return {"stats": {"total_urls": 0, "phishing_count": 0, "safe_count": 0, "today_scans": 0}, "module": "01_phishing_detector"}


@router.get("/latest-paged")
def get_latest(limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    """Son eklenen tehditler"""
    try:
        limit = max(limit, 1)
        page = max(page, 1)
        offset = (page - 1) * limit
        status_rank = case(
            (func.lower(PhishingURL.status).in_(["active", "online"]), 0),
            (func.lower(PhishingURL.status) == "valid", 1),
            else_=2,
        )
        total = db.query(PhishingURL).count()
        items = (
            db.query(PhishingURL)
            .order_by(status_rank.asc(), PhishingURL.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        rows = [
            {
                "id": item.id,
                "url": item.url,
                "domain": item.domain_norm or item.url,
                "target": item.target or "Phishing",
                "status": item.status or "unknown",
                "submission_time": item.submission_time.isoformat() if item.submission_time else None,
            }
            for item in items
        ]
        total_pages = (total + limit - 1) // limit if limit else 1
        return {
            "data": rows,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "page_size": limit,
            "module": "01_phishing_detector"
        }
    except Exception:
        return {"data": [], "page": 1, "total_pages": 1, "total": 0, "module": "01_phishing_detector"}


@router.get("/search")
def search_urls(url: str, limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    """URL içinde arama yap (case-insensitive) - fast search without count()"""
    try:
        if not url:
            raise HTTPException(status_code=400, detail="Arama sorgusu boş olamaz")

        offset = (page - 1) * limit
        # Fast search - no count() for performance
        results = db.query(PhishingURL).filter(
            PhishingURL.url.ilike(f"%{url}%")
        ).order_by(PhishingURL.id.desc()).offset(offset).limit(limit).all()

        if not results and page == 1:
            logger.info(f"Arama sonuç yok: {url}")
            return {
                "status": "SAFE",
                "data": [],
                "page": 1,
                "total_pages": 0,
                "total": 0,
                "module": "01_phishing_detector"
            }

        # Approximate pagination - if we got full limit, there are more results
        has_more = len(results) == limit
        total = len(results) + (1 if has_more else 0)  # Approximate
        total_pages = page + (1 if has_more else 0)

        logger.info(f"Arama yapıldı: {url} - Sonuç: {len(results)}")
        return {
            "status": "DANGER" if results else "SAFE",
            "data": results,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Arama hatası: {str(e)}")
        return {
            "status": "ERROR",
            "data": [],
            "page": 1,
            "total_pages": 0,
            "total": 0,
            "module": "01_phishing_detector"
        }


@router.post("/update-db")
def update_phishtank_database(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_api_key),
):
    """Deprecated: Lokal PhishTank import kaldirildi."""
    return {
        "status": "deprecated",
        "message": "Lokal PhishTank JSON import kaldirildi. /fetch-all endpoint'ini kullanin.",
        "module": "01_phishing_detector"
    }





@router.post("/fetch-all")
def fetch_all_phishing_data(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_api_key),
):
    """Tum kaynaklardan phishing verileri cek (GitHub, OpenPhish, URLHaus, Kaggle, CertStream, OTX)"""
    try:
        result = fetch_all_sources(db)
        return {
            "status": "success",
            "message": f"Tum kaynaklardan {result['total_added']} yeni veri eklendi",
            "data": result,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "module": "01_phishing_detector"
        }


@router.get('/history')
@router.get('/scan-history')
def get_scan_history_paged(limit: int = Query(20, ge=1, le=100), page: int = Query(1, ge=1), days: int = Query(30, ge=1, le=365),
                           api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    query = db.query(PrivateScan).filter(PrivateScan.user_id == api_key.user_id, PrivateScan.created_at >= datetime.utcnow()-timedelta(days=days))
    total = query.count()
    rows = query.order_by(PrivateScan.created_at.desc()).offset((page-1)*limit).limit(limit).all()
    data = [{'url': r.url, 'risk_score': r.risk_score, 'safety_score': 100-r.risk_score, 'risk_level': r.risk_level,
             'checked_at': r.created_at.isoformat(), 'is_safe': r.risk_score <= 20} for r in rows]
    return {'data': data, 'history': data, 'total': total, 'page': page, 'total_pages': max(1,(total+limit-1)//limit)}


@router.get("/latest")
def get_latest_phishing_urls(limit: int = 20, db: Session = Depends(get_db)):
    """Son phishing URL'leri getir (gerçek PhishingURL tablosundan)"""
    try:
        # Use real PhishingURL table instead of cache
        items = db.query(PhishingURL).order_by(PhishingURL.id.desc()).limit(limit).all()

        latest = []
        for item in items:
            latest.append({
                'url': item.url,
                'domain': item.domain_norm or item.url,
                'risk_score': 85,  # Default high risk for known phishing
                'submission_time': item.submission_time.isoformat() if item.submission_time else datetime.now().isoformat(),
                'target': item.target or 'Phishing',
                'phish_id': item.phish_id,
                'status': item.status
            })

        return {
            "latest": latest,
            "limit": limit,
            "total": db.query(PhishingURL).count(),
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Latest fetch error: {e}")
        # Fallback to cache if main DB fails
        try:
            latest = get_latest_phishing(limit=limit)
            return {
                "latest": latest,
                "limit": limit,
                "module": "01_phishing_detector"
            }
        except Exception:
            return {
                "latest": [],
                "limit": limit,
                "module": "01_phishing_detector"
            }


@router.get("/threat-types")
def get_threat_types_distribution():
    """Tehdit tipi dağılımını getir (cache_db'den)"""
    try:
        types = get_threat_type_distribution()
        return {
            "types": types,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Threat types fetch error: {e}")
        return {
            "types": {},
            "module": "01_phishing_detector"
        }


@router.get("/skipped-urls")
def get_skipped_urls(days: int = 30):
    """Sources dolu ama risk_score=0 olan URL'leri tespit et"""
    try:
        from .cache_db import detect_skipped_urls
        skipped = detect_skipped_urls(days=days)
        return {
            "skipped": skipped,
            "count": len(skipped),
            "days": days,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Skipped URLs fetch error: {e}")
        return {
            "skipped": [],
            "count": 0,
            "days": days,
            "module": "01_phishing_detector"
        }


@router.get("/cleanup/analyze")
def analyze_cleanup(days: int = 30):
    """Kayıtları analiz et ve temizleme kriterlerine göre grupla"""
    try:
        from .cache_db import analyze_records
        analysis = analyze_records(days=days)
        return {
            "analysis": analysis,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Cleanup analysis error: {e}")
        return {
            "analysis": {
                "total_records": 0,
                "categories": {},
                "error": str(e)
            },
            "module": "01_phishing_detector"
        }


@router.post("/cleanup")
def perform_cleanup(days: int = 30, unscanned: bool = True, no_sources: bool = False, no_raw_data: bool = False, dry_run: bool = False):
    """Profesyonel cleanup - kriter bazlı temizleme"""
    try:
        from .cache_db import cleanup_records
        criteria = {
            'days': days,
            'unscanned': unscanned,
            'no_sources': no_sources,
            'no_raw_data': no_raw_data
        }
        result = cleanup_records(criteria, dry_run=dry_run)
        return {
            "result": result,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        return {
            "result": {
                "deleted": 0,
                "error": str(e)
            },
            "module": "01_phishing_detector"
        }
