"""
01 - Phishing Detector Module Router
Tehdit veritabanı, URL tarama ve analiz endpointleri
"""
import uuid
import logging
from datetime import datetime, timedelta
from functools import wraps

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import case, func

from shared.utils.db import get_db
from app.models import PhishingURL
from app.security import require_admin_api_key
from .scanner import calculate_safety_score
from .url_normalize import normalize_url_record
from .fetch_all_sources import fetch_all_sources
from .cache_db import (
    get_cached_scan_result,
    get_phishing_history,
    get_latest_phishing,
    get_threat_type_distribution,
    get_phishing_stats,
    get_scan_history,
    write_phishing_url,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["01-phishing-detector"])

# Rate limiting depolama (in-memory)
RATE_LIMIT_STORAGE = {}


class SiteAddRequest(BaseModel):
    url: str
    target: str
    status: str


class URLCheckRequest(BaseModel):
    url: str


class URLCheckResponse(BaseModel):
    status: str
    score: float
    threat_level: str
    details: dict


# Rate limiting decorator
def rate_limit(max_requests: int, time_window: int):
    """Rate limiting decorator (requests per time_window seconds)"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = datetime.now()
            client_id = kwargs.get('db').__hash__() if 'db' in kwargs else str(args)
            
            if client_id not in RATE_LIMIT_STORAGE:
                RATE_LIMIT_STORAGE[client_id] = []
            
            # Eski requests'i temizle
            cutoff_time = now - timedelta(seconds=time_window)
            RATE_LIMIT_STORAGE[client_id] = [
                req_time for req_time in RATE_LIMIT_STORAGE[client_id]
                if req_time > cutoff_time
            ]
            
            # Limiti kontrol et
            if len(RATE_LIMIT_STORAGE[client_id]) >= max_requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {max_requests} requests per {time_window}s"
                )
            
            RATE_LIMIT_STORAGE[client_id].append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator


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
@rate_limit(max_requests=60, time_window=60)
def check_url(request: URLCheckRequest, db: Session = Depends(get_db)):
    """URL güvenlik skorunu hesapla"""
    if not request.url:
        raise HTTPException(status_code=400, detail="URL boş olamaz")
    try:
        requested_url = request.url.strip()
        cached_result = get_cached_scan_result(requested_url, days=30)
        if cached_result:
            sources = []
            for src in cached_result.get("sources", []):
                if isinstance(src, dict):
                    name = src.get("name")
                    if name:
                        sources.append(str(name))
                elif isinstance(src, str):
                    sources.append(src)
            write_phishing_url(
                url=requested_url,
                risk_score=int(cached_result.get("score", 0)),
                risk_level=str(cached_result.get("risk_level", "unknown")),
                is_safe=bool(cached_result.get("score", 0) >= 80),
                sources=sources,
                raw_data=cached_result,
                track_event=True,
            )
            cached_result["module"] = "01_phishing_detector"
            cached_result["cache"] = "30d-hit"
            logger.info(f"URL cache hit: {requested_url}")
            return cached_result

        result = calculate_safety_score(requested_url, db)
        sources = []
        for src in result.get("sources", []):
            if isinstance(src, dict):
                name = src.get("name")
                if name:
                    sources.append(str(name))
        write_phishing_url(
            url=requested_url,
            risk_score=int(result.get("score", 0)),
            risk_level=str(result.get("risk_level", "unknown")),
            is_safe=bool(result.get("score", 0) >= 80),
            sources=sources,
            raw_data=result,
            track_event=True,
        )
        result["module"] = "01_phishing_detector"
        logger.info(f"URL kontrol yapıldı: {requested_url} - Skor: {result.get('score')}")
        return result
    except Exception as e:
        logger.error(f"URL kontrol hatası: {str(e)}")
        write_phishing_url(
            url=request.url.strip(),
            risk_score=50,
            risk_level="degraded",
            is_safe=False,
            sources=["degraded"],
            raw_data={"error": str(e)},
            track_event=True,
        )
        # Fail-soft: UI'nin tamamen kırılmasını engellemek için degrade yanıt döndür.
        return {
            "status": "degraded",
            "url": request.url,
            "score": 50,
            "risk_level": "medium",
            "details": ["Harici kaynak hatası veya gecikmesi nedeniyle kısmi sonuç döndürüldü."],
            "sources": [],
            "module": "01_phishing_detector",
        }


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Toplam zararlı site sayısı"""
    try:
        # Try cache_db first
        cache_stats = get_phishing_stats()
        if cache_stats["total_urls"] > 0:
            return {
                "stats": cache_stats,
                "module": "01_phishing_detector"
            }
        
        # Fallback to SQLAlchemy
        count = db.query(PhishingURL).count()
        return {
            "stats": {
                "total_urls": count,
                "phishing_count": count,
                "safe_count": 0,
                "today_scans": 0
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
    """URL içinde arama yap (case-insensitive)"""
    try:
        if not url:
            raise HTTPException(status_code=400, detail="Arama sorgusu boş olamaz")
        
        offset = (page - 1) * limit
        # Case-insensitive arama
        query = db.query(PhishingURL).filter(
            PhishingURL.url.ilike(f"%{url}%")
        )
        total = query.count()
        results = query.order_by(PhishingURL.id.desc()).offset(offset).limit(limit).all()
        
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
        
        total_pages = (total + limit - 1) // limit if limit else 1
        logger.info(f"Arama yapıldı: {url} - Sonuç: {total}")
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


@router.get("/history")
def get_phishing_scan_history(limit: int = 50, days: int = 30, db: Session = Depends(get_db)):
    """URL tarama geçmişini getir (threat_intel_cache.db)."""
    try:
        history_page = get_scan_history(limit=limit, page=1, days=days)
        return {
            "history": history_page["data"],
            "limit": limit,
            "days": days,
            "total": history_page["total"],
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"History fetch error: {e}")
        # Fallback to cache if main DB fails
        try:
            history = get_phishing_history(limit=limit, days=days)
            return {
                "history": history,
                "limit": limit,
                "days": days,
                "module": "01_phishing_detector"
            }
        except:
            return {
                "history": [],
                "limit": limit,
                "days": days,
                "module": "01_phishing_detector"
            }


@router.get("/scan-history")
def get_scan_history_paged(limit: int = 20, page: int = 1, days: int = 30):
    """Paginated URL scan history for frontend chips/list."""
    try:
        result = get_scan_history(limit=limit, page=page, days=days)
        result["module"] = "01_phishing_detector"
        return result
    except Exception as e:
        logger.error(f"Scan history fetch error: {e}")
        return {
            "data": [],
            "page": 1,
            "total_pages": 0,
            "total": 0,
            "limit": limit,
            "module": "01_phishing_detector",
        }


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
        except:
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
