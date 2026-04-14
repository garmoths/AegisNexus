"""
01 - Phishing Detector Module Router
Tehdit veritabanı, URL tarama ve analiz endpointleri
"""
import uuid
import logging
from typing import List, Optional
from datetime import datetime, timedelta
from functools import wraps

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from shared.utils.db import get_db, SessionLocal
from app.models import PhishingURL
from .scanner import calculate_safety_score
from .url_normalize import normalize_url_record
from .fetch_data import update_database_from_phishtank
from .fetch_all_sources import fetch_all_sources

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
def add_site(item: SiteAddRequest, db: Session = Depends(get_db)):
    """Yeni phishing sitesi ekle"""
    if not item.url or not item.target:
        raise HTTPException(status_code=400, detail="URL ve Hedef boş olamaz")

    phish_id_gen = f"PHISH-{uuid.uuid4().hex[:12].upper()}"

    canon, uh, dn = normalize_url_record(item.url)
    stored_url = canon if canon else item.url.strip()

    new_site = PhishingURL(
        phish_id=phish_id_gen,
        url=stored_url,
        url_hash=uh,
        domain_norm=dn,
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
        result = calculate_safety_score(request.url, db)
        result["module"] = "01_phishing_detector"
        logger.info(f"URL kontrol yapıldı: {request.url} - Skor: {result.get('score')}")
        return result
    except Exception as e:
        logger.error(f"URL kontrol hatası: {str(e)}")
        raise HTTPException(status_code=500, detail="URL kontrol başarısız")


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Toplam zararlı site sayısı"""
    try:
        count = db.query(PhishingURL).count()
        return {
            "toplam_zararli_site": count,
            "module": "01_phishing_detector"
        }
    except Exception:
        return {"toplam_zararli_site": 0, "module": "01_phishing_detector"}


@router.get("/latest")
def get_latest(limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    """Son eklenen tehditler"""
    try:
        offset = (page - 1) * limit
        total = db.query(PhishingURL).count()
        items = db.query(PhishingURL).order_by(PhishingURL.id.desc()).offset(offset).limit(limit).all()
        total_pages = (total + limit - 1) // limit if limit else 1
        return {
            "data": items,
            "page": page,
            "total_pages": total_pages,
            "total": total,
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
def update_phishtank_database(db: Session = Depends(get_db)):
    """Phishtank JSON'dan veritabanını güncelle"""
    try:
        result = update_database_from_phishtank(db)
        return {
            "status": "success",
            "message": "Veritabanı güncellendi",
            "data": result,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "module": "01_phishing_detector"
        }





@router.post("/fetch-all")
def fetch_all_phishing_data(db: Session = Depends(get_db)):
    """Tum kaynaklardan phishing verileri cek (URLHaus, OpenPhish, TweetFeed, Phishtank)"""
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
