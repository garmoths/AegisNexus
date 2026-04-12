import random
import string

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.deps import get_db
from app.fetch_data import verileri_guncelle
from app.models import PhishingURL
from app.scanner import calculate_safety_score
from app.url_normalize import normalize_url_record
from app.database import SessionLocal

router = APIRouter(tags=["threat-db"])


class SiteAddRequest(BaseModel):
    url: str
    target: str
    status: str


class URLCheckRequest(BaseModel):
    url: str


@router.post("/api/add-site")
def add_site(item: SiteAddRequest, db: Session = Depends(get_db)):
    if not item.url or not item.target:
        raise HTTPException(status_code=400, detail="URL ve Hedef boş olamaz")

    random_id = "".join(random.choices(string.digits, k=5))
    phish_id_gen = f"PHISH-{random_id}"

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
        return {"status": "success", "message": "Site başarıyla veritabanına eklendi!", "id": phish_id_gen}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Kayıt hatası: {str(e)}")


@router.post("/api/check-url")
def check_url(request: URLCheckRequest, db: Session = Depends(get_db)):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL boş olamaz")
    return calculate_safety_score(request.url, db)


@router.get("/stats/")
def get_stats(db: Session = Depends(get_db)):
    try:
        count = db.query(PhishingURL).count()
        return {"toplam_zararli_site": count}
    except Exception:
        return {"toplam_zararli_site": 0}


@router.get("/latest/")
def get_latest(limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    try:
        offset = (page - 1) * limit
        total = db.query(PhishingURL).count()
        items = db.query(PhishingURL).order_by(PhishingURL.id.desc()).offset(offset).limit(limit).all()
        total_pages = (total + limit - 1) // limit if limit else 1
        return {"data": items, "page": page, "total_pages": total_pages, "total": total}
    except Exception:
        return {"data": [], "page": 1, "total_pages": 1, "total": 0}


@router.get("/check/")
def db_check(url: str, limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    try:
        offset = (page - 1) * limit
        query = db.query(PhishingURL).filter(PhishingURL.url.contains(url))
        total = query.count()
        results = query.order_by(PhishingURL.id.desc()).offset(offset).limit(limit).all()
        if not results and page == 1:
            return {"status": "SAFE", "data": [], "page": 1, "total_pages": 0, "total": 0}
        total_pages = (total + limit - 1) // limit if limit else 1
        return {"status": "DANGER", "data": results, "page": page, "total_pages": total_pages, "total": total}
    except Exception:
        return {"status": "ERROR", "data": [], "page": 1, "total_pages": 0, "total": 0}


@router.post("/api/update-database")
async def update_database():
    try:
        added = verileri_guncelle()
        db = SessionLocal()
        total = db.query(PhishingURL).count()
        db.close()
        return {
            "status": "success",
            "yeni_eklenen": added,
            "toplam_kayit": total,
            "message": f"{added:,} yeni tehdit eklendi. Toplam: {total:,}",
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}
