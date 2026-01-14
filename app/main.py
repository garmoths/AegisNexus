import os
from fastapi import FastAPI, Depends, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app import models, database

# YOL AYARLARI
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
templates_dir = os.path.join(BASE_DIR, "frontend", "templates")
static_dir = os.path.join(BASE_DIR, "frontend", "static")

app = FastAPI()

app.mount("/static", StaticFiles(directory=static_dir), name="static")
templates = Jinja2Templates(directory=templates_dir)


def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/stats/")
def get_stats(db: Session = Depends(get_db)):
    count = db.query(models.PhishingURL).count()
    return {"toplam_zararli_site": count}


# --- YENİ: EN SON EKLENENLERİ GETİR ---
@app.get("/latest/")
def get_latest(limit: int = 20, db: Session = Depends(get_db)):
    # ID'si en büyük olanlar (en son eklenenler) en üstte gelsin
    results = db.query(models.PhishingURL).order_by(desc(models.PhishingURL.id)).limit(limit).all()
    return {
        "status": "LATEST",
        "count": len(results),
        "data": results
    }


# --- ARAMA MOTORU (LİMİT ÖZELLİKLİ) ---
@app.get("/check/")
def check_url(url: str = Query(..., min_length=3), limit: int = 20, db: Session = Depends(get_db)):
    results = db.query(models.PhishingURL).filter(
        models.PhishingURL.url.ilike(f"%{url}%")
    ).limit(limit).all()

    if results:
        return {
            "status": "DANGER",
            "count": len(results),
            "data": results
        }
    else:
        return {
            "status": "SAFE",
            "count": 0,
            "message": "Temiz"
        }