import os
import random
import string
from pathlib import Path
from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import desc

# Senin dosyalarından importlar
from app.database import SessionLocal, engine, Base
from app.models import PhishingURL
from app.scanner import calculate_safety_score

# Veritabanı tablolarını oluştur
try:
    Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"DB Bilgisi: {e}")

app = FastAPI()

# ========================================================
# 1. DOSYA YOLLARI
# ========================================================
# Bu dosya (main.py) neredeyse, bir üst klasöre çıkıp frontend'i oradan bulur.
BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "frontend" / "static"
HTML_FILE = BASE_DIR / "frontend" / "templates" / "index.html"

# Terminale dosya yolunu yazdıralım ki emin olalım
print(f"DEBUG -> HTML Dosyası şurada aranıyor: {HTML_FILE}")

# Static klasör bağlantısı
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    print(f"UYARI: Static klasörü bulunamadı: {STATIC_DIR}")


# ========================================================
# 2. VERİTABANI BAĞLANTISI
# ========================================================
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ========================================================
# 3. YENİ BÖLÜM: SİTE EKLEME İŞLEMİ (/api/add-site)
# ========================================================

# Frontend'den gelecek veri modeli
class SiteAddRequest(BaseModel):
    url: str
    target: str
    status: str


@app.post("/api/add-site")
def add_site(item: SiteAddRequest, db: Session = Depends(get_db)):
    # Boş veri kontrolü
    if not item.url or not item.target:
        raise HTTPException(status_code=400, detail="URL ve Hedef boş olamaz")

    # Rastgele benzersiz bir ID oluştur (Örn: PHISH-9482)
    random_id = ''.join(random.choices(string.digits, k=5))
    phish_id_gen = f"PHISH-{random_id}"

    # Veritabanı nesnesini hazırla
    new_site = PhishingURL(
        phish_id=phish_id_gen,
        url=item.url,
        target=item.target,
        status=item.status,
        online=True if item.status == "ONLINE" else False
    )

    try:
        db.add(new_site)
        db.commit()
        db.refresh(new_site)
        return {"status": "success", "message": "Site başarıyla veritabanına eklendi!", "id": phish_id_gen}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Kayıt hatası: {str(e)}")


# ========================================================
# 4. DİĞER API ENDPOINTLERİ
# ========================================================

class URLCheckRequest(BaseModel):
    url: str


# 👇 DÜZELTİLEN KISIM BURASI 👇
@app.post("/api/check-url")
def check_url(request: URLCheckRequest, db: Session = Depends(get_db)):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL boş olamaz")

    # Artık 'db' değişkenini scanner'a gönderiyoruz!
    return calculate_safety_score(request.url, db)


@app.get("/stats/")
def get_stats(db: Session = Depends(get_db)):
    try:
        count = db.query(PhishingURL).count()
        return {"toplam_zararli_site": count}
    except Exception as e:
        print(f"DB Hatası: {e}")
        return {"toplam_zararli_site": 0}


@app.get("/latest/")
def get_latest(limit: int = 20, db: Session = Depends(get_db)):
    try:
        items = db.query(PhishingURL).order_by(PhishingURL.id.desc()).limit(limit).all()
        return {"data": items}
    except Exception:
        return {"data": []}


@app.get("/check/")
def db_check(url: str, limit: int = 20, db: Session = Depends(get_db)):
    try:
        results = db.query(PhishingURL).filter(PhishingURL.url.contains(url)).limit(limit).all()
        if not results:
            return {"status": "SAFE", "data": []}
        return {"status": "DANGER", "data": results}
    except Exception:
        return {"status": "ERROR", "data": []}


# ========================================================
# 5. ANA SAYFA
# ========================================================
@app.get("/")
async def read_root():
    if HTML_FILE.exists():
        return FileResponse(HTML_FILE)

    return {
        "Hata": "index.html bulunamadı.",
        "Aranan_Yol": str(HTML_FILE),
        "Mevcut_Klasor": str(BASE_DIR)
    }
