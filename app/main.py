from fastapi import FastAPI, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from app import models, database

app = FastAPI()


# Veritabanı bağlantısı
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.get("/")
def read_root():
    return {"durum": "Canavar Gibi Çalışıyor! 🚀", "sahibi": "Enes"}


# 1. Özet Bilgi (Veritabanında kaç site var?)
@app.get("/stats/")
def get_stats(db: Session = Depends(get_db)):
    count = db.query(models.PhishingURL).count()
    return {"toplam_zararli_site": count, "mesaj": "Veritabanı dolu ve hazır!"}


# 2. SORGULAMA MOTORU (Chrome Eklentisi bunu kullanacak)
# Örnek kullanım: /check/?url=http://kotu-site.com
@app.get("/check/")
def check_url(url: str = Query(..., description="Kontrol edilecek site adresi"), db: Session = Depends(get_db)):
    # Veritabanında bu URL var mı diye bakıyoruz
    # (Tam eşleşme arıyoruz)
    site = db.query(models.PhishingURL).filter(models.PhishingURL.url == url).first()

    if site:
        return {
            "result": "DANGER",
            "message": "⚠️ DİKKAT! Bu site veritabanımızda kayıtlı!",
            "details": {
                "target": site.target,
                "status": site.status
            }
        }
    else:
        return {
            "result": "SAFE",
            "message": "✅ Temiz görünüyor (veya henüz listemize düşmedi)."
        }


# 3. Son Eklenen 50 Siteyi Gör (Hepsini değil, bilgisayar donmasın)
@app.get("/latest/")
def get_latest(db: Session = Depends(get_db)):
    siteler = db.query(models.PhishingURL).order_by(models.PhishingURL.id.desc()).limit(50).all()
    return siteler