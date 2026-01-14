import sys
import os
import requests
import time
from datetime import datetime

# YOL AYARLARI
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.append(project_root)

from app.database import SessionLocal, engine
from app import models


# --- KAYNAKLAR ---
def fetch_online_sources():
    urls = []
    print(f"   📡 [Online] URLHaus taranıyor...")
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/text_online/", timeout=20)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.split('\n') if l.strip() and not l.startswith("#")]
            urls.extend(lines)
    except:
        pass

    print(f"   📡 [Online] GitHub & OpenPhish taranıyor...")
    try:
        r = requests.get(
            "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/main/phishing-links/ACTIVE-PHISHING-URLS.txt",
            timeout=20)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.split('\n') if l.strip() and not l.startswith("#")]
            urls.extend(lines)
    except:
        pass

    try:
        r = requests.get("https://openphish.com/feed.txt", timeout=20)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.split('\n') if l.strip()]
            urls.extend(lines)
    except:
        pass

    return list(set(urls))  # Tekrarlayanları temizle ve döndür


def verileri_guncelle():
    print(f"\n⏰ GÜNCELLEME ZAMANI: {datetime.now().strftime('%H:%M:%S')}")

    # 1. Yeni verileri internetten çek
    online_urls = fetch_online_sources()
    print(f"📦 İnternette bulunan aktif tehdit sayısı: {len(online_urls)}")

    # 2. Veritabanını aç
    db = SessionLocal()
    models.Base.metadata.create_all(bind=engine)

    try:
        # 3. Bizde ZATEN VAR olanları hafızaya al (Hız için)
        existing_urls = {x[0] for x in db.query(models.PhishingURL.url).all()}

        new_items = []
        for url in online_urls:
            if url not in existing_urls:
                # Sadece bizde YOKSA ekle
                new_items.append(models.PhishingURL(
                    phish_id=str(abs(hash(url))),
                    url=url,
                    status="active",
                    online=True,
                    target="Unknown",
                    submission_time=datetime.now()
                ))
                existing_urls.add(url)  # Tekrar eklememek için listeye de ekle

        # 4. Kaydet
        if new_items:
            print(f"🔥 {len(new_items)} adet YENİ site bulundu ve ekleniyor...")
            db.bulk_save_objects(new_items)
            db.commit()
            print("✅ Veritabanı GÜNCELLENDİ.")
        else:
            print("💤 Yeni bir tehdit yok, veritabanın zaten güncel.")

    except Exception as e:
        print(f"💥 Hata: {e}")
        db.rollback()
    finally:
        db.close()


# --- SONSUZ DÖNGÜ ---
if __name__ == "__main__":
    SAAT_ARALIGI = 4  # Kaç saatte bir güncellesin?

    print("🛡️ OTOMATİK KORUMA SİSTEMİ DEVREDE")
    print(f"Bilgisayar açık olduğu sürece her {SAAT_ARALIGI} saatte bir yeni veri çekecek.\n")

    while True:
        verileri_guncelle()

        print(f"⏳ Şimdi bekleme modu... ({SAAT_ARALIGI} saat)")
        # Programı uyut (Saniye cinsinden)
        time.sleep(SAAT_ARALIGI * 60 * 60)
