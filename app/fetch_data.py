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

PHISHING_DB_SOURCES = {
    "phishing_db_links_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt",
    "phishing_db_domains_active": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "openphish": "https://openphish.com/feed.txt",
}


def fetch_from_url(name, url, timeout=60):
    """Tek bir kaynaktan URL listesi çeker."""
    print(f"   📡 [{name}] taranıyor...")
    try:
        r = requests.get(url, timeout=timeout)
        if r.status_code == 200:
            lines = [l.strip() for l in r.text.split('\n')
                     if l.strip() and not l.startswith("#") and not l.startswith("//")]
            print(f"   ✅ [{name}] {len(lines):,} kayıt bulundu.")
            return lines
        else:
            print(f"   ⚠️ [{name}] HTTP {r.status_code}")
    except Exception as e:
        print(f"   ❌ [{name}] Hata: {e}")
    return []


def fetch_online_sources():
    """Tüm kaynaklardan verileri çeker ve birleştirir."""
    all_urls = []
    for name, url in PHISHING_DB_SOURCES.items():
        urls = fetch_from_url(name, url)
        all_urls.extend(urls)
    return list(set(all_urls))  # Tekrarları temizle


def import_to_db(urls, source_tag="Unknown", batch_size=5000):
    """URL listesini veritabanına toplu olarak ekler."""
    db = SessionLocal()
    models.Base.metadata.create_all(bind=engine)

    try:
        # Mevcut URL'leri hafızaya al (hız için)
        print("   🔍 Mevcut kayıtlar kontrol ediliyor...")
        existing_urls = {x[0] for x in db.query(models.PhishingURL.url).all()}
        print(f"   📊 Veritabanında mevcut: {len(existing_urls):,} kayıt")

        new_items = []
        for url in urls:
            if url not in existing_urls:
                # Eğer domain ise (http ile başlamıyorsa) URL formatına çevir
                display_url = url if url.startswith("http") else f"http://{url}"

                new_items.append(models.PhishingURL(
                    phish_id=str(abs(hash(url))),
                    url=display_url,
                    status="active",
                    online=True,
                    target=source_tag,
                    submission_time=datetime.now()
                ))
                existing_urls.add(url)

        if new_items:
            print(f"   🔥 {len(new_items):,} adet YENİ site ekleniyor...")
            # Toplu ekleme (batch)
            for i in range(0, len(new_items), batch_size):
                batch = new_items[i:i + batch_size]
                db.bulk_save_objects(batch)
                db.commit()
                print(f"   💾 Batch {i // batch_size + 1}: {len(batch):,} kayıt eklendi.")
            print(f"   ✅ Toplam {len(new_items):,} yeni kayıt veritabanına eklendi!")
        else:
            print("   💤 Yeni bir tehdit yok, veritabanın zaten güncel.")

        return len(new_items)

    except Exception as e:
        print(f"   💥 Hata: {e}")
        db.rollback()
        return 0
    finally:
        db.close()


def verileri_guncelle():
    """Ana güncelleme fonksiyonu."""
    print(f"\n{'='*60}")
    print(f"⏰ GÜNCELLEME ZAMANI: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # 1. Tüm kaynaklardan verileri çek
    online_urls = fetch_online_sources()
    print(f"\n📦 Toplam benzersiz tehdit: {len(online_urls):,}")

    # 2. Veritabanına ekle
    added = import_to_db(online_urls, source_tag="Phishing.DB")

    print(f"\n{'='*60}")
    print(f"📊 SONUÇ: {added:,} yeni kayıt eklendi")
    print(f"{'='*60}\n")
    return added


# --- SONSUZ DÖNGÜ ---
if __name__ == "__main__":
    SAAT_ARALIGI = 4  # Kaç saatte bir güncellesin?

    print("🛡️ OTOMATİK KORUMA SİSTEMİ DEVREDE")
    print(f"Bilgisayar açık olduğu sürece her {SAAT_ARALIGI} saatte bir yeni veri çekecek.\n")

    while True:
        verileri_guncelle()

        print(f"⏳ Şimdi bekleme modu... ({SAAT_ARALIGI} saat)")
        time.sleep(SAAT_ARALIGI * 60 * 60)
