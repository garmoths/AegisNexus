"""
Phishtank veri çekme modülü
JSON dosyasından veritabanına phishing URL'leri aktarır
"""
import json
import os
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from app.models import PhishingURL
from .url_normalize import normalize_url_record

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PHISHTANK_PATH = os.path.join(BASE_DIR, "phishtank.json")


def load_phishtank_data(filepath: Optional[str] = None) -> List[Dict]:
    """Phishtank JSON dosyasını yükle"""
    path = filepath or PHISHTANK_PATH
    
    if not os.path.exists(path):
        print(f"⚠️  Dosya bulunamadı: {path}")
        return []
    
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict) and 'data' in data:
                return data['data']
            return data if isinstance(data, list) else []
    except Exception as e:
        print(f" JSON yükleme hatası: {e}")
        return []


def import_to_database(db: Session, entries: List[Dict], batch_size: int = 1000) -> Dict:
    """Phishtank verilerini veritabanına aktar"""
    added = 0
    updated = 0
    errors = 0
    
    for i, entry in enumerate(entries):
        try:
            phish_id = str(entry.get('phish_id', ''))
            if not phish_id:
                continue
            
            # Mevcut kayıt var mı kontrol et
            existing = db.query(PhishingURL).filter(
                PhishingURL.phish_id == phish_id
            ).first()
            
            url = entry.get('url', '')
            normalized = normalize_url_record(url) if url else {}
            
            if existing:
                # Güncelle
                existing.url = url
                existing.url_hash = normalized.get('url_hash')
                existing.domain_norm = normalized.get('domain_norm')
                existing.status = entry.get('status', 'unknown')
                existing.online = entry.get('online', False)
                existing.target = entry.get('target', 'Unknown')
                updated += 1
            else:
                # Yeni kayıt
                new_entry = PhishingURL(
                    phish_id=phish_id,
                    url=url,
                    url_hash=normalized.get('url_hash'),
                    domain_norm=normalized.get('domain_norm'),
                    status=entry.get('status', 'unknown'),
                    online=entry.get('online', False),
                    target=entry.get('target', 'Unknown'),
                    submission_time=datetime.utcnow()
                )
                db.add(new_entry)
                added += 1
            
            # Batch commit
            if (i + 1) % batch_size == 0:
                db.commit()
                print(f"✅ İşlenen: {i + 1}/{len(entries)} (Eklendi: {added}, Güncellendi: {updated})")
                
        except Exception as e:
            errors += 1
            if errors <= 5:  # İlk 5 hatayı göster
                print(f"⚠️  Kayıt hatası ({phish_id}): {e}")
            continue
    
    # Son commit
    db.commit()
    
    return {
        "total": len(entries),
        "added": added,
        "updated": updated,
        "errors": errors
    }


def update_database_from_phishtank(db: Session, filepath: Optional[str] = None) -> Dict:
    """Ana fonksiyon - Phishtank verilerini veritabanına güncelle"""
    print("🔄 Phishtank verileri yükleniyor...")
    
    data = load_phishtank_data(filepath)
    if not data:
        return {"error": "Veri yüklenemedi", "added": 0, "updated": 0}
    
    print(f"📊 Toplam {len(data)} kayıt bulundu")
    print("💾 Veritabanına aktarılıyor...")
    
    result = import_to_database(db, data)
    
    print(f"\n✅ Tamamlandı!")
    print(f"   Eklendi: {result['added']}")
    print(f"   Güncellendi: {result['updated']}")
    print(f"   Hata: {result['errors']}")
    
    return result


if __name__ == "__main__":
    # Komut satırından çalıştırma
    from shared.utils.db import SessionLocal
    
    db = SessionLocal()
    try:
        result = update_database_from_phishtank(db)
        print(f"\nSonuç: {result}")
    finally:
        db.close()
