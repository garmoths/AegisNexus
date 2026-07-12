"""
Mevcut tüm VictimCase kayıtlarının severity_score'unu yeni mantıkla yeniden hesaplar.
Çalıştırmak için (sunucuda):
    cd /var/www/aegis_nexus && python scripts/rescore_cases.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.database import SessionLocal
from app.models import VictimCase

HIGH_KEYWORDS_1 = (
    "credential", "password", "account takeover", "bank", "wallet", "2fa",
    "şifre", "parola", "hesap ele geçir", "banka", "kart", "kimlik", "sms doğrulama",
)
HIGH_KEYWORDS_2 = (
    "ransomware", "financial", "payment", "wire", "crypto",
    "fidye", "ödeme", "havale", "kripto", "dolandırıcılık", "sahte",
)


def calc_severity(text: str) -> int:
    blob = (text or "").lower()
    sev = 60
    if any(k in blob for k in HIGH_KEYWORDS_1):
        sev += 15
    if any(k in blob for k in HIGH_KEYWORDS_2):
        sev += 15
    return max(0, min(100, sev))


def main():
    db = SessionLocal()
    try:
        cases = db.query(VictimCase).all()
        updated = 0
        for c in cases:
            blob = f"{c.case_title or ''} {c.narrative_summary or ''} {c.critical_warning or ''}"
            new_sev = calc_severity(blob)
            if c.severity_score != new_sev:
                c.severity_score = new_sev
                updated += 1
        db.commit()
        print(f"Tamamlandı: {len(cases)} vaka kontrol edildi, {updated} güncellendi.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
