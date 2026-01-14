import re
import json
import os
import requests
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.models import PhishingURL

# =========================================================
# AYARLAR VE JSON YÜKLEME
# =========================================================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHISHTANK_PATH = os.path.join(BASE_DIR, "phishtank.json")

PHISHTANK_DB = set()
try:
    if os.path.exists(PHISHTANK_PATH):
        with open(PHISHTANK_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            for entry in data:
                u = entry['url']
                clean_u = u.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]
                PHISHTANK_DB.add(clean_u)
except Exception:
    pass


# =========================================================
# ANA ANALİZ FONKSİYONU
# =========================================================
def calculate_safety_score(input_url, db: Session = None):
    # 0. URL DÜZENLEME
    input_url = input_url.strip().lower()  # Küçük harfe çevir

    # Eğer protokol yoksa ekle (analiz için)
    if not input_url.startswith(("http://", "https://")):
        check_url = "https://" + input_url
    else:
        check_url = input_url

    parsed = urlparse(check_url)
    domain = parsed.netloc or parsed.path
    domain = domain.replace("www.", "")

    # Kullanıcı sadece "youtube" yazdıysa domain "youtube" olur, bunu da koruyalım
    raw_domain = input_url.replace("https://", "").replace("http://", "").replace("www.", "").split('/')[0]

    # ---------------------------------------------------------
    # 1. KATMAN: WHITELIST (BEYAZ LİSTE)
    # ---------------------------------------------------------
    # Buraya popüler sitelerin hem uzantılı hem uzantısız hallerini ekliyoruz
    safe_domains = [
        "google", "google.com",
        "youtube", "youtube.com",
        "facebook", "facebook.com",
        "twitter", "twitter.com", "x.com",
        "instagram", "instagram.com",
        "linkedin", "linkedin.com",
        "github", "github.com",
        "microsoft", "microsoft.com",
        "apple", "apple.com",
        "amazon", "amazon.com",
        "netflix", "netflix.com",
        "stackoverflow", "stackoverflow.com",
        "wikipedia", "wikipedia.org",
        "whatsapp", "whatsapp.com",
        "turkiye.gov.tr", "enabiz.gov.tr",
        "ziraatbank.com.tr", "garantibbva.com.tr", "isbank.com.tr"
    ]

    # Eşleşme kontrolünü genişletiyoruz (Tam eşleşme veya .com ile biten)
    is_safe = False
    if raw_domain in safe_domains:
        is_safe = True
    elif any(safe in domain for safe in safe_domains):
        # Ancak burada dikkatli olalım, "fake-google.com" da "google" içerir.
        # Bu yüzden sadece domainin sonu güvenli listeyle bitiyor mu diye bakalım.
        for safe in safe_domains:
            if domain == safe or domain.endswith("." + safe):
                is_safe = True
                break

    if is_safe:
        return {
            "url": input_url, "score": 100, "risk_level": "Güvenli (Doğrulanmış)",
            "details": ["Güvenilir Siteler Listesinde (Whitelist) mevcut.", "Resmi Kurum."],
            "sources": [{"name": "Whitelist", "status": "Temiz"}]
        }

    # ---------------------------------------------------------
    # 2. KATMAN: INTERNAL DB (SENİN VERİTABANIN)
    # ---------------------------------------------------------
    if db:
        # DÜZELTME BURADA: .contains yerine daha katı bir kontrol yapıyoruz.
        # "youtube" yazınca içinde "youtube" geçen her şeyi getirmesin.
        # Kullanıcının girdiği URL birebir veritabanındaki kötü URL mi?

        # 1. Tam eşleşme ara
        match = db.query(PhishingURL).filter(PhishingURL.url == input_url).first()

        # 2. Eğer tam eşleşme yoksa, domain bazlı ara ama dikkatli ol
        if not match:
            # Veritabanında bu domaini içeren kayıtları getir ama "youtube" gibi kısa kelimeleri filtreleme
            if len(input_url) > 6:  # Çok kısa kelimelerde partial search yapma
                potential_matches = db.query(PhishingURL).filter(PhishingURL.url.contains(input_url)).limit(5).all()
                for pm in potential_matches:
                    # Bulunan kötü site, bizim girdiğimiz siteyle aynı mı veya onun alt sayfası mı?
                    if pm.url == input_url or input_url.startswith(pm.url):
                        match = pm
                        break

        if match:
            return {
                "url": input_url,
                "score": 0,
                "risk_level": "ÇOK TEHLİKELİ (DB Kayıtlı)",
                "details": [
                    f"Bu site veritabanınızda tespit edildi! (ID: {match.phish_id})",
                    f"Hedef: {match.target}",
                    "Veritabanı eşleşmesi sağlandı."
                ],
                "sources": [{"name": "INTERNAL DB", "status": "TEHDİT 🚨"}]
            }

    # ---------------------------------------------------------
    # 3. KATMAN: PHISHTANK (JSON)
    # ---------------------------------------------------------
    if domain in PHISHTANK_DB:
        return {
            "url": input_url, "score": 0, "risk_level": "ÇOK TEHLİKELİ",
            "details": ["Bu site global kara listede (PhishTank) mevcut!", "Veri girmeyiniz."],
            "sources": [{"name": "PhishTank", "status": "TEHDİT 🚨"}]
        }

    # ---------------------------------------------------------
    # 4. KATMAN: CANLILIK TESTİ
    # ---------------------------------------------------------
    site_is_up = False
    try:
        response = requests.get(check_url, timeout=3)
        if response.status_code < 400: site_is_up = True
    except:
        site_is_up = False

    if not site_is_up:
        return {
            "url": input_url, "score": 0, "risk_level": "Siteye Ulaşılamıyor",
            "details": ["Böyle bir site bulunamadı veya sunucusu kapalı."],
            "sources": [{"name": "Ping", "status": "Başarısız ❌"}]
        }

    # ---------------------------------------------------------
    # 5. KATMAN: MANTIKSAL ANALİZ
    # ---------------------------------------------------------
    score = 90
    risks = []

    if check_url.startswith("http://"):
        score -= 25
        risks.append("Güvensiz (HTTP) bağlantı.")

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        score -= 40
        risks.append("IP adresi kullanılıyor.")

    if len(input_url) > 75:
        score -= 10
        risks.append("URL çok uzun.")

    suspicious = ["login", "giris", "verify", "onay", "bank", "account", "hesap", "update", "bonus"]
    found = [w for w in suspicious if w in input_url.lower()]
    if found:
        score -= 20
        risks.append(f"Şüpheli kelimeler: {', '.join(found)}")

    final_score = max(0, min(100, score))
    risk_level = "Güvenli"
    if final_score < 50:
        risk_level = "Tehlikeli"
    elif final_score < 80:
        risk_level = "Şüpheli"

    if not risks: risks.append("Temiz görünüyor.")

    return {
        "url": input_url, "score": final_score, "risk_level": risk_level, "details": risks,
        "sources": [{"name": "AI Analiz", "status": "Tamamlandı"}]
    }
