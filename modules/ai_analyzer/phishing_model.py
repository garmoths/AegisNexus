
"""
ML-Powered Phishing Detection Model
Random Forest + TF-IDF with balanced training data + URL feature engineering
"""
import os, json, re, logging
import numpy as np
from typing import Dict, List
from collections import Counter

logger = logging.getLogger(__name__)

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    import joblib
    import tldextract
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

class PhishingMLModel:
    ML_WEIGHT = 0.40
    URL_WEIGHT = 0.35
    TEXT_WEIGHT = 0.25
    
    MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.joblib")
    VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), "tfidf_vectorizer.joblib")
    
    def __init__(self):
        self.model = None
        self.vectorizer = None
        self.is_trained = False
        if ML_AVAILABLE:
            self._load_or_create()
    
    def _load_or_create(self):
        if os.path.exists(self.MODEL_PATH) and os.path.exists(self.VECTORIZER_PATH):
            try:
                self.model = joblib.load(self.MODEL_PATH)
                self.vectorizer = joblib.load(self.VECTORIZER_PATH)
                self.is_trained = True
                logger.info("ML model loaded from disk")
                return
            except:
                pass
        logger.info("Training new ML model...")
        self._train_model()
    
    def _train_model(self):
        phishing = [
            "Hesabiniz askiya alindi. Hemen tiklayin: http://bit.ly/2xK9mQ",
            "Sifrenizi guncelleyin: https://guvenlik-bankasi.com/verify",
            "ACIL! Hesabiniz 24 saat icinde kapatilacak. Dogrulama: http://tinyurl.com/y8k9m",
            "Kredi karti bilgilerinizi dogrulayin. http://akbank-guncelleme.com/login",
            "Odul kazandiniz! Hemen alin: http://hediye-kampanya.tk/kazan",
            "Hesabiniz bloke edildi. https://guvenlik-dogrulama.com/hesap",
            "Son uyari! Hesabiniz silinecek. http://hesap-kurtar.ml/confirm",
            "Sifrenizi onaylayin: https://ziraat-hesap.net/giris",
            "Faturaniz odenmemis, kapatilacak: http://fatura-odeme.tk",
            "Hesabiniz dogrulanmadi. https://whatsapp-dogrulama.com/verify",
            "Sifrenizi degistirin: http://instagram-guvenlik.tk",
            "Kargonuz teslim edilemedi. Bilgileri guncelleyin: https://kargo-guncelle.com",
            "Uyeliginiz sonlandirilacak. http://netflix-hesap.tk/odeme",
            "Hesabiniz kilitlendi. https://apple-id-dogrulama.com",
            "Supheli giris. https://google-hesap-guvenlik.com",
            "Account compromised! Verify: http://secure-login.tk",
            "PayPal account limited. http://paypal-verify.ml",
            "You won prize! Claim: http://prize-claim.tk/winner",
            "Password stolen. Reset: http://password-reset.ga",
            "Account verification: http://bit.ly/3xK9mQ",
            "Package waiting: http://fedex-update.ml",
            "iCloud unknown device: http://icloud-verify.tk",
            "Payment failed: http://netflix-billing.ml",
            "Hesabiniz askiya alindi: https://guvenlik-hesap.com/verify",
            "Supheli islem tespit edildi. Sifre degistirin: http://sifre-yenile.tk",
            "Kartiniz bloke oldu. Aktif edin: http://kart-aktif.ml",
            "3 basarisiz giris. Sifre sifirlayin: http://sifre-sifirla.tk",
            "Hesabiniz bloke! Tikla: http://bit.ly/3kL9mQ",
            "Kargonuz dagitimda. Adres dogrulama: http://tiny.cc/kargoadres",
            "Telefon numaraniz odul kazandi! http://hediye.tk",
        ]
        safe = [
            "Merhaba, yarin saat 14:00da toplanti Zoom: https://zoom.us/j/987654321",
            "Toplanti odasi degisti. Oda B-302 saat 10:30. Zoom: https://zoom.us/j/123456",
            "Fatura 250TL. Son odeme 15 Mayis. https://sirket.com/faturalar",
            "Siparisiniz kargoya verildi. https://kargo.com/TRK123456",
            "Makale duzeltmeleri tamamlandi. Dropbox: https://dropbox.com/s/abc",
            "App Store guncellemesi: https://apps.apple.com/tr/app/123",
            "Aylik bulten: https://sirket.com/bulten",
            "Dokumanlar: https://docs.google.com/document/d/123",
            "Proje yonetimi: https://trello.com/b/abc123",
            "Kaynak kod: https://github.com/kullanici/proje",
            "Basvurunuz alinmistir. En kisa surede donus.",
            "Proje teslim tarihi haftaya pazartesi.",
            "Yemek siparisiniz yolda. 20 dakika.",
            "Aylik bultenimiz yayinda.",
            "Is basvurunuz alindi. Donus yapilacak.",
            "Sozlesme guncellenmistir.",
            "Isbirligi teklifiniz icin tesekkurler.",
            "Hesap ozetiniz ektedir. Bu ay 1250TL.",
            "TK1924 sefer sayili ucunuz zamaninda.",
            "Veli toplantisi 20 Martta okulda.",
            "Yillik izin talep formunu doldurun.",
            "Bu ayki faturaniz 89.90TL.",
            "Deadline next Friday.",
            "Order 12345 shipped. https://shop.com/track/12345",
            "Stand-up 9:30. Google Meet: https://meet.google.com/abc",
            "Password changed successfully.",
            "Purchase receipt on our website.",
            "Training module: https://training.company.com",
            "Appointment March 15 at 2:00 PM.",
            "Newsletter: https://blog.company.com/security",
            "Maintenance Sunday: https://status.company.com",
            "Earnings report: https://investor.company.com/q1",
            "Nasilsin? Hafta sonu bulusalim mi?",
            "Sinav sonuclari: https://ogr.istanbul.edu.tr/sonuc",
            "ODTU web sitesi: https://www.metu.edu.tr",
            "Yarin hava yagmurlu olacak.",
            "Dogum gunun kutlu olsun!",
            "Piknige gidelim mi? Herkes gelecek.",
            "Kitap kulubu cumartesi 15:00. Zoom: https://zoom.us/j/555",
            "Toplanti notlari ektedir. Gorusmek uzere.",
            "Proje dosyasi guncellendi. Inceleyin.",
            "Yillik degerlendirme toplantisi persembe.",
            "Butce onayi icin imzalamaniz gerekiyor.",
            "Yeni surum yayinda. Guncelleyin.",
            "Musteri memnuniyet anketi. Katilim kazan.",
            "Sertifikaniz hazir: https://sirket.com/sertifika",
            "Haftalik rapor: https://rapor.sirket.com/hafta",
            "Sirket ici duyuru: Yemek listesi ektedir.",
            "Egitim videosu: https://video.sirket.com/egitim",
            "Ogrenci bilgi sistemi: https://obs.istanbul.edu.tr",
            "E-devlet kapisi: https://www.turkiye.gov.tr",
        ]
        
        all_texts = phishing + safe
        all_labels = [1]*len(phishing) + [0]*len(safe)
        
        self.vectorizer = TfidfVectorizer(
            max_features=5000, ngram_range=(1, 4),
            analyzer="char_wb", sublinear_tf=True,
            max_df=0.85, min_df=1,
            strip_accents="unicode",
            token_pattern=r"(?u)\b\w+\b"
        )
        X = self.vectorizer.fit_transform(all_texts)
        
        self.model = RandomForestClassifier(
            n_estimators=300, max_depth=20,
            min_samples_split=5, min_samples_leaf=2,
            class_weight="balanced", random_state=42, n_jobs=-1
        )
        self.model.fit(X, all_labels)
        self.is_trained = True
        logger.info(f"ML model trained on {len(all_texts)} samples")
        
        try:
            os.makedirs(os.path.dirname(self.MODEL_PATH), exist_ok=True)
            joblib.dump(self.model, self.MODEL_PATH)
            joblib.dump(self.vectorizer, self.VECTORIZER_PATH)
        except:
            pass
    
    def extract_url_features(self, text: str) -> Dict:
        features = {
            "has_url": 0.0, "url_count": 0.0, "has_https": 0.0,
            "has_ip": 0.0, "num_dots": 0.0, "num_hyphens": 0.0,
            "url_length": 0.0, "has_suspicious_tld": 0.0,
            "has_shortener": 0.0, "has_phishing_path": 0.0,
            "has_brand": 0.0, "has_at": 0.0, "num_params": 0.0,
            "has_redirect": 0.0, "subdomain_len": 0.0,
        }
        urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", text)
        
        if not urls:
            return features
        
        features["has_url"] = 1.0
        features["url_count"] = float(len(urls))
        
        for url in urls:
            domain = url.split("//")[-1].split("/")[0].lower() if "//" in url else url.lower()
            features["has_https"] = max(features["has_https"], 1.0 if url.startswith("https://") else 0.0)
            features["has_ip"] = max(features["has_ip"], 1.0 if re.match(r"^\d+\.\d+\.\d+\.\d+", domain) else 0.0)
            features["num_dots"] = max(features["num_dots"], float(url.count(".")))
            features["num_hyphens"] = max(features["num_hyphens"], float(url.count("-")))
            features["url_length"] = max(features["url_length"], float(len(url)))
            
            suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click", ".link"]
            features["has_suspicious_tld"] = max(features["has_suspicious_tld"],
                1.0 if any(tld in url.lower() for tld in suspicious_tlds) else 0.0)
            
            shorteners = ["bit.ly", "tinyurl", "tiny.cc", "is.gd", "ow.ly", "buff.ly", "rb.gy"]
            features["has_shortener"] = max(features["has_shortener"],
                1.0 if any(s in url.lower() for s in shorteners) else 0.0)
            
            phishing_paths = ["/verify", "/confirm", "/login", "/auth", "/secure",
                "/update", "/account", "/password", "/reset", "/activate",
                "/giris", "/hesap", "/dogrulama", "/guncelle", "/odeme", "/sifre", "/onay"]
            path_part = url.split(domain)[-1] if domain in url else ""
            features["has_phishing_path"] = max(features["has_phishing_path"],
                1.0 if any(pp in path_part.lower() for pp in phishing_paths) else 0.0)
            
            try:
                ext = tldextract.extract(url)
                features["subdomain_len"] = max(features["subdomain_len"], float(len(ext.subdomain)))
            except:
                pass
            
            brand_words = ["apple", "icloud", "google", "microsoft", "paypal", "netflix", "amazon",
                "akbank", "garanti", "isbank", "ziraat", "vakifbank", "halkbank", "yapikredi",
                "instagram", "facebook", "whatsapp", "twitter", "linkedin", "spotify",
                "turkcell", "vodafone", "turktelekom", "devlet", "sgk", "ptt", "edevlet",
                "guvenlik", "hesap", "dogrulama", "onay", "sifre", "odeme", "kargo"]
            features["has_brand"] = max(features["has_brand"],
                1.0 if any(b in domain for b in brand_words) else 0.0)
            
            features["has_at"] = max(features["has_at"], 1.0 if "@" in url else 0.0)
            if "?" in url:
                q = url.split("?")[-1]
                features["num_params"] = max(features["num_params"], float(len(q.split("&"))))
            if re.search(r"redirect|url=|link=|goto=", url.lower()):
                features["has_redirect"] = max(features["has_redirect"], 1.0)
        
        return features
    
    def predict(self, text: str) -> Dict:
        result = {
            "is_phishing": False, "is_scam": False, "confidence_score": 0.0,
            "threat_level": "low", "ml_probability": 0.0,
            "identified_threats": [], "psychological_triggers": [],
            "suspicious_elements": [], "url_features": {}
        }
        
        text_lower = text.lower()
        urf = self.extract_url_features(text)
        result["url_features"] = urf
        
        # 1. ML probability
        ml_prob = 0.0
        if ML_AVAILABLE and self.is_trained:
            try:
                X = self.vectorizer.transform([text])
                ml_prob = float(self.model.predict_proba(X)[0][1])
            except:
                pass
        result["ml_probability"] = ml_prob
        
        # 2. URL risk score
        url_risk = 0.0
        url_weights = {
            "has_suspicious_tld": 30.0, "has_shortener": 25.0,
            "has_brand": 25.0, "has_phishing_path": 25.0,
            "has_ip": 20.0, "has_redirect": 15.0,
        }
        for feat, w in url_weights.items():
            if urf.get(feat, 0) > 0:
                url_risk += w
        if urf.get("num_hyphens", 0) >= 2:
            url_risk += 15.0
        if urf.get("url_length", 0) > 50:
            url_risk += 5.0
        url_risk = min(url_risk, 80.0)
        
        # 3. Text-based scoring
        text_score = 0.0
        keywords = [
            "hesabiniz", "sifreniz", "parolaniz", "kredi karti", "banka",
            "askiya", "kapatilacak", "engellenecek", "dogrulama", "dogrula",
            "tiklayin", "tikla", "acil", "hemen", "simdi",
            "bloke", "kisitli", "tehdit", "silinecek",
            "sure", "doluyor", "odul", "kazandiniz", "ucretsiz",
        ]
        for kw in keywords:
            if kw in text_lower:
                text_score += 5.0
        
        urgent = ["acil", "hemen", "simdi", "tehlike", "uyari"]
        if any(k in text_lower for k in urgent):
            text_score += 10.0
            result["psychological_triggers"].append("urgency")
            result["identified_threats"].append("Aciliyet yaratarak acele karar aldirma")
        
        fear = ["kapatilacak", "engellenecek", "askiya", "bloke", "kisitli", "tehdit", "silinecek"]
        if any(k in text_lower for k in fear):
            text_score += 15.0
            result["psychological_triggers"].append("fear")
            result["identified_threats"].append("Korku/tehdit temasi (psikolojik baski)")
        
        auth = ["banka", "devlet", "guvenlik", "yetkili", "resmi", "musterimiz"]
        if any(k in text_lower for k in auth):
            text_score += 5.0
            result["psychological_triggers"].append("authority")
        
        if text.count("!") >= 2:
            text_score += 5.0
        upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if upper_ratio > 0.3 and len(text) > 50:
            text_score += 5.0
        
        text_score = min(text_score, 50.0)
        
        # 4. Suspicious elements
        if urf.get("has_suspicious_tld", 0) > 0:
            result["suspicious_elements"].append("Supheli alan adi (.tk, .ml vb.)")
        if urf.get("has_shortener", 0) > 0:
            result["suspicious_elements"].append("Kisa URL servisi")
        if urf.get("has_brand", 0) > 0:
            result["suspicious_elements"].append("Marka taklidi domain")
        if urf.get("has_phishing_path", 0) > 0:
            result["suspicious_elements"].append("Phishing URL path (/verify, /login)")
        if urf.get("has_ip", 0) > 0:
            result["suspicious_elements"].append("IP tabanli URL")
        
        # 5. FINAL HYBRID SCORE
        if ml_prob > 0:
            final = (self.ML_WEIGHT * ml_prob * 100) + (self.URL_WEIGHT * url_risk) + (self.TEXT_WEIGHT * text_score)
        else:
            final = (0.60 * url_risk) + (0.40 * text_score)
        final = min(final, 100.0)
        
        # 6. Decision
        result["confidence_score"] = round(final, 1)
        if final >= 50:
            result["is_phishing"] = True
            result["is_scam"] = final >= 40
            result["threat_level"] = "critical"
        elif final >= 25:
            result["is_phishing"] = True
            result["threat_level"] = "high"
        elif final >= 12:
            result["is_phishing"] = False
            result["threat_level"] = "medium"
        else:
            result["threat_level"] = "safe"
        
        # Add brand impersonation threat
        if urf.get("has_brand", 0) > 0 and final >= 30:
            result["identified_threats"].append("Marka taklidi tespit edildi")
        
        return result

phishing_model = PhishingMLModel()
