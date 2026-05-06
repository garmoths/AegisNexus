"""
B1 — HTML Derin Analizi (BeautifulSoup DOM Tabanlı)
======================================================
`ai_analyzer.py`'nin metin tabanlı NLP'sini tamamlar; DOM yapısını ayrıştırır.

Tespit edilen tehditler:
  - Çapraz-domain form action (credential hasat)
  - Gizli/görünmez formlar
  - Kredi kartı / CVV alanları
  - Sayfa başlığı/h1'de marka + domain uyuşmazlığı
  - Şüpheli iframe kaynakları
  - Harici kaynaktan favicon gizleme

Çıktı::
    {
        "penalty"   : int,          # 0-85 arasında toplam ceza
        "details"   : list[str],    # Frontend'e gösterilecek bulgular
        "definitive": bool,         # penalty >= 65 → Gemini atlansın
        "html_analysis": dict,      # Ham sonuçlar (debug için)
    }
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Marka → resmi domain eşlemesi ────────────────────────────────────────
BRAND_DOMAINS: Dict[str, List[str]] = {
    "ziraat":       ["ziraatbank.com.tr", "ziraat.com.tr"],
    "ziraatbank":   ["ziraatbank.com.tr", "ziraat.com.tr"],
    "garanti":      ["garantibbva.com.tr", "garanti.com.tr"],
    "garantibbva":  ["garantibbva.com.tr", "garanti.com.tr"],
    "isbank":       ["isbank.com.tr", "isbank.com"],
    "iş bankası":   ["isbank.com.tr", "isbank.com"],
    "akbank":       ["akbank.com", "akbank.com.tr"],
    "yapikredi":    ["yapikredi.com.tr", "ykb.com"],
    "yapı kredi":   ["yapikredi.com.tr", "ykb.com"],
    "halkbank":     ["halkbank.com.tr", "halkbankasi.com.tr"],
    "vakifbank":    ["vakifbank.com.tr"],
    "vakıfbank":    ["vakifbank.com.tr"],
    "denizbank":    ["denizbank.com", "denizbank.com.tr"],
    "qnb":          ["qnbfinansbank.com", "finansbank.com.tr"],
    "finansbank":   ["qnbfinansbank.com", "finansbank.com.tr"],
    "enpara":       ["enpara.com"],
    "paypal":       ["paypal.com"],
    "google":       ["google.com", "google.com.tr", "gmail.com"],
    "gmail":        ["google.com", "gmail.com"],
    "microsoft":    ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "outlook":      ["outlook.com", "microsoft.com"],
    "apple":        ["apple.com", "icloud.com"],
    "icloud":       ["apple.com", "icloud.com"],
    "amazon":       ["amazon.com", "amazon.com.tr"],
    "netflix":      ["netflix.com"],
    "instagram":    ["instagram.com"],
    "facebook":     ["facebook.com", "fb.com"],
    "twitter":      ["twitter.com", "x.com"],
    "trendyol":     ["trendyol.com"],
    "hepsiburada":  ["hepsiburada.com"],
    "n11":          ["n11.com"],
    "btcturk":      ["btcturk.com"],
    "paribu":       ["paribu.com"],
    "binance":      ["binance.com"],
    "e-devlet":     ["turkiye.gov.tr", "e-devlet.gov.tr"],
    "edevlet":      ["turkiye.gov.tr", "e-devlet.gov.tr"],
}

# Kredi kartı / finansal alan adları
_CC_FIELD_PATTERNS = re.compile(
    r"(card[_\-\s]?num|cardno|pan\b|credit[_\-\s]?card|kart[_\-\s]?no|"
    r"kart[_\-\s]?numar|cvv|cvc|cvc2|cvv2|güvenlik[_\-\s]?kod|"
    r"guvenlik[_\-\s]?kod|expir|son[_\-\s]?kullanma|card[_\-\s]?expir)",
    re.IGNORECASE,
)

MAX_PENALTY = 85


def _domain_matches_brand(domain: str, brand: str) -> bool:
    """Mevcut domain markaya ait resmi domainlerden biri mi?"""
    official = BRAND_DOMAINS.get(brand.lower(), [])
    domain_clean = domain.lower().replace("www.", "")
    return any(domain_clean == od or domain_clean.endswith("." + od) for od in official)


def _extract_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.replace("www.", "").lower()
    except Exception:
        return ""


def analyze_html(html_content: str, url: str) -> Dict[str, Any]:
    """
    HTML DOM'u BeautifulSoup ile ayrıştırarak phishing göstergelerini tespit eder.

    Args:
        html_content : Ham HTTP yanıt metni (requests.text)
        url          : Taranan URL (domain eşleştirme için)

    Returns:
        dict: penalty, details, definitive, html_analysis
    """
    if not html_content:
        return {"penalty": 0, "details": [], "definitive": False, "html_analysis": {}}

    try:
        from bs4 import BeautifulSoup
    except ImportError:
        logger.warning("bs4 kurulu değil, HTML analizi atlandı")
        return {"penalty": 0, "details": [], "definitive": False, "html_analysis": {}}

    try:
        soup = BeautifulSoup(html_content[:300_000], "html.parser")
    except Exception as e:
        logger.warning(f"BeautifulSoup ayrıştırma hatası: {e}")
        return {"penalty": 0, "details": [], "definitive": False, "html_analysis": {}}

    domain = _extract_domain(url)
    penalty = 0
    details: List[str] = []
    raw: Dict[str, Any] = {}

    # ── 1. Çapraz-domain form action ──────────────────────────────────────
    cross_domain_forms = 0
    form_actions = []
    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        form_actions.append(action)
        if action.startswith("http"):
            action_domain = _extract_domain(action)
            if action_domain and action_domain != domain:
                cross_domain_forms += 1
    raw["cross_domain_forms"] = cross_domain_forms
    raw["form_actions"] = form_actions[:5]
    if cross_domain_forms > 0:
        p = min(35, cross_domain_forms * 18)
        penalty += p
        details.append(
            f"🚨 Formlar farklı domain'e gönderiyor ({cross_domain_forms} form) — credential hasat riski (+{p})"
        )

    # ── 2. Gizli / görünmez formlar ───────────────────────────────────────
    hidden_forms = 0
    for form in soup.find_all("form"):
        style = (form.get("style") or "").lower()
        hidden_attr = form.get("hidden") is not None
        if "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", "") or hidden_attr:
            hidden_forms += 1
    raw["hidden_forms"] = hidden_forms
    if hidden_forms > 0:
        p = min(25, hidden_forms * 13)
        penalty += p
        details.append(f"⚠️ Gizli form tespit edildi ({hidden_forms} adet) (+{p})")

    # ── 3. Kredi kartı / CVV alanları ─────────────────────────────────────
    cc_fields = 0
    for inp in soup.find_all("input"):
        name = (inp.get("name") or inp.get("id") or inp.get("placeholder") or "").lower()
        if _CC_FIELD_PATTERNS.search(name):
            cc_fields += 1
    raw["cc_fields"] = cc_fields
    if cc_fields > 0:
        p = min(45, cc_fields * 15)
        penalty += p
        details.append(f"🚨 Kredi kartı/CVV formu tespit edildi ({cc_fields} alan) (+{p})")

    # ── 4. Marka adı → domain uyuşmazlığı ────────────────────────────────
    title_tag = soup.find("title")
    h1_tags = soup.find_all("h1")
    og_title = soup.find("meta", property="og:site_name") or soup.find("meta", {"name": "application-name"})

    page_header_text = " ".join(filter(None, [
        title_tag.get_text() if title_tag else "",
        " ".join(t.get_text() for t in h1_tags[:3]),
        og_title.get("content", "") if og_title else "",
    ])).lower()

    brand_mismatch_found = None
    for brand, official_domains in BRAND_DOMAINS.items():
        if brand.lower() in page_header_text:
            if not _domain_matches_brand(domain, brand):
                brand_mismatch_found = brand
                break
    raw["brand_mismatch"] = brand_mismatch_found
    raw["page_header_text_sample"] = page_header_text[:200]
    if brand_mismatch_found:
        p = 55
        penalty += p
        details.append(
            f"🚨 Sayfa başlığında '{brand_mismatch_found}' markası var "
            f"ama domain '{domain}' resmi değil (+{p})"
        )

    # ── 5. Şifre alanı + marka eşleşmesi ─────────────────────────────────
    password_inputs = soup.find_all("input", {"type": "password"})
    raw["password_inputs"] = len(password_inputs)
    if password_inputs and brand_mismatch_found:
        p = 15
        penalty += p
        details.append(f"🚨 Marka taklidi + şifre formu kombinasyonu (+{p})")
    elif password_inputs and not brand_mismatch_found:
        p = 8
        penalty += p
        details.append(f"⚠️ Şifre giriş alanı var (domain: {domain}) (+{p})")

    # ── 6. Şüpheli iframe ─────────────────────────────────────────────────
    suspicious_iframes = 0
    for iframe in soup.find_all("iframe"):
        src = (iframe.get("src") or "").strip()
        if src.startswith("http"):
            iframe_domain = _extract_domain(src)
            if iframe_domain and iframe_domain != domain:
                suspicious_iframes += 1
    raw["suspicious_iframes"] = suspicious_iframes
    if suspicious_iframes > 0:
        p = min(20, suspicious_iframes * 10)
        penalty += p
        details.append(f"⚠️ Harici domain iframe tespit edildi ({suspicious_iframes} adet) (+{p})")

    # ── 7. Harici domain favicon ──────────────────────────────────────────
    favicon_external = False
    for link in soup.find_all("link"):
        rel_val = link.get("rel") or []
        rel_str = " ".join(rel_val).lower() if isinstance(rel_val, list) else str(rel_val).lower()
        if "icon" not in rel_str:
            continue
        href = (link.get("href") or "").strip()
        if href.startswith("http"):
            fav_domain = _extract_domain(href)
            if fav_domain and fav_domain != domain:
                favicon_external = True
                break
    raw["favicon_external"] = favicon_external
    if favicon_external:
        p = 10
        penalty += p
        details.append(f"⚠️ Favicon farklı domain'den yükleniyor (+{p})")

    # ── Sonuç ─────────────────────────────────────────────────────────────
    penalty = min(penalty, MAX_PENALTY)
    definitive = penalty >= 65

    if details:
        logger.info(f"HTML Analyzer [{domain}]: penalty={penalty}, definitive={definitive}, {len(details)} bulgu")

    return {
        "penalty": penalty,
        "details": details,
        "definitive": definitive,
        "html_analysis": raw,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# B2 — pHash Logo Karşılaştırma
# ═══════════════════════════════════════════════════════════════════════════════

_LOGO_DB_PATH = Path(__file__).parent / "data" / "logo_hashes.json"
_PHASH_THRESHOLD = int(os.getenv("PHASH_THRESHOLD", "8"))

_LOGO_DB: Dict[str, List[Dict[str, str]]] = {}


def _load_logo_db() -> None:
    """logo_hashes.json dosyasını yükle. Dosya yoksa boş devam et."""
    global _LOGO_DB
    try:
        if _LOGO_DB_PATH.exists():
            with open(_LOGO_DB_PATH, "r", encoding="utf-8") as f:
                _LOGO_DB = json.load(f)
            logger.debug(f"[pHash] Logo DB yüklendi: {len(_LOGO_DB)} marka")
        else:
            _LOGO_DB = {}
    except Exception as exc:
        logger.warning(f"[pHash] Logo DB yüklenemedi: {exc}")
        _LOGO_DB = {}


_load_logo_db()


def _brand_matches_url(brand: str, url: str) -> bool:
    """URL zaten markanın resmi domaini ise True döner — pHash cezası verilmez."""
    url_lower = url.lower()
    brand_lower = brand.lower()
    if brand_lower in url_lower:
        official_domains = BRAND_DOMAINS.get(brand_lower, [])
        if official_domains:
            return any(d in url_lower for d in official_domains)
        return True
    return False


def check_logo_phash(
    screenshot_bytes: bytes,
    url: str = "",
) -> Dict[str, Any]:
    """
    B2: Screenshot PNG baytlarından perceptual hash hesaplar, logo DB ile karşılaştırır.

    Kontrol edilen bölgeler:
      - Tam sayfa
      - Header crop (üst %30) — logolar genelde üstte olur

    distance <= _PHASH_THRESHOLD → ~%92+ benzerlik → penalty=60, definitive=True

    Args:
        screenshot_bytes: Ham PNG baytları (base64-decode edilmiş).
        url: Tarandığı URL — domain eşleşme kontrolü için.

    Returns:
        {
          "penalty": int,
          "brand": str | None,
          "definitive": bool,
          "distance": int,
          "similarity": float,
          "detail": str,
        }
    """
    _no_match = {"penalty": 0, "brand": None, "definitive": False,
                 "distance": 999, "similarity": 0.0, "detail": ""}

    if not _LOGO_DB:
        return {**_no_match, "detail": "Logo DB boş — build_logo_db.py çalıştırın"}

    if not screenshot_bytes:
        return {**_no_match, "detail": "Screenshot boş"}

    try:
        import imagehash
        from PIL import Image
    except ImportError:
        return {**_no_match, "detail": "imagehash/Pillow yüklü değil"}

    try:
        img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")
        w, h = img.size
    except Exception as exc:
        return {**_no_match, "detail": f"Görüntü açılamadı: {exc}"}

    # Kontrol bölgeleri: tam sayfa + header (üst %30)
    regions: Dict[str, Any] = {"full": img}
    if h > 100:
        regions["header"] = img.crop((0, 0, w, max(100, int(h * 0.30))))

    best_distance = 999
    best_brand: Optional[str] = None
    best_region = "full"

    for region_name, region_img in regions.items():
        try:
            region_hash = imagehash.phash(region_img)
        except Exception:
            continue

        for brand, entries in _LOGO_DB.items():
            for entry in entries:
                try:
                    stored = imagehash.hex_to_hash(entry["hash"])
                    dist = region_hash - stored
                    if dist < best_distance:
                        best_distance = dist
                        best_brand = brand
                        best_region = region_name
                except Exception:
                    continue

    if best_distance > _PHASH_THRESHOLD or best_brand is None:
        return {**_no_match, "distance": best_distance,
                "detail": f"Eşleşme yok (en yakın: {best_brand}, dist={best_distance})"}

    # Domain kontrolü — markanın kendi sitesiyse ceza verme
    if _brand_matches_url(best_brand, url):
        logger.debug(f"[pHash] {best_brand} logou eşleşti ama domain doğru — ceza verilmedi")
        return {
            "penalty": 0, "brand": best_brand, "definitive": False,
            "distance": best_distance, "similarity": 0.0,
            "detail": f"Logo eşleşti ama domain doğru ({best_brand})",
        }

    similarity = max(0.0, (1.0 - best_distance / 64.0) * 100)
    detail = (
        f"⚠️ Marka logosu tespit edildi: {best_brand} "
        f"(benzerlik ~%{similarity:.0f}, bölge: {best_region}, dist={best_distance})"
    )
    logger.info(f"[pHash] {detail} — url={url}")
    return {
        "penalty": 60,
        "brand": best_brand,
        "definitive": True,
        "distance": best_distance,
        "similarity": round(similarity, 1),
        "detail": detail,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# B3 — EasyOCR Metin Okuma
# ═══════════════════════════════════════════════════════════════════════════════

_OCR_MODEL_DIR = os.getenv(
    "EASYOCR_MODEL_DIR", "/var/www/aegis_nexus/.easyocr_models"
)
_OCR_MAX_PENALTY = 70
_OCR_DEFINITIVE_THRESHOLD = 65

# Process-level singleton — her worker process tek seferinde yükler
_ocr_reader = None


def get_ocr_reader():
    """EasyOCR Reader singleton — lazy init, process başına 1 kez yüklenir."""
    global _ocr_reader
    if _ocr_reader is None:
        try:
            import easyocr
            logger.info("[OCR] EasyOCR Reader yükleniyor...")
            _ocr_reader = easyocr.Reader(
                ["tr", "en"],
                gpu=False,
                verbose=False,
                model_storage_directory=_OCR_MODEL_DIR,
            )
            logger.info("[OCR] EasyOCR Reader hazır.")
        except ImportError:
            logger.warning("[OCR] easyocr yüklü değil — pip install easyocr opencv-python-headless numpy")
            raise
    return _ocr_reader


# ── OCR için credential / brand anahtar kelimeleri ────────────────────────────

_CREDENTIAL_KEYWORDS: List[str] = [
    "şifre", "sifre", "parola", "password", "pin", "kart no", "kart numarası",
    "cvv", "cvc", "son kullanma", "expiry", "iban", "tc kimlik", "tckn",
    "kullanıcı adı", "username", "email", "e-posta", "giriş yap", "login",
    "hesabınıza", "hesabiniza", "doğrulama kodu", "otp", "sms kodu",
    "kredi kartı", "banka kartı", "hesap numarası",
]

_BRAND_OCR_KEYWORDS: Dict[str, str] = {
    "ziraat": "Ziraat Bankası",
    "garanti": "Garanti BBVA",
    "akbank": "Akbank",
    "isbank": "İş Bankası",
    "isbankasi": "İş Bankası",
    "vakifbank": "VakıfBank",
    "halkbank": "Halkbank",
    "denizbank": "Denizbank",
    "enpara": "Enpara",
    "paypal": "PayPal",
    "google": "Google",
    "microsoft": "Microsoft",
    "apple": "Apple",
    "amazon": "Amazon",
    "netflix": "Netflix",
    "instagram": "Instagram",
    "facebook": "Facebook",
    "twitter": "Twitter",
    "whatsapp": "WhatsApp",
    "btcturk": "BtcTurk",
    "paribu": "Paribu",
}


def analyze_with_ocr(
    screenshot_bytes: bytes,
    domain: str = "",
) -> Dict[str, Any]:
    """
    B3: Screenshot PNG'den EasyOCR ile metin oku, brand/credential tespit et.

    Mantık:
      - OCR metni brand keyword içeriyor + domain marka ile eşleşmiyor → penalty=55
      - Credential keyword de varsa → +15 ekstra
      - Domain markanın kendi domaini ise ceza yok

    Args:
        screenshot_bytes: Ham PNG baytları.
        domain: Tarandığı URL domaini (domain check için).

    Returns:
        {
          "penalty": int,
          "definitive": bool,
          "ocr_text_sample": str,
          "brands_found": list,
          "credentials_found": list,
          "detail": str,
        }
    """
    _no_match: Dict[str, Any] = {
        "penalty": 0,
        "definitive": False,
        "ocr_text_sample": "",
        "brands_found": [],
        "credentials_found": [],
        "detail": "",
    }

    if not screenshot_bytes:
        return {**_no_match, "detail": "Screenshot boş"}

    try:
        import numpy as np
        from PIL import Image
    except ImportError:
        return {**_no_match, "detail": "numpy/Pillow yüklü değil"}

    # PNG → numpy array
    try:
        img = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")
        img_np = np.array(img)
    except Exception as exc:
        return {**_no_match, "detail": f"Görüntü açılamadı: {exc}"}

    # OCR
    try:
        reader = get_ocr_reader()
        ocr_results = reader.readtext(img_np, detail=0, paragraph=True)
        ocr_text = " ".join(ocr_results).lower()
    except ImportError:
        return {**_no_match, "detail": "easyocr yüklü değil"}
    except Exception as exc:
        logger.warning(f"[OCR] readtext hatası: {exc}")
        return {**_no_match, "detail": f"OCR hatası: {exc}"}

    domain_lower = domain.lower()
    penalty = 0
    brands_found: List[str] = []
    credentials_found: List[str] = []

    # Brand tespiti
    for keyword, brand_name in _BRAND_OCR_KEYWORDS.items():
        if keyword in ocr_text:
            # Domain kendi markasıysa ceza verme
            if _brand_matches_url(keyword, domain_lower if domain_lower.startswith("http") else f"https://{domain_lower}"):
                continue
            if keyword not in brands_found:
                brands_found.append(keyword)

    # Credential tespiti
    for cred_kw in _CREDENTIAL_KEYWORDS:
        if cred_kw in ocr_text:
            credentials_found.append(cred_kw)

    # Ceza hesapla — marka tespiti olmadan credential tek başına ceza vermez
    if brands_found:
        penalty += 55
        if credentials_found:
            extra = min(15, len(credentials_found) * 5)
            penalty += extra

    penalty = min(penalty, _OCR_MAX_PENALTY)
    definitive = penalty >= _OCR_DEFINITIVE_THRESHOLD

    ocr_sample = ocr_text[:300]

    details = []
    if brands_found:
        details.append(f"OCR marka tespiti: {', '.join(brands_found)}")
    if credentials_found:
        details.append(f"Kimlik bilgisi isteği: {', '.join(credentials_found[:3])}")
    detail_str = " | ".join(details) if details else "Şüpheli içerik yok"

    if brands_found or credentials_found:
        logger.info(f"[OCR] {detail_str} — domain={domain}")

    return {
        "penalty": penalty,
        "definitive": definitive,
        "ocr_text_sample": ocr_sample,
        "brands_found": brands_found,
        "credentials_found": credentials_found[:5],
        "detail": detail_str,
    }
