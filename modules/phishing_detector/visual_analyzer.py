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

import logging
import re
from typing import Any, Dict, List, Tuple
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
