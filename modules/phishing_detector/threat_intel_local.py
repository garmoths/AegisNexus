"""
Local Threat Intelligence API Replacements
=========================================
VirusTotal ve AbuseIPDB'nin yaptığını tamamen local yapan modül
Mevcut kodunda sadece import'u değiştirmen yeterli
"""

import re
import socket
import ipaddress
import json
import logging
import sqlite3
from pathlib import Path
from urllib.parse import urlparse
from rapidfuzz import fuzz

logger = logging.getLogger(__name__)
WHITELIST_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "whitelist.db"


def _is_whitelisted_domain(domain: str) -> bool:
    domain_norm = (domain or "").lower().strip()
    if domain_norm.startswith("www."):
        domain_norm = domain_norm[4:]
    if not domain_norm:
        return False
    if not WHITELIST_DB_PATH.exists():
        return False
    try:
        conn = sqlite3.connect(WHITELIST_DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM whitelist_domains WHERE domain_norm = ? LIMIT 1", (domain_norm,))
        if cur.fetchone():
            conn.close()
            return True
        parts = domain_norm.split(".")
        for part_count in range(1, len(parts)):
            partial_domain = ".".join(parts[-part_count - 1 :])
            cur.execute("SELECT 1 FROM whitelist_domains WHERE domain_norm = ? LIMIT 1", (partial_domain,))
            if cur.fetchone():
                conn.close()
                return True
        conn.close()
    except Exception as exc:
        logger.debug(f"Whitelist check failed in threat_intel_local: {exc}")
    return False


def _extract_cached_vt(raw_data: object) -> dict | None:
    """Cache edilmiş tam tarama sonucundan VirusTotal özetini çıkar."""
    if not isinstance(raw_data, dict):
        return None

    threat_intel = raw_data.get("threat_intel")
    if isinstance(threat_intel, dict):
        vt = threat_intel.get("virustotal")
        if isinstance(vt, dict):
            return vt

    vt = raw_data.get("virustotal")
    if isinstance(vt, dict):
        return vt

    return None


def _best_cached_vt_result(url: str, domain: str) -> dict | None:
    """Aynı URL veya domain için cache'e yazılmış VT özetini bul.

    Bu katman canlı API'ye gitmez; yalnızca threat_intel_cache.db içindeki
    önceki tarama sonuçlarını kullanır.
    """
    from .cache_db import get_db_connection

    normalized_url = (url or "").strip()
    normalized_domain = (domain or "").lower().strip()
    if normalized_domain.startswith("www."):
        normalized_domain = normalized_domain[4:]

    candidates: list[dict] = []
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT url, domain, raw_data, checked_at
                FROM phishing_urls
                WHERE url = ? OR domain = ?
                ORDER BY checked_at DESC, id DESC
                LIMIT 25
                """,
                (normalized_url, normalized_domain),
            )

            for row in cursor.fetchall():
                raw_data = None
                if row["raw_data"]:
                    try:
                        raw_data = json.loads(row["raw_data"])
                    except Exception:
                        raw_data = None

                vt = _extract_cached_vt(raw_data)
                if not isinstance(vt, dict):
                    continue

                engines = vt.get("engines")
                engine_count = len(engines) if isinstance(engines, list) else 0
                malicious = int(vt.get("malicious", 0) or 0)
                suspicious = int(vt.get("suspicious", 0) or 0)
                clean = int(vt.get("clean", 0) or 0)
                total = int(vt.get("total_engines", 0) or (malicious + suspicious + clean))

                candidates.append({
                    "available": True,
                    "status": vt.get("status") or "Yerel VT cache sonucu",
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "clean": clean,
                    "total_engines": total,
                    "engines": engines if isinstance(engines, list) else [],
                    "source": f"cache:{row['url']}" if row["url"] == normalized_url else f"cache-domain:{row['domain']}",
                    "cached_at": row["checked_at"],
                    "_rank": (malicious, suspicious, engine_count, total),
                })
    except Exception as exc:
        logger.debug(f"Cached VirusTotal lookup failed: {exc}")

    if not candidates:
        return None

    best = max(candidates, key=lambda item: item["_rank"])
    best.pop("_rank", None)
    if best["malicious"] > 0:
        best["status"] = f"🚨 {best['malicious']}/{best.get('total_engines', 0)} motor TEHLİKELİ olarak işaretledi"
    elif best["suspicious"] > 0:
        best["status"] = f"⚠️ {best['suspicious']}/{best.get('total_engines', 0)} motor ŞÜPHELİ olarak işaretledi"
    else:
        best["status"] = f"✅ {best.get('total_engines', 0)} motorun hiçbiri tehdit tespit etmedi"
    return best


def _best_cached_scan_raw_data(url: str, domain: str) -> dict | None:
    """Aynı URL/domain için cache'e yazılmış tam tarama sonucunu döndür."""
    from .cache_db import get_db_connection

    normalized_url = (url or "").strip()
    normalized_domain = (domain or "").lower().strip()
    if normalized_domain.startswith("www."):
        normalized_domain = normalized_domain[4:]

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT raw_data
                FROM phishing_urls
                WHERE url = ? OR domain = ?
                ORDER BY checked_at DESC, id DESC
                LIMIT 25
                """,
                (normalized_url, normalized_domain),
            )
            for row in cursor.fetchall():
                if not row["raw_data"]:
                    continue
                try:
                    raw_data = json.loads(row["raw_data"])
                except Exception:
                    continue
                if isinstance(raw_data, dict):
                    return raw_data
    except Exception as exc:
        logger.debug(f"Cached scan lookup failed: {exc}")
    return None


def _extract_cached_component(raw_data: object, component: str) -> dict | None:
    """Tam tarama sonucundan bir bileşeni çıkar (ör. abuseipdb, spamhaus_domain)."""
    if not isinstance(raw_data, dict):
        return None

    threat_intel = raw_data.get("threat_intel")
    if isinstance(threat_intel, dict):
        value = threat_intel.get(component)
        if isinstance(value, dict):
            return value

    value = raw_data.get(component)
    if isinstance(value, dict):
        return value

    return None

# ============================================================
# VİRUSTOTAL REPLACEMENT → check_virustotal_local()
# Orijinal: vt["malicious"], vt["suspicious"] döndürüyordu
# Bu fonksiyon aynı dict yapısını döndürür, kod değişmez
# ============================================================

def check_virustotal_local(url: str, db) -> dict:
    """
    Döndürdüğü dict orijinal VirusTotal dict'i ile aynı yapıda:
    {
        "malicious": int,   # 0, 1, 2, 3+ 
        "suspicious": int,
        "source": str       # hangi feed'den geldi
    }
    Böylece mevcut penalty kodun (>=3, >=1) hiç değişmez.
    """
    from app.models import PhishingURL
    
    domain = urlparse(url).netloc.lower().replace("www.", "")
    malicious_hits = 0
    suspicious_hits = 0
    source = None

    cached_vt = _best_cached_vt_result(url, domain)
    if cached_vt:
        return cached_vt

    # Whitelist domainlerde fuzzy false-positive üretme.
    if _is_whitelisted_domain(domain):
        return {"malicious": 0, "suspicious": 0, "source": "whitelist", "available": True}

    # --- KONTROL 1: Exact URL match (feed DB'nde var mı?) ---
    exact_match = db.query(PhishingURL).filter(
        PhishingURL.url == url,
        PhishingURL.status == 'valid'
    ).first()
    if exact_match:
        # Direkt DB hit → 5 motor işaretledi gibi davran (40 penalty tetiklenir)
        return {"malicious": 5, "suspicious": 0, "source": exact_match.phish_id, "available": True}

    # --- KONTROL 2: Domain exact match ---
    domain_matches = db.query(PhishingURL).filter(
        PhishingURL.domain_norm == domain,
        PhishingURL.status == 'valid'
    ).all()
    if domain_matches:
        total_hits = len(domain_matches)
        source = domain_matches[0].phish_id
        if total_hits >= 3:
            return {"malicious": 3, "suspicious": 0, "source": source, "available": True}
        else:
            return {"malicious": 1, "suspicious": 0, "source": source, "available": True}

    # --- KONTROL 3: Fuzzy domain match (typosquatting tespiti) ---
    # Kısa domainlerde (< 10 karakter) atlıyoruz: 'za.com.tr' gibi 2-harfli
    # isimlerde rastgele yüksek skor çıkar → false positive riski çok yüksek.
    if len(domain) >= 10:
        db_domains = db.query(PhishingURL.domain_norm).filter(
            PhishingURL.status == 'valid'
        ).distinct().all()

        db_domains = [d[0] for d in db_domains if d[0] and len(d[0]) >= len(domain) - 3 and len(d[0]) <= len(domain) + 3]
        best_score = 0
        best_domain = None

        for db_domain in db_domains[:5000]:  # Limit for performance
            score = fuzz.token_sort_ratio(domain, db_domain)
            if score > best_score:
                best_score = score
                best_domain = db_domain

        if best_score >= 93:
            # Neredeyse aynı domain → 3 motor işaretledi gibi (40 penalty)
            return {"malicious": 3, "suspicious": 0, "source": f"fuzzy:{best_domain}", "available": True}
        elif best_score >= 88:
            # Çok yakın benzerlik (1-2 karakter fark) → 1 motor şüpheli buldu
            return {"malicious": 1, "suspicious": 0, "source": f"fuzzy:{best_domain}", "available": True}

    # --- KONTROL 4: URL feature skoru (hiçbir yerde bulunamadı) ---
    suspicious_score = _calculate_url_suspicion(url, domain)
    if suspicious_score >= 3:
        suspicious_hits = 2  # 10 penalty tetiklenir
    elif suspicious_score >= 2:
        suspicious_hits = 1  # 10 penalty tetiklenir

    return {"malicious": malicious_hits, "suspicious": suspicious_hits, "source": None, "available": True}


def _calculate_url_suspicion(url: str, domain: str) -> int:
    """
    URL'nin şüpheli özelliklerini sayar.
    Her şüpheli özellik 1 puan, toplam 5+ → kesin şüpheli
    """
    score = 0
    url_lower = url.lower()

    # Uzun URL
    if len(url) > 100:
        score += 1

    # Çok fazla subdomain
    if domain.count('.') >= 4:
        score += 1

    # IP adresi kullanımı
    if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 2

    # Riskli TLD
    RISKY_TLDS = {'.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', 
                  '.work', '.click', '.loan', '.win', '.racing'}
    if any(domain.endswith(tld) for tld in RISKY_TLDS):
        score += 1

    # Phishing anahtar kelimeleri URL'de
    PHISHING_KEYWORDS = [
        'verify', 'secure', 'login', 'update', 'confirm', 'account',
        'banking', 'paypal', 'instagram', 'facebook', 'apple', 'google',
        'microsoft', 'amazon', 'netflix', 'doğrula', 'hesap', 'güvenlik'
    ]
    hits = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)
    score += min(hits, 2)  # max 2 puan

    # Çok fazla tire veya rakam
    if domain.count('-') >= 3:
        score += 1
    if sum(c.isdigit() for c in domain) / max(len(domain), 1) > 0.4:
        score += 1

    # Encoding / obfuscation
    if '%' in url and url.count('%') > 3:
        score += 1

    return score


# ============================================================
# ABUSEIPDB REPLACEMENT → check_abuseipdb_local()
# Orijinal: aipdb["abuse_score"] döndürüyordu (0-100)
# Bu fonksiyon aynı dict yapısını döndürür
# ============================================================

# IP blacklist'leri memory'e yükle (uygulama başlarken bir kez çalıştır)
_IP_BLACKLIST: set = set()
_IP_NETWORKS: list = []

# EasyOCR reader'ı için global referans (preload_models ile başlatılır)
_EASYOCR_READER = None


def preload_models(ip_lists_dir: str = "/opt/phishing/ip_lists") -> dict:
    """
    Worker/API başlangıcında bir kez çağrılır.
    - EasyOCR reader'ını singleton olarak başlatır.
    - IP blacklist'leri memory'e yükler.
    - Playwright browser pool'u pre-warm eder.

    Böylece her istekte ~30sn OCR yükleme + ~2-3sn IP blacklist yükleme
    overhead'i ortadan kalkar.
    
    Returns:
        {"ocr_loaded": bool, "ip_loaded": int, "playwright_loaded": bool}
    """
    global _EASYOCR_READER, _IP_BLACKLIST, _IP_NETWORKS
    
    result = {"ocr_loaded": False, "ip_loaded": 0, "playwright_loaded": False}
    
    # 1. EasyOCR preload
    try:
        from modules.phishing_detector.visual_analyzer import get_ocr_reader
        _EASYOCR_READER = get_ocr_reader()
        result["ocr_loaded"] = True
        logger.info("[Preload] EasyOCR Reader hazır")
    except ImportError:
        logger.warning("[Preload] easyocr yüklü değil, atlanıyor")
    except Exception as exc:
        logger.warning(f"[Preload] EasyOCR yüklenemedi: {exc}")
    
    # 2. IP blacklist preload
    try:
        count = load_ip_blacklists(ip_lists_dir)
        result["ip_loaded"] = count
        logger.info(f"[Preload] IP blacklist yüklendi: {count} giriş")
    except Exception as exc:
        logger.warning(f"[Preload] IP blacklist yüklenemedi: {exc}")
    
    # 3. Playwright pool pre-warm (opsiyonel)
    try:
        from modules.phishing_detector.playwright_pool import init_pool
        init_pool()
        result["playwright_loaded"] = True
        logger.info("[Preload] Playwright pool pre-warm tamam")
    except Exception as exc:
        logger.warning(f"[Preload] Playwright pool pre-warm başarısız: {exc}")
    
    return result


def load_ip_blacklists(filepath_dir: str = "/opt/phishing/ip_lists"):
    """
    Firehol + Spamhaus listelerini memory'e yükler.
    Celery beat ile günde 1 kez refresh edilmeli.
    """
    global _IP_BLACKLIST, _IP_NETWORKS
    import os

    _IP_BLACKLIST = set()
    _IP_NETWORKS = []

    list_files = [
        f"{filepath_dir}/firehol_level1.netset",
        f"{filepath_dir}/spamhaus_drop.txt",
        f"{filepath_dir}/spamhaus_edrop.txt",
        f"{filepath_dir}/emerging_threats.txt",
    ]

    for fpath in list_files:
        if not os.path.exists(fpath):
            logger.warning(f"IP list file not found: {fpath}")
            continue
        with open(fpath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                try:
                    if '/' in line:
                        _IP_NETWORKS.append(ipaddress.ip_network(line, strict=False))
                    else:
                        _IP_BLACKLIST.add(line)
                except ValueError:
                    continue

    logger.info(f"Loaded {len(_IP_BLACKLIST)} IPs and {len(_IP_NETWORKS)} networks to memory")
    return len(_IP_BLACKLIST) + len(_IP_NETWORKS)


def check_abuseipdb_local(url: str) -> dict:
    """
    Döndürdüğü dict orijinal AbuseIPDB dict'i ile aynı yapıda:
    {"abuse_score": int, "available": bool}  # 0-100
    Mevcut penalty kodu (>= 70) hiç değişmez.
    """
    domain = urlparse(url).netloc.lower().replace("www.", "")

    cached_scan = _best_cached_scan_raw_data(url, domain)
    if cached_scan:
        cached_abuse = _extract_cached_component(cached_scan, "abuseipdb")
        if isinstance(cached_abuse, dict):
            score = int(cached_abuse.get("abuse_score", 0) or 0)
            result = dict(cached_abuse)
            result["abuse_score"] = score
            result.setdefault("available", True)
            result["status"] = cached_abuse.get("status") or ("Yüksek suistimal skoru" if score >= 70 else "Temiz")
            result["source"] = cached_abuse.get("source") or "cache"
            return result

    # Domain'den IP çöz
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        # DNS çözümlenemedi → şüpheli say
        return {"abuse_score": 50, "available": True}

    ip_obj = ipaddress.ip_address(ip)

    # Private IP → temiz
    if ip_obj.is_private or ip_obj.is_loopback:
        return {"abuse_score": 0, "available": True}

    # Exact IP blacklist kontrolü
    if ip in _IP_BLACKLIST:
        return {"abuse_score": 85, "available": True}  # 25 penalty tetiklenir

    # CIDR network kontrolü
    for network in _IP_NETWORKS:
        if ip_obj in network:
            return {"abuse_score": 75, "available": True}  # 25 penalty tetiklenir

    return {"abuse_score": 0, "available": True}
