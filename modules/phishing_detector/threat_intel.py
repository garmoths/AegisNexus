"""
Threat Intelligence API Integrations
======================================
Harici API servisleri ile tehdit istihbaratı entegrasyonu.
- VirusTotal API
- Google Safe Browsing API
- AbuseIPDB
"""

import os
import json
import logging
import hashlib
import socket
import requests
from urllib.parse import urlparse, quote_plus
from dotenv import load_dotenv
from datetime import datetime, timedelta
from functools import wraps

load_dotenv()
logger = logging.getLogger(__name__)

# API Key'ler .env dosyasından okunur (multiple keys for rotation)
VIRUSTOTAL_API_KEYS = os.getenv("VIRUSTOTAL_API_KEYS", "").split(",") if os.getenv("VIRUSTOTAL_API_KEYS") else []
VIRUSTOTAL_API_KEY = VIRUSTOTAL_API_KEYS[0] if VIRUSTOTAL_API_KEYS else os.getenv("VIRUSTOTAL_API_KEY", "")

GOOGLE_SAFE_BROWSING_KEYS = os.getenv("GOOGLE_SAFE_BROWSING_KEYS", "").split(",") if os.getenv("GOOGLE_SAFE_BROWSING_KEYS") else []
GOOGLE_SAFE_BROWSING_KEY = GOOGLE_SAFE_BROWSING_KEYS[0] if GOOGLE_SAFE_BROWSING_KEYS else os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

ABUSEIPDB_API_KEYS = os.getenv("ABUSEIPDB_API_KEYS", "").split(",") if os.getenv("ABUSEIPDB_API_KEYS") else []
ABUSEIPDB_API_KEY = ABUSEIPDB_API_KEYS[0] if ABUSEIPDB_API_KEYS else os.getenv("ABUSEIPDB_API_KEY", "")

# Cache depolama (in-memory)
API_CACHE = {}
CACHE_TTL = 3600  # 1 saat

# Rate limiting depolama
API_RATE_LIMITS = {
    "virustotal": {"requests": [], "limit": 4, "window": 60, "key_index": 0},  # 4 req/min
    "abuseipdb": {"requests": [], "limit": 1500, "window": 86400, "key_index": 0},  # 1500 req/day
    "google_safe": {"requests": [], "limit": 10000, "window": 86400, "key_index": 0},  # 10000 req/day
}


def _rotate_api_key(api_name):
    """API key'i rotate et (rate limit aşıldıysa sonraki key'e geç)."""
    if api_name not in API_RATE_LIMITS:
        return None
    
    if api_name == "virustotal":
        if len(VIRUSTOTAL_API_KEYS) > 1:
            current_idx = API_RATE_LIMITS[api_name]["key_index"]
            next_idx = (current_idx + 1) % len(VIRUSTOTAL_API_KEYS)
            API_RATE_LIMITS[api_name]["key_index"] = next_idx
            API_RATE_LIMITS[api_name]["requests"] = []  # Reset rate limit counter
            logger.info(f"Rotated VirusTotal key: {current_idx} → {next_idx}")
            return VIRUSTOTAL_API_KEYS[next_idx]
        return VIRUSTOTAL_API_KEYS[0] if VIRUSTOTAL_API_KEYS else None
    
    elif api_name == "google_safe":
        if len(GOOGLE_SAFE_BROWSING_KEYS) > 1:
            current_idx = API_RATE_LIMITS[api_name]["key_index"]
            next_idx = (current_idx + 1) % len(GOOGLE_SAFE_BROWSING_KEYS)
            API_RATE_LIMITS[api_name]["key_index"] = next_idx
            API_RATE_LIMITS[api_name]["requests"] = []
            logger.info(f"Rotated Google Safe key: {current_idx} → {next_idx}")
            return GOOGLE_SAFE_BROWSING_KEYS[next_idx]
        return GOOGLE_SAFE_BROWSING_KEYS[0] if GOOGLE_SAFE_BROWSING_KEYS else None
    
    elif api_name == "abuseipdb":
        if len(ABUSEIPDB_API_KEYS) > 1:
            current_idx = API_RATE_LIMITS[api_name]["key_index"]
            next_idx = (current_idx + 1) % len(ABUSEIPDB_API_KEYS)
            API_RATE_LIMITS[api_name]["key_index"] = next_idx
            API_RATE_LIMITS[api_name]["requests"] = []
            logger.info(f"Rotated AbuseIPDB key: {current_idx} → {next_idx}")
            return ABUSEIPDB_API_KEYS[next_idx]
        return ABUSEIPDB_API_KEYS[0] if ABUSEIPDB_API_KEYS else None
    
    return None


def _get_current_api_key(api_name):
    """Şu anda aktif olan API key'i getir."""
    if api_name == "virustotal":
        idx = API_RATE_LIMITS[api_name]["key_index"]
        return VIRUSTOTAL_API_KEYS[idx] if idx < len(VIRUSTOTAL_API_KEYS) else None
    elif api_name == "google_safe":
        idx = API_RATE_LIMITS[api_name]["key_index"]
        return GOOGLE_SAFE_BROWSING_KEYS[idx] if idx < len(GOOGLE_SAFE_BROWSING_KEYS) else None
    elif api_name == "abuseipdb":
        idx = API_RATE_LIMITS[api_name]["key_index"]
        return ABUSEIPDB_API_KEYS[idx] if idx < len(ABUSEIPDB_API_KEYS) else None
    return None


def _check_rate_limit(api_name):
    """Rate limit kontrolü."""
    if api_name not in API_RATE_LIMITS:
        return True
    
    limit_config = API_RATE_LIMITS[api_name]
    now = datetime.now()
    cutoff = now - timedelta(seconds=limit_config["window"])
    
    # Eski requestleri temizle
    limit_config["requests"] = [
        req_time for req_time in limit_config["requests"]
        if req_time > cutoff
    ]
    
    # Limiti kontrol et
    if len(limit_config["requests"]) >= limit_config["limit"]:
        logger.warning(f"{api_name} rate limit aşıldı")
        return False
    
    limit_config["requests"].append(now)
    return True


def _get_cached(cache_key):
    """Cache'den al."""
    if cache_key in API_CACHE:
        cached_data, timestamp = API_CACHE[cache_key]
        if datetime.now() - timestamp < timedelta(seconds=CACHE_TTL):
            logger.debug(f"Cache hit: {cache_key}")
            return cached_data
        else:
            del API_CACHE[cache_key]
    return None


def _set_cached(cache_key, data):
    """Cache'ye koy."""
    API_CACHE[cache_key] = (data, datetime.now())


# =========================================================
# 1. VIRUSTOTAL API
# =========================================================

def check_virustotal(url, timeout=8):
    """
    VirusTotal API v3 ile URL taraması (rate limited + cached).
    Döndürür: {"malicious": int, "suspicious": int, "clean": int, "status": str}
    """
    cache_key = f"vt_{hashlib.sha256(url.encode()).hexdigest()}"
    
    # Cache kontrol
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not VIRUSTOTAL_API_KEY:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "malicious": 0, "suspicious": 0, "clean": 0,
            "engines": []
        }
    
    # Rate limit kontrol + API key rotation
    if not _check_rate_limit("virustotal"):
        # Rate limit aşıldıysa sonraki key'e geç
        rotated_key = _rotate_api_key("virustotal")
        if rotated_key:
            logger.info("VirusTotal rate limit aşıldı, sonraki API key'e geçildi")
        else:
            return {
                "available": True,
                "status": "VirusTotal rate limit aşıldı (4 req/dakika) - başka key yok",
                "malicious": 0, "suspicious": 0, "clean": 0,
                "engines": [],
                "rate_limited": True
            }

    try:
        # URL'yi base64 ile encode et (VT API v3 gereksinimi)
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Şu anda aktif olan API key'i kullan
        current_key = _get_current_api_key("virustotal")
        headers = {"x-apikey": current_key}

        # Önce mevcut raporu kontrol et
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        resp = requests.get(api_url, headers=headers, timeout=timeout)

        if resp.status_code == 404:
            # Rapor yoksa yeni tarama başlat
            scan_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=timeout
            )
            if scan_resp.status_code == 200:
                return {
                    "available": True,
                    "status": "Tarama başlatıldı (sonuçlar birkaç dakika içinde hazır)",
                    "malicious": 0, "suspicious": 0, "clean": 0,
                    "engines": [],
                    "scan_initiated": True
                }
            return {
                "available": True,
                "status": f"Tarama başlatılamadı (HTTP {scan_resp.status_code})",
                "malicious": 0, "suspicious": 0, "clean": 0,
                "engines": []
            }

        if resp.status_code != 200:
            return {
                "available": True,
                "status": f"API hatası (HTTP {resp.status_code})",
                "malicious": 0, "suspicious": 0, "clean": 0,
                "engines": []
            }

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)

        # Tehdit tespit eden motorları listele
        threat_engines = []
        for engine_name, result in results.items():
            if result.get("category") in ("malicious", "suspicious"):
                threat_engines.append({
                    "engine": engine_name,
                    "result": result.get("result", ""),
                    "category": result.get("category", "")
                })

        total = malicious + suspicious + harmless + undetected
        if malicious > 0:
            status = f"🚨 {malicious}/{total} motor TEHLİKELİ olarak işaretledi"
        elif suspicious > 0:
            status = f"⚠️ {suspicious}/{total} motor ŞÜPHELİ olarak işaretledi"
        else:
            status = f"✅ {total} motorun hiçbiri tehdit tespit etmedi"

        result = {
            "available": True,
            "status": status,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": harmless,
            "total_engines": total,
            "engines": threat_engines[:10]  # En fazla 10 motor
        }
        
        # Cache'ye koy
        _set_cached(cache_key, result)
        return result

    except requests.Timeout:
        return {
            "available": True,
            "status": "VirusTotal zaman aşımı",
            "malicious": 0, "suspicious": 0, "clean": 0,
            "engines": []
        }
    except Exception as e:
        logger.error(f"VirusTotal hatası: {e}")
        return {
            "available": True,
            "status": f"Bağlantı hatası: {str(e)[:50]}",
            "malicious": 0, "suspicious": 0, "clean": 0,
            "engines": []
        }


# =========================================================
# 2. GOOGLE SAFE BROWSING API
# =========================================================

def check_google_safe_browsing(url, timeout=8):
    """
    Google Safe Browsing API v4 ile kontrol (cached + rate limited).
    Döndürür: {"threat": bool, "threat_type": str, "status": str}
    """
    cache_key = f"gsb_{hashlib.sha256(url.encode()).hexdigest()}"
    
    # Cache kontrol
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not GOOGLE_SAFE_BROWSING_KEY:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "threat": False,
            "threat_type": None
        }
    
    # Rate limit kontrol
    if not _check_rate_limit("google_safe"):
        return {
            "available": True,
            "status": "Google Safe Browsing rate limit aşıldı",
            "threat": False,
            "threat_type": None,
            "rate_limited": True
        }

    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_KEY}"

        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                    "THREAT_TYPE_UNSPECIFIED"
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        resp = requests.post(api_url, json=payload, timeout=timeout)

        if resp.status_code != 200:
            return {
                "available": True,
                "status": f"API hatası (HTTP {resp.status_code})",
                "threat": False,
                "threat_type": None
            }

        data = resp.json()
        matches = data.get("matches", [])

        if matches:
            threat_type = matches[0].get("threatType", "UNKNOWN")
            threat_names = {
                "MALWARE": "Zararlı Yazılım",
                "SOCIAL_ENGINEERING": "Sosyal Mühendislik (Phishing)",
                "UNWANTED_SOFTWARE": "İstenmeyen Yazılım",
                "POTENTIALLY_HARMFUL_APPLICATION": "Potansiyel Zararlı Uygulama",
            }
            result = {
                "available": True,
                "status": f"🚨 Google: {threat_names.get(threat_type, threat_type)} tespit edildi!",
                "threat": True,
                "threat_type": threat_names.get(threat_type, threat_type)
            }
            _set_cached(cache_key, result)
            return result

        result = {
            "available": True,
            "status": "✅ Google Safe Browsing: Temiz",
            "threat": False,
            "threat_type": None
        }
        _set_cached(cache_key, result)
        return result

    except Exception as e:
        logger.error(f"Google Safe Browsing hatası: {e}")
        return {
            "available": True,
            "status": f"Bağlantı hatası: {str(e)[:50]}",
            "threat": False,
            "threat_type": None
        }


# =========================================================
# 3. ABUSEIPDB API
# =========================================================

def check_abuseipdb(url, timeout=8):
    """
    AbuseIPDB ile domain/IP itibar kontrolü (cached + rate limited).
    Döndürür: {"abuse_score": int, "reports": int, "status": str}
    """
    cache_key = f"abuseipdb_{hashlib.sha256(url.encode()).hexdigest()}"
    
    # Cache kontrol
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not ABUSEIPDB_API_KEY:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "abuse_score": 0,
            "total_reports": 0
        }
    
    # Rate limit kontrol
    if not _check_rate_limit("abuseipdb"):
        return {
            "available": True,
            "status": "AbuseIPDB rate limit aşıldı (1500 req/gün)",
            "abuse_score": 0,
            "total_reports": 0,
            "rate_limited": True
        }

    try:
        # Domain'den IP çöz
        parsed = urlparse(url if url.startswith("http") else "https://" + url)
        hostname = parsed.netloc or parsed.path
        hostname = hostname.replace("www.", "").split(":")[0]

        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            return {
                "available": True,
                "status": "Domain IP'ye çözümlenemedi",
                "abuse_score": 0,
                "total_reports": 0
            }

        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": 90
        }

        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers, params=params, timeout=timeout
        )

        if resp.status_code != 200:
            return {
                "available": True,
                "status": f"API hatası (HTTP {resp.status_code})",
                "abuse_score": 0,
                "total_reports": 0
            }

        data = resp.json().get("data", {})
        abuse_score = data.get("abuseConfidenceScore", 0)
        total_reports = data.get("totalReports", 0)
        country = data.get("countryCode", "??")
        isp = data.get("isp", "Bilinmiyor")

        if abuse_score >= 70:
            status = f"🚨 AbuseIPDB: Yüksek risk skoru ({abuse_score}%) — {total_reports} rapor — {country}"
        elif abuse_score >= 30:
            status = f"⚠️ AbuseIPDB: Orta risk ({abuse_score}%) — {total_reports} rapor — {country}"
        elif total_reports > 0:
            status = f"ℹ️ AbuseIPDB: Düşük risk ({abuse_score}%) — {total_reports} rapor — ISP: {isp}"
        else:
            status = f"✅ AbuseIPDB: Temiz — ISP: {isp} — {country}"

        result = {
            "available": True,
            "status": status,
            "abuse_score": abuse_score,
            "total_reports": total_reports,
            "ip": ip_address,
            "country": country,
            "isp": isp
        }
        
        # Cache'ye koy
        _set_cached(cache_key, result)
        return result

    except Exception as e:
        logger.error(f"AbuseIPDB hatası: {e}")
        return {
            "available": True,
            "status": f"Bağlantı hatası: {str(e)[:50]}",
            "abuse_score": 0,
            "total_reports": 0
        }


# =========================================================
# 4. TOPLU TEHDİT İSTİHBARATI
# =========================================================

def run_threat_intelligence(url):
    """
    Tüm harici API'leri paralel olmayan şekilde çalıştırır.
    Her API bağımsız çalışır, biri hata verse diğerleri etkilenmez.
    """
    results = {
        "virustotal": None,
        "google_safe_browsing": None,
        "abuseipdb": None,
        "total_penalty": 0,
        "findings": [],
        "sources": [],
    }

    # --- VirusTotal ---
    try:
        vt = check_virustotal(url)
        results["virustotal"] = vt
        if vt.get("available"):
            results["sources"].append({
                "name": "VirusTotal",
                "status": vt["status"]
            })
            if vt["malicious"] >= 3:
                results["total_penalty"] += 40
                results["findings"].append(f"🛡️ VirusTotal: {vt['malicious']} motor tehlikeli olarak işaretledi!")
            elif vt["malicious"] >= 1:
                results["total_penalty"] += 20
                results["findings"].append(f"⚠️ VirusTotal: {vt['malicious']} motor şüpheli buldu")
            elif vt.get("suspicious", 0) >= 1:
                results["total_penalty"] += 10
                results["findings"].append(f"⚠️ VirusTotal: {vt['suspicious']} motor şüpheli olarak işaretledi")
    except Exception as e:
        logger.error(f"VT err: {e}")

    # --- Google Safe Browsing ---
    try:
        gsb = check_google_safe_browsing(url)
        results["google_safe_browsing"] = gsb
        if gsb.get("available"):
            results["sources"].append({
                "name": "Google Safe Browsing",
                "status": gsb["status"]
            })
            if gsb["threat"]:
                results["total_penalty"] += 50
                results["findings"].append(f"🛡️ {gsb['status']}")
    except Exception as e:
        logger.error(f"GSB err: {e}")

    # --- AbuseIPDB ---
    try:
        aipdb = check_abuseipdb(url)
        results["abuseipdb"] = aipdb
        if aipdb.get("available"):
            results["sources"].append({
                "name": "AbuseIPDB",
                "status": aipdb["status"]
            })
            if aipdb["abuse_score"] >= 70:
                results["total_penalty"] += 25
                results["findings"].append(f"🛡️ AbuseIPDB: Yüksek suistimal skoru ({aipdb['abuse_score']}%)")
            elif aipdb["abuse_score"] >= 30:
                results["total_penalty"] += 10
                results["findings"].append(f"⚠️ AbuseIPDB: Orta suistimal skoru ({aipdb['abuse_score']}%)")
    except Exception as e:
        logger.error(f"AIPDB err: {e}")

    return results
