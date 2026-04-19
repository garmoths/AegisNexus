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
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")
logger = logging.getLogger(__name__)

def _parse_api_keys(raw_value: str) -> list[str]:
    if not raw_value:
        return []
    normalized = raw_value.replace("\n", ",")
    return [k.strip() for k in normalized.split(",") if k.strip()]


# API Key'ler .env dosyasından okunur (multiple keys for rotation)
VIRUSTOTAL_API_KEYS = _parse_api_keys(os.getenv("VIRUSTOTAL_API_KEYS", ""))
if not VIRUSTOTAL_API_KEYS:
    VIRUSTOTAL_API_KEYS = _parse_api_keys(os.getenv("VIRUSTOTAL_API_KEY", ""))

GOOGLE_SAFE_BROWSING_KEYS = _parse_api_keys(os.getenv("GOOGLE_SAFE_BROWSING_KEYS", ""))
if not GOOGLE_SAFE_BROWSING_KEYS:
    GOOGLE_SAFE_BROWSING_KEYS = _parse_api_keys(os.getenv("GOOGLE_SAFE_BROWSING_KEY", ""))

ABUSEIPDB_API_KEYS = _parse_api_keys(os.getenv("ABUSEIPDB_API_KEYS", ""))
if not ABUSEIPDB_API_KEYS:
    ABUSEIPDB_API_KEYS = _parse_api_keys(os.getenv("ABUSEIPDB_API_KEY", ""))

URLSCAN_API_KEYS = _parse_api_keys(os.getenv("URLSCAN_API_KEYS", ""))
if not URLSCAN_API_KEYS:
    URLSCAN_API_KEYS = _parse_api_keys(os.getenv("URLSCAN_API_KEY", ""))

# Cache depolama (in-memory)
API_CACHE = {}
CACHE_TTL = 3600  # 1 saat

# Rate limiting depolama
API_RATE_LIMITS = {
    "virustotal": {"requests": [], "limit": 4, "window": 60, "key_index": 0},  # 4 req/min
    "abuseipdb": {"requests": [], "limit": 1500, "window": 86400, "key_index": 0},  # 1500 req/day
    "google_safe": {"requests": [], "limit": 10000, "window": 86400, "key_index": 0},  # 10000 req/day
    "urlscan": {"requests": [], "limit": 30, "window": 60, "key_index": 0},  # 30 req/min
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
    
    elif api_name == "urlscan":
        if len(URLSCAN_API_KEYS) > 1:
            current_idx = API_RATE_LIMITS[api_name]["key_index"]
            next_idx = (current_idx + 1) % len(URLSCAN_API_KEYS)
            API_RATE_LIMITS[api_name]["key_index"] = next_idx
            API_RATE_LIMITS[api_name]["requests"] = []
            logger.info(f"Rotated urlscan.io key: {current_idx} → {next_idx}")
            return URLSCAN_API_KEYS[next_idx]
        return URLSCAN_API_KEYS[0] if URLSCAN_API_KEYS else None
    
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
    elif api_name == "urlscan":
        idx = API_RATE_LIMITS[api_name]["key_index"]
        return URLSCAN_API_KEYS[idx] if idx < len(URLSCAN_API_KEYS) else None
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
    VirusTotal API v3 ile URL taraması (key rotation + cached).
    Sadece 200 = başarı, başka her şey = sonraki key'e geç.
    Döndürür: {"malicious": int, "suspicious": int, "clean": int, "status": str}
    """
    cache_key = f"vt_{hashlib.sha256(url.encode()).hexdigest()}"
    
    # Cache kontrol
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not VIRUSTOTAL_API_KEYS:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "malicious": 0, "suspicious": 0, "clean": 0,
            "engines": []
        }
    
    # Tüm key'leri dene
    attempts = len(VIRUSTOTAL_API_KEYS)
    last_status_code = None
    for attempt in range(attempts):
        try:
            import base64
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            
            current_key = _get_current_api_key("virustotal")
            headers = {"x-apikey": current_key}
            
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            resp = requests.get(api_url, headers=headers, timeout=timeout)
            last_status_code = resp.status_code
            
            # Sadece 200 = başarı - immediately return!
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                harmless = stats.get("harmless", 0)
                undetected = stats.get("undetected", 0)
                
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
                    "engines": threat_engines[:10]
                }
                _set_cached(cache_key, result)
                logger.debug(f"✅ VirusTotal success on attempt {attempt + 1}, returning immediately")
                return result
            
            elif resp.status_code == 404:
                # Rapor yoksa yeni tarama başlat
                scan_resp = requests.post(
                    "https://www.virustotal.com/api/v3/urls",
                    headers=headers,
                    data={"url": url},
                    timeout=timeout
                )
                last_status_code = scan_resp.status_code
                if scan_resp.status_code == 200:
                    return {
                        "available": True,
                        "status": "Tarama başlatıldı (sonuçlar birkaç dakika içinde hazır)",
                        "malicious": 0, "suspicious": 0, "clean": 0,
                        "engines": [],
                        "scan_initiated": True
                    }
                else:
                    logger.warning(f"VirusTotal key #{API_RATE_LIMITS['virustotal']['key_index']}: HTTP {scan_resp.status_code}, rotating...")
                    _rotate_api_key("virustotal")
                    continue
            
            else:
                # Non-200 status = rotate to next key
                logger.warning(f"VirusTotal key #{API_RATE_LIMITS['virustotal']['key_index']}: HTTP {resp.status_code}, rotating (attempt {attempt + 1}/{attempts})...")
                _rotate_api_key("virustotal")
                continue
        
        except requests.Timeout:
            logger.warning(f"VirusTotal key #{API_RATE_LIMITS['virustotal']['key_index']}: timeout (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("virustotal")
            continue
        except Exception as e:
            logger.warning(f"VirusTotal key #{API_RATE_LIMITS['virustotal']['key_index']}: {e} (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("virustotal")
            continue
    
    # Tüm key'ler başarısız - return empty result
    logger.error(f"❌ VirusTotal: All {len(VIRUSTOTAL_API_KEYS)} keys exhausted")
    status_detail = f"VirusTotal: Tüm {len(VIRUSTOTAL_API_KEYS)} API key başarısız"
    if last_status_code is not None:
        status_detail += f" (son HTTP {last_status_code})"
    return {
        "available": False if last_status_code == 401 else True,
        "status": status_detail,
        "malicious": 0, "suspicious": 0, "clean": 0,
        "engines": []
    }


# =========================================================
# 2. GOOGLE SAFE BROWSING API
# =========================================================

def check_google_safe_browsing(url, timeout=8):
    """
    Google Safe Browsing API v4 ile kontrol (key rotation + cached).
    Sadece 200 = başarı, başka her şey = sonraki key'e geç.
    Döndürür: {"threat": bool, "threat_type": str, "status": str}
    """
    cache_key = f"gsb_{hashlib.sha256(url.encode()).hexdigest()}"
    
    # Cache kontrol
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not GOOGLE_SAFE_BROWSING_KEYS:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "threat": False,
            "threat_type": None
        }
    
    # Tüm key'leri dene
    attempts = len(GOOGLE_SAFE_BROWSING_KEYS)
    for attempt in range(attempts):
        try:
            current_key = _get_current_api_key("google_safe")
            api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={current_key}"
            
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
            
            # Sadece 200 = başarı - immediately return!
            if resp.status_code == 200:
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
                    logger.debug(f"✅ Google Safe Browsing success on attempt {attempt + 1}, returning immediately")
                    return result
                
                result = {
                    "available": True,
                    "status": "✅ Google Safe Browsing: Temiz",
                    "threat": False,
                    "threat_type": None
                }
                _set_cached(cache_key, result)
                logger.debug(f"✅ Google Safe Browsing success (clean) on attempt {attempt + 1}, returning immediately")
                return result
            
            else:
                logger.warning(f"Google Safe Browsing key #{API_RATE_LIMITS['google_safe']['key_index']}: HTTP {resp.status_code}, rotating (attempt {attempt + 1}/{attempts})...")
                _rotate_api_key("google_safe")
                continue
        
        except requests.Timeout:
            logger.warning(f"Google Safe Browsing key #{API_RATE_LIMITS['google_safe']['key_index']}: timeout (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("google_safe")
            continue
        except Exception as e:
            logger.warning(f"Google Safe Browsing key #{API_RATE_LIMITS['google_safe']['key_index']}: {e} (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("google_safe")
            continue
    
    # Tüm key'ler başarısız - return empty result
    logger.error(f"❌ Google Safe Browsing: All {len(GOOGLE_SAFE_BROWSING_KEYS)} keys exhausted")
    return {
        "available": True,
        "status": f"Google Safe Browsing: Tüm {len(GOOGLE_SAFE_BROWSING_KEYS)} API key başarısız",
        "threat": False,
        "threat_type": None
    }


# =========================================================
# 3. URLSCAN.IO
# =========================================================

def _format_urlscan_result(data):
    verdicts = data.get("verdicts", {})
    overall = verdicts.get("overall", {}) if isinstance(verdicts, dict) else {}
    malicious = bool(overall.get("malicious", False))
    score = overall.get("score", 0) or 0
    categories = overall.get("categories", []) if isinstance(overall.get("categories", []), list) else []
    report_url = data.get("task", {}).get("reportURL")
    
    if malicious:
        status = "🚨 urlscan.io: Zararlı olarak işaretlendi"
    elif score and score > 0:
        status = f"⚠️ urlscan.io: Şüpheli skor ({score})"
    else:
        status = "✅ urlscan.io: Temiz"
    
    return {
        "available": True,
        "status": status,
        "malicious": malicious,
        "score": score,
        "categories": categories,
        "report_url": report_url,
    }


def check_urlscan(url, timeout=12):
    """
    urlscan.io API ile URL taraması (key rotation + cached).
    """
    cache_key = f"urlscan_{hashlib.sha256(url.encode()).hexdigest()}"
    
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not URLSCAN_API_KEYS:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "malicious": False,
            "score": 0,
            "categories": []
        }
    
    attempts = len(URLSCAN_API_KEYS)
    last_status_code = None
    for attempt in range(attempts):
        try:
            current_key = _get_current_api_key("urlscan")
            headers = {"API-Key": current_key, "Content-Type": "application/json"}
            
            search_resp = requests.get(
                "https://urlscan.io/api/v1/search/",
                headers={"API-Key": current_key},
                params={"q": f'url:"{url}"', "size": 1},
                timeout=timeout
            )
            last_status_code = search_resp.status_code
            
            if search_resp.status_code == 200:
                search_data = search_resp.json()
                results = search_data.get("results", [])
                if results:
                    result_url = results[0].get("result")
                    if result_url:
                        result_resp = requests.get(result_url, headers={"API-Key": current_key}, timeout=timeout)
                        last_status_code = result_resp.status_code
                        if result_resp.status_code == 200:
                            formatted = _format_urlscan_result(result_resp.json())
                            _set_cached(cache_key, formatted)
                            return formatted
            
            scan_resp = requests.post(
                "https://urlscan.io/api/v1/scan/",
                headers=headers,
                json={"url": url, "visibility": "public"},
                timeout=timeout
            )
            last_status_code = scan_resp.status_code
            
            if scan_resp.status_code == 200:
                return {
                    "available": True,
                    "status": "urlscan.io: Tarama başlatıldı (sonuçlar birkaç dakika içinde hazır)",
                    "scan_initiated": True,
                    "malicious": False,
                    "score": 0,
                    "categories": []
                }
            
            logger.warning(f"urlscan.io key #{API_RATE_LIMITS['urlscan']['key_index']}: HTTP {scan_resp.status_code}, rotating (attempt {attempt + 1}/{attempts})...")
            _rotate_api_key("urlscan")
        
        except requests.Timeout:
            logger.warning(f"urlscan.io key #{API_RATE_LIMITS['urlscan']['key_index']}: timeout (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("urlscan")
            continue
        except Exception as e:
            logger.warning(f"urlscan.io key #{API_RATE_LIMITS['urlscan']['key_index']}: {e} (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("urlscan")
            continue
    
    status_detail = f"urlscan.io: Tüm {len(URLSCAN_API_KEYS)} API key başarısız"
    if last_status_code is not None:
        status_detail += f" (son HTTP {last_status_code})"
    
    return {
        "available": False if last_status_code in (401, 403) else True,
        "status": status_detail,
        "malicious": False,
        "score": 0,
        "categories": []
    }


# =========================================================
# 4. ABUSEIPDB API
# =========================================================

def check_abuseipdb(url, timeout=8):
    """
    AbuseIPDB ile domain/IP itibar kontrolü (key rotation + cached).
    Sadece 200 = başarı, başka her şey = sonraki key'e geç.
    Döndürür: {"abuse_score": int, "reports": int, "status": str}
    """
    cache_key = f"abuseipdb_{hashlib.sha256(url.encode()).hexdigest()}"
    
    # Cache kontrol
    cached = _get_cached(cache_key)
    if cached:
        return cached
    
    if not ABUSEIPDB_API_KEYS:
        return {
            "available": False,
            "status": "API key tanımlı değil",
            "abuse_score": 0,
            "total_reports": 0
        }
    
    # Tüm key'leri dene
    attempts = len(ABUSEIPDB_API_KEYS)
    for attempt in range(attempts):
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
            
            current_key = _get_current_api_key("abuseipdb")
            headers = {
                "Key": current_key,
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
            
            # Sadece 200 = başarı - immediately return!
            if resp.status_code == 200:
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
                _set_cached(cache_key, result)
                logger.debug(f"✅ AbuseIPDB success on attempt {attempt + 1}, returning immediately")
                return result
            
            else:
                logger.warning(f"AbuseIPDB key #{API_RATE_LIMITS['abuseipdb']['key_index']}: HTTP {resp.status_code}, rotating (attempt {attempt + 1}/{attempts})...")
                _rotate_api_key("abuseipdb")
                continue
        
        except requests.Timeout:
            logger.warning(f"AbuseIPDB key #{API_RATE_LIMITS['abuseipdb']['key_index']}: timeout (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("abuseipdb")
            continue
        except Exception as e:
            logger.warning(f"AbuseIPDB key #{API_RATE_LIMITS['abuseipdb']['key_index']}: {e} (attempt {attempt + 1}/{attempts}), rotating...")
            _rotate_api_key("abuseipdb")
            continue
    
    # Tüm key'ler başarısız - return empty result
    logger.error(f"❌ AbuseIPDB: All {len(ABUSEIPDB_API_KEYS)} keys exhausted")
    return {
        "available": True,
        "status": f"AbuseIPDB: Tüm {len(ABUSEIPDB_API_KEYS)} API key başarısız",
        "abuse_score": 0,
        "total_reports": 0
    }


# =========================================================
# 4. TOPLU TEHDİT İSTİHBARATI
# =========================================================

def run_threat_intelligence(url):
    """
    Tüm harici API'leri paralel olmayan şekilde çalıştırır.
    PRIMARY: URLScan.io (reliyable)
    FALLBACK: VirusTotal (single key, limited)
    SECONDARY: Google Safe Browsing, AbuseIPDB
    """
    results = {
        "urlscan": None,           # PRIMARY
        "virustotal": None,         # FALLBACK (single key)
        "google_safe_browsing": None,
        "abuseipdb": None,
        "total_penalty": 0,
        "findings": [],
        "sources": [],
    }

    # --- URLScan.io (PRIMARY) ---
    try:
        urlscan = check_urlscan(url)
        results["urlscan"] = urlscan
        if urlscan.get("available"):
            results["sources"].append({
                "name": "urlscan.io",
                "status": urlscan["status"]
            })
            if urlscan.get("malicious"):
                results["total_penalty"] += 35
                results["findings"].append("🛡️ urlscan.io: Zararlı olarak işaretlendi")
            elif urlscan.get("score", 0) and urlscan.get("score", 0) > 0:
                results["total_penalty"] += 15
                results["findings"].append(f"⚠️ urlscan.io: Şüpheli skor ({urlscan.get('score')})")
    except Exception as e:
        logger.error(f"URLScan err: {e}")
    
    # --- VirusTotal (FALLBACK - single key) ---
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
