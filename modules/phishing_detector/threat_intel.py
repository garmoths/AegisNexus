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
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .cache_db import write_phishing_url, write_ioc
from .screenshot_analyzer import analyze as analyze_screenshot
from .scoring import (
    combine_probabilities,
    to_probability,
    apply_source_weight,
    detect_signals,
    apply_correlation_boost,
    SCORING_MODEL_VERSION,
)

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

ABUSE_CH_API_KEYS = _parse_api_keys(os.getenv("ABUSE_API_KEYS", ""))
if not ABUSE_CH_API_KEYS:
    ABUSE_CH_API_KEYS = _parse_api_keys(os.getenv("ABUSE_API_KEY", ""))

ABUSE_CH_KEY_INDEX = 0

# Cache depolama (in-memory)
API_CACHE = {}
CACHE_TTL = 3600  # 1 saat

# VALIDATED CACHE - Sadece tüm API'ler başarılı olduğunda sakla
VALIDATED_CACHE = {}
VALIDATED_CACHE_TTL = 7200  # 2 saat (daha uzun, çünkü full scan)

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


def _get_current_abuse_ch_key():
    if not ABUSE_CH_API_KEYS:
        return None
    return ABUSE_CH_API_KEYS[ABUSE_CH_KEY_INDEX]


def _rotate_abuse_ch_key():
    global ABUSE_CH_KEY_INDEX
    if len(ABUSE_CH_API_KEYS) > 1:
        ABUSE_CH_KEY_INDEX = (ABUSE_CH_KEY_INDEX + 1) % len(ABUSE_CH_API_KEYS)
    return _get_current_abuse_ch_key()


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


# =========================================================
# 1. VIRUSTOTAL API
# =========================================================

def check_virustotal(url, timeout=5):
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

def check_google_safe_browsing(url, timeout=5):
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
# 4. ABUSEIPDB API
# =========================================================

def check_abuseipdb(url, timeout=5):
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


def check_ioc_threatfox(ioc_value: str, timeout: int = 10):
    """ThreatFox IOC cross-check."""
    normalized = (ioc_value or "").strip()
    cache_key = f"threatfox_{hashlib.sha256(normalized.lower().encode()).hexdigest()}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    if not normalized:
        return {"found": False, "status": "Boş IOC"}

    if not ABUSE_CH_API_KEYS:
        return {"found": False, "status": "ABUSE_API_KEY tanımlı değil"}

    attempts = len(ABUSE_CH_API_KEYS)
    for _ in range(attempts):
        try:
            current_key = _get_current_abuse_ch_key()
            headers = {"API-KEY": current_key} if current_key else {}
            response = requests.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": normalized},
                headers=headers,
                timeout=timeout,
            )
            if response.status_code != 200:
                _rotate_abuse_ch_key()
                continue

            data = response.json()
            if data.get("query_status") == "ok" and data.get("data"):
                entry = data["data"][0]
                result = {
                    "found": True,
                    "ioc_type": entry.get("ioc_type"),
                    "threat_type": entry.get("threat_type"),
                    "malware": entry.get("malware"),
                    "confidence": int(entry.get("confidence_level") or 0),
                    "tags": entry.get("tags", []),
                    "status": "IOC bulundu",
                }
                _set_cached(cache_key, result)
                return result

            result = {"found": False, "status": "IOC bulunamadı"}
            _set_cached(cache_key, result)
            return result
        except Exception as exc:
            logger.warning(f"ThreatFox error: {exc}")
            _rotate_abuse_ch_key()
            continue

    return {"found": False, "status": "ThreatFox sorgusu başarısız"}


def check_hash_malwarebazaar(file_hash: str, timeout: int = 10):
    """MalwareBazaar hash lookup."""
    normalized = (file_hash or "").strip()
    cache_key = f"mb_{hashlib.sha256(normalized.lower().encode()).hexdigest()}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    if not normalized:
        return {"found": False, "status": "Boş hash"}

    if not ABUSE_CH_API_KEYS:
        return {"found": False, "status": "ABUSE_API_KEY tanımlı değil"}

    attempts = len(ABUSE_CH_API_KEYS)
    for _ in range(attempts):
        try:
            current_key = _get_current_abuse_ch_key()
            headers = {"API-KEY": current_key} if current_key else {}
            response = requests.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": normalized},
                headers=headers,
                timeout=timeout,
            )
            if response.status_code != 200:
                _rotate_abuse_ch_key()
                continue

            data = response.json()
            if data.get("query_status") == "ok" and data.get("data"):
                entry = data["data"][0]
                result = {
                    "found": True,
                    "malware_family": entry.get("signature"),
                    "file_type": entry.get("file_type"),
                    "threat_score": (entry.get("intelligence") or {}).get("clamav"),
                    "tags": entry.get("tags", []),
                    "first_seen": entry.get("first_seen"),
                    "status": "Hash bulundu",
                }
                _set_cached(cache_key, result)
                return result

            result = {"found": False, "status": "Hash bulunamadı"}
            _set_cached(cache_key, result)
            return result
        except Exception as exc:
            logger.warning(f"MalwareBazaar error: {exc}")
            _rotate_abuse_ch_key()
            continue

    return {"found": False, "status": "MalwareBazaar sorgusu başarısız"}


def check_ip_shodan(ip: str, timeout: int = 10):
    """Shodan InternetDB lookup."""
    normalized = (ip or "").strip()
    cache_key = f"shodan_{normalized}"
    cached = _get_cached(cache_key)
    if cached:
        return cached

    if not _is_valid_ip(normalized):
        return {"found": False, "status": "Geçersiz IP"}

    try:
        response = requests.get(f"https://internetdb.shodan.io/{normalized}", timeout=timeout)
        if response.status_code != 200:
            return {"found": False, "status": f"Shodan HTTP {response.status_code}"}
        data = response.json()
        result = {
            "found": True,
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "cpes": data.get("cpes", []),
            "vulns": data.get("vulns", []),
            "tags": data.get("tags", []),
            "status": "IP bulundu",
        }
        _set_cached(cache_key, result)
        return result
    except Exception as exc:
        logger.warning(f"Shodan InternetDB error: {exc}")
        return {"found": False, "status": "Shodan sorgusu başarısız"}


def _persist_screenshot_indicators(url: str, indicators: list, confidence: int = 70):
    """Screenshot analizinden gelen indicator'ları IOC cache'e aktar."""
    for item in indicators or []:
        ioc_type = "url"
        ioc_value = url
        threat_type = "phishing"

        if isinstance(item, dict):
            ioc_type = str(item.get("type") or item.get("ioc_type") or "url").strip().lower()
            ioc_value = str(item.get("value") or item.get("ioc_value") or url).strip()
            threat_type = str(item.get("threat_type") or "phishing").strip().lower()
        elif isinstance(item, str) and item.strip():
            ioc_value = item.strip()

        if not ioc_value:
            continue

        if ioc_type not in {"url", "domain", "ip", "hash"}:
            ioc_type = "url"

        write_ioc(
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            threat_type=threat_type,
            confidence=max(0, min(100, int(confidence))),
            source="screenshot_analyzer",
            raw_data={"url": url, "indicator": item},
        )


def _extract_domain_from_url(url: str) -> str:
    parsed_url = urlparse(url if url.startswith("http") else "https://" + url)
    return (parsed_url.netloc or parsed_url.path or "").lower().replace("www.", "").split(":")[0]


def _parse_iso_datetime(value: str | None):
    if not value:
        return None
    try:
        normalized = str(value).strip()
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except Exception:
        return None


# =========================================================
# FAS A: Bayesian Kombinasyon Katmanı
# =========================================================

def combine_probabilities(probabilities: list[float]) -> float:
    """
    Birden fazla bağımsız risk sinyalini Bayesian kombinasyon ile birleştir.
    P(malicious) = 1 - Π(1 - p_i)
    
    Örnek:
    - [0.8, 0.7] → 0.94
    - [0.3, 0.2] → 0.44
    - [] → 0.0
    """
    if not probabilities:
        return 0.0
    
    prob_safe = 1.0
    for p in probabilities:
        bounded_p = max(0.0, min(1.0, float(p)))
        prob_safe *= (1.0 - bounded_p)
    
    return max(0.0, min(1.0, 1.0 - prob_safe))


def to_probability(raw_penalty: int | float) -> float:
    """
    0-100 ölçekli ceza değerini 0-1 arası olasılığa çevir.
    """
    bounded = max(0, min(100, int(raw_penalty)))
    return bounded / 100.0


# =========================================================
# FAS B: Kaynak Ağırlıklandırması (Tiered Reliability)
# =========================================================

SOURCE_WEIGHTS = {
    # Tier 1 — yüksek kesinlik, az false positive
    "virustotal_malicious": 1.0,      # 50+ motor → kesin
    "google_safe_browsing": 0.95,     # Google'ın kendi sistemi
    "phishtank_verified": 0.90,       # İnsan doğrulamalı

    # Tier 2 — güvenilir ama bazen geç güncellenir
    "urlhaus": 0.75,
    "spamhaus_dbl": 0.70,
    "threatfox": 0.65,
    "spamhaus_xbl": 0.60,

    # Tier 3 — destekleyici sinyal, tek başına yetersiz
    "abuseipdb": 0.45,
    "spamhaus_zrd": 0.30,
    "screenshot_suspicious": 0.35,
    "ml_model": 0.40,

    # Tier 4 — yapısal sinyaller, bağlam gerektirir
    "suspicious_tld": 0.25,
    "typosquatting": 0.45,
    "no_https": 0.20,
    "iframe_unknown": 0.15,
}


def get_weighted_penalty(source: str, penalty: int | float) -> float:
    """
    Kaynak ağırlığını, ceza değerine uygula.
    weight=0.75, penalty=40 → 30 (etkin ceza)
    """
    weight = SOURCE_WEIGHTS.get(source, 0.5)
    raw = max(0, min(100, int(penalty)))
    weighted = (raw / 100.0) * weight
    return weighted


# =========================================================
# FAS C: Korelasyon Boost Katmanı
# =========================================================

def _apply_legacy_boost(signals: dict, base_risk: float) -> list[tuple[str, float]]:
    """
    Belirli sinyal kombinasyonları bir arada gelirse,
    çarpanla artar (boost).
    
    Döner: [(boost_name, multiplier), ...]
    """
    boosts = []
    
    # Phishing trifecta: typosquatting + şüpheli TLD + login formu
    if (signals.get("typosquatting") and
        signals.get("suspicious_tld") and
        signals.get("credential_form")):
        boosts.append(("phishing_trifecta", 1.4))
    
    # Threat intel + görsel analiz aynı markayı işaret
    if (signals.get("ti_brand") and
        signals.get("visual_brand") and
        signals.get("ti_brand") == signals.get("visual_brand")):
        boosts.append(("brand_consensus", 1.3))
    
    # Yeni domain + suistimal IP + kara liste = fresh_malicious
    if (signals.get("domain_age_days", 999) < 30 and
        signals.get("abuseipdb_score", 0) > 50 and
        signals.get("urlhaus_listed")):
        boosts.append(("fresh_malicious", 1.35))
    
    # Screenshot alınamadı AMA diğer sinyaller şüpheli
    if (signals.get("screenshot_failed") and
        signals.get("structural_risk", 0) > 0.3):
        boosts.append(("hidden_suspicious", 1.2))
    
    # Birden fazla VT motor + GSB'nin de bulması
    if (signals.get("vt_malicious_count", 0) >= 3 and
        signals.get("google_safe_browsing_threat")):
        boosts.append(("multi_engine_consensus", 1.25))
    
    return boosts


def _get_domain_age_penalty(domain: str) -> dict:
    """
    RDAP üzerinden domain yaşı sinyali üretir.
    Penalty skalası:
    - <7 gün: +65
    - <30 gün: +40
    - <90 gün: +20
    - >=90 gün: +0
    - bilgi alınamaz: +15 (belirsizlik)
    """
    if not domain:
        return {
            "available": False,
            "domain": domain,
            "age_days": None,
            "penalty": 15,
            "detail": "Domain yaşı belirlenemedi (boş domain).",
        }

    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
        if not resp.ok:
            return {
                "available": False,
                "domain": domain,
                "age_days": None,
                "penalty": 15,
                "detail": f"Domain yaşı alınamadı (RDAP HTTP {resp.status_code}).",
            }

        data = resp.json() if resp.content else {}
        events = data.get("events", []) if isinstance(data, dict) else []
        creation_ts = None
        for event in events:
            if not isinstance(event, dict):
                continue
            action = str(event.get("eventAction", "")).lower()
            if action in {"registration", "created"}:
                creation_ts = _parse_iso_datetime(event.get("eventDate"))
                if creation_ts:
                    break

        if creation_ts is None:
            return {
                "available": False,
                "domain": domain,
                "age_days": None,
                "penalty": 15,
                "detail": "Domain yaşı alınamadı (RDAP creation date yok).",
            }

        age_days = max(0, (datetime.now(timezone.utc) - creation_ts).days)
        if age_days < 7:
            return {
                "available": True,
                "domain": domain,
                "age_days": age_days,
                "penalty": 65,
                "detail": f"Domain {age_days} günlük — çok yeni.",
            }
        if age_days < 30:
            return {
                "available": True,
                "domain": domain,
                "age_days": age_days,
                "penalty": 40,
                "detail": f"Domain {age_days} günlük — yeni.",
            }
        if age_days < 90:
            return {
                "available": True,
                "domain": domain,
                "age_days": age_days,
                "penalty": 20,
                "detail": f"Domain {age_days} günlük — görece yeni.",
            }
        return {
            "available": True,
            "domain": domain,
            "age_days": age_days,
            "penalty": 0,
            "detail": f"Domain {age_days} günlük — köklü.",
        }
    except Exception as exc:
        logger.warning(f"Domain age RDAP error ({domain}): {exc}")
        return {
            "available": False,
            "domain": domain,
            "age_days": None,
            "penalty": 15,
            "detail": "Domain yaşı alınamadı (RDAP hatası).",
        }


def _screenshot_failed_penalty(current_risk_score: int) -> int:
    """
    Screenshot alınamama cezası mevcut risk seviyesine göre değişir.
    - risk<20: 0
    - 20<=risk<50: 8
    - risk>=50: 18
    """
    bounded = max(0, min(100, int(current_risk_score)))
    current_risk = bounded / 100.0
    if current_risk < 0.20:
        return 0
    if current_risk < 0.50:
        return 8
    return 18


# =========================================================
# 4. TOPLU TEHDİT İSTİHBARATI
# =========================================================

# A4: Paralel çalışma için iş parçacığı sayısı
_THREAT_INTEL_WORKERS = int(os.getenv("THREAT_INTEL_WORKERS", "5"))


def _task_screenshot(url: str, http_meta, page_text: str, pre_penalty: int):
    """Playwright screenshot + Groq (llama-4-scout) analizi (en ağır iş, B1 pre_penalty ile)."""
    return analyze_screenshot(url=url, http_meta=http_meta, page_text=page_text, pre_penalty=pre_penalty)


def _task_virustotal(url: str):
    """VirusTotal yerel DB sorgusu — her thread kendi SQLAlchemy session'ını açar."""
    from .threat_intel_local import check_virustotal_local as check_virustotal
    from app.database import SessionLocal
    db = None
    try:
        db = SessionLocal()
        result = check_virustotal(url, db)
        return result
    except Exception as exc:
        return {"malicious": 0, "suspicious": 0, "available": False, "source": None, "error": str(exc)}
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                pass


def _task_gsb(url: str):
    """Google Safe Browsing harici API sorgusu."""
    return check_google_safe_browsing(url)


def _task_abuseipdb(url: str):
    """AbuseIPDB yerel IP blacklist sorgusu.
    IP listeleri preload_models() ile startup'ta yüklenmiştir.
    """
    from .threat_intel_local import check_abuseipdb_local as check_abuseipdb
    return check_abuseipdb(url)


def _task_spamhaus_group(url: str, domain: str, resolved_ip: str | None):
    """URLhaus + Spamhaus (domain+IP) + ThreatFox — dahili paralel ThreadPoolExecutor."""
    from .spamhaus_client import query_ip as spamhaus_query_ip, query_domain as spamhaus_query_domain
    from .urlhaus_client import query_url as urlhaus_query_url
    from .threatfox_client import query_ioc as threatfox_query_ioc

    inner_futures: dict = {}
    group: dict = {}
    inner_executor = ThreadPoolExecutor(max_workers=4)
    try:
        inner_futures[inner_executor.submit(urlhaus_query_url, url)] = "urlhaus"
        inner_futures[inner_executor.submit(spamhaus_query_domain, domain)] = "spamhaus_domain"
        if resolved_ip:
            inner_futures[inner_executor.submit(spamhaus_query_ip, resolved_ip)] = "spamhaus_ip"
        inner_futures[inner_executor.submit(threatfox_query_ioc, domain, "domain")] = "threatfox"

        try:
            for future in as_completed(inner_futures, timeout=15):
                key = inner_futures[future]
                try:
                    group[key] = future.result()
                except Exception as exc:
                    logger.warning(f"Spamhaus grup alt-sorgu hatası [{key}]: {exc}")
        except TimeoutError:
            for future, key in inner_futures.items():
                if key not in group:
                    logger.warning(f"Spamhaus grup alt-sorgu timeout [{key}]")

    finally:
        inner_executor.shutdown(wait=False)
    return group


def _task_domain_age(domain: str):
    """RDAP domain yaşı kontrolü — paralel TI bloğunda çalışır."""
    return _get_domain_age_penalty(domain)


def run_threat_intelligence(url, http_meta=None, page_text: str = "", is_whitelisted: bool = False, pre_penalty: int = 0):
    """
    Tüm tehdit istihbaratı kontrollerini PARALEL çalıştırır (A4).
    5 eş zamanlı iş: Screenshot · VT · GSB · AbuseIPDB · Spamhaus/URLhaus/ThreatFox

    validated=True ise: TÜM kontroller başarılı
    validated=False ise: En az bir kontrol başarısız
    """
    results = {
        "screenshot_analysis": None,
        "domain_age": None,
        "virustotal": None,
        "google_safe_browsing": None,
        "abuseipdb": None,
        "total_penalty": 0,
        "findings": [],
        "sources": [],
        "validated": False,
    }
    all_available = True
    domain = _extract_domain_from_url(url)
    screenshot_failed = False

    # ── A4: Domain / IP çözümlemesi (paralel task'lar için ön hazırlık) ──
    parsed_url = urlparse(url if url.startswith("http") else "https://" + url)
    domain = (parsed_url.netloc or parsed_url.path or "").lower().replace("www.", "").split(":")[0]
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(domain)
    except Exception:
        pass

    # ── A4: TÜM kontroller paralel çalıştır (screenshot + RDAP dahil) ─────
    task_results: dict = {}
    futures_map: dict = {}
    with ThreadPoolExecutor(max_workers=max(6, _THREAT_INTEL_WORKERS + 1)) as executor:
        futures_map[executor.submit(_task_screenshot, url, http_meta, page_text, pre_penalty)] = "screenshot"
        futures_map[executor.submit(_task_virustotal, url)] = "virustotal"
        futures_map[executor.submit(_task_gsb, url)] = "gsb"
        futures_map[executor.submit(_task_abuseipdb, url)] = "abuseipdb"
        futures_map[executor.submit(_task_spamhaus_group, url, domain, resolved_ip)] = "spamhaus_group"
        futures_map[executor.submit(_task_domain_age, domain)] = "domain_age"
        try:
            for future in as_completed(futures_map, timeout=40):
                name = futures_map[future]
                try:
                    task_results[name] = future.result()
                except Exception as exc:
                    logger.error(f"Paralel task hatası [{name}]: {exc}")
                    task_results[name] = None
                    all_available = False
        except TimeoutError:
            # Süre dolan tasklar None olarak işle, eldeki sonuçlarla devam et
            all_available = False
            for fut, name in futures_map.items():
                if name not in task_results:
                    logger.warning(f"Paralel task timeout [{name}] — sonuç atlanıyor")
                    task_results[name] = None

    # ── Sonuçları skorla (ana thread, thread-safe) ────────────────────────

    # --- Screenshot Analyzer ---
    shot = task_results.get("screenshot") or {}
    results["screenshot_analysis"] = shot or None
    if shot.get("ai_skipped"):
        skip_reason = shot.get("ai_skip_reason", "bilinmiyor")
        results["total_penalty"] += 10
        results["sources"].append({"name": "Screenshot Analyzer", "status": f"AI atlandı ({skip_reason})"})
        results["findings"].append(f"📸 Screenshot Analyzer: AI atlandı — {skip_reason} (belirsizlik cezası +10)")
    elif shot.get("available", True) and shot:
        risk_score = max(0, min(100, int(shot.get("risk_score", 50))))
        risk_level_str = str(shot.get("risk_level", "UNKNOWN")).upper()
        weighted_penalty = int(round(risk_score * 0.60))
        if risk_level_str == "CRITICAL":
            weighted_penalty = max(weighted_penalty, 70)
        elif risk_level_str == "HIGH":
            weighted_penalty = max(weighted_penalty, 50)
        elif risk_level_str == "MEDIUM":
            weighted_penalty = max(weighted_penalty, 25)
        results["sources"].append({"name": "Screenshot Analyzer", "status": f"{risk_level_str} ({risk_score}/100)"})
        results["total_penalty"] += weighted_penalty
        if weighted_penalty > 0:
            results["findings"].append(
                f"📸 Screenshot Analyzer: {shot.get('verdict', 'Analiz tamamlandı')} "
                f"(risk={risk_score}, ağırlıklı ceza={weighted_penalty})"
            )
        indicators = shot.get("threat_indicators", []) if isinstance(shot, dict) else []
        if indicators:
            _persist_screenshot_indicators(url, indicators, confidence=risk_score)
    elif shot is not None:
        all_available = False
        results["total_penalty"] += 15
        results["findings"].append("📸 Screenshot Analyzer: Ekran görüntüsü alınamadı (belirsizlik cezası uygulandı)")

    # --- VirusTotal LOCAL ---
    vt = task_results.get("virustotal")
    results["virustotal"] = vt
    if vt is not None:
        if vt.get("available"):
            vt_status_label = vt.get("status") or ("Temiz" if vt.get("malicious", 0) == 0 else f"{vt.get('malicious')} tehlikeli")
            results["sources"].append({"name": "VirusTotal", "status": vt_status_label})
            if vt["malicious"] >= 3:
                results["total_penalty"] += 40
                results["findings"].append(f"🛡️ VirusTotal: {vt['malicious']} motor tehlikeli olarak işaretledi!")
            elif vt["malicious"] >= 1:
                results["total_penalty"] += 20
                results["findings"].append(f"⚠️ VirusTotal: {vt['malicious']} motor şüpheli buldu")
            elif vt.get("suspicious", 0) >= 1:
                results["total_penalty"] += 10
                results["findings"].append(f"⚠️ VirusTotal: {vt['suspicious']} motor şüpheli olarak işaretledi")
        else:
            all_available = False
    else:
        all_available = False

    # --- Google Safe Browsing ---
    gsb = task_results.get("gsb")
    results["google_safe_browsing"] = gsb
    if gsb is not None:
        if gsb.get("available"):
            gsb_status_label = gsb.get("status") or (f"Tehdit: {gsb.get('threat')}" if gsb.get("threat") else "Güvenli")
            results["sources"].append({"name": "Google Safe Browsing", "status": gsb_status_label})
            if gsb.get("threat"):
                results["total_penalty"] += 50
                results["findings"].append(f"🛡️ Google Safe Browsing: {gsb_status_label}")
        else:
            all_available = False
    else:
        all_available = False

    # --- AbuseIPDB LOCAL ---
    aipdb = task_results.get("abuseipdb")
    results["abuseipdb"] = aipdb
    if aipdb is not None:
        if aipdb.get("abuse_score", 0) >= 70:
            results["sources"].append({"name": "AbuseIPDB (Local)", "status": "IP blacklist match"})
            results["total_penalty"] += 25
            results["findings"].append(f"🛡️ AbuseIPDB (Local): Yüksek suistimal skoru ({aipdb['abuse_score']}%)")
        elif aipdb.get("abuse_score", 0) >= 30:
            results["sources"].append({"name": "AbuseIPDB (Local)", "status": "IP suspicious"})
            results["total_penalty"] += 10
            results["findings"].append(f"⚠️ AbuseIPDB (Local): Orta suistimal skoru ({aipdb['abuse_score']}%)")
    else:
        all_available = False

    # --- Domain Age (RDAP) ---
    domain_age_signal = task_results.get("domain_age") or {"available": False, "penalty": 0, "detail": "Domain yaşı alınamadı (timeout)."}
    results["domain_age"] = domain_age_signal
    if is_whitelisted and domain_age_signal.get("penalty", 0) > 0:
        results["sources"].append({
            "name": "Domain Age (RDAP)",
            "status": f"{domain_age_signal.get('detail')} Ancak whitelist nedeniyle ceza uygulanmadı"
        })
    else:
        age_penalty = int(domain_age_signal.get("penalty", 0) or 0)
        if age_penalty > 0:
            results["total_penalty"] += age_penalty
            results["sources"].append({
                "name": "Domain Age (RDAP)",
                "status": domain_age_signal.get("detail", "Domain yaşı belirsiz")
            })
            results["findings"].append(f"🧭 Domain Yaşı: {domain_age_signal.get('detail')} (ceza +{age_penalty})")
        else:
            results["sources"].append({
                "name": "Domain Age (RDAP)",
                "status": domain_age_signal.get("detail", "Domain yaşı normal")
            })

    # --- Spamhaus / URLhaus / ThreatFox ---
    sg = task_results.get("spamhaus_group") or {}
    urlhaus_result = sg.get("urlhaus")
    spamhaus_domain_result = sg.get("spamhaus_domain")
    spamhaus_ip_result = sg.get("spamhaus_ip")
    threatfox_result = sg.get("threatfox")

    # URLhaus
    if urlhaus_result and urlhaus_result.get("listed"):
        results["urlhaus"] = urlhaus_result
        if is_whitelisted:
            results["sources"].append({"name": "URLhaus", "status": "Listed ancak whitelist nedeniyle ceza uygulanmadı"})
        else:
            results["total_penalty"] += 40
            results["sources"].append({"name": "URLhaus", "status": f"Listed ({urlhaus_result.get('threat_type', 'unknown')})"})
            results["findings"].append(f"🛡️ URLhaus: URL kara listede ({urlhaus_result.get('threat_type', 'unknown')})")
            write_ioc(ioc_type="url", ioc_value=url, threat_type=urlhaus_result.get("threat_type", "phishing"), confidence=80, source="urlhaus", raw_data=urlhaus_result)
    elif urlhaus_result:
        results["urlhaus"] = urlhaus_result
    else:
        results["urlhaus"] = {"listed": False, "available": False, "status": "Sorgulama yapılamadı"}

    # Spamhaus domain
    if spamhaus_domain_result and spamhaus_domain_result.get("listed"):
        results["spamhaus_domain"] = spamhaus_domain_result
        lists = spamhaus_domain_result.get("lists", [])
        if is_whitelisted:
            results["sources"].append({"name": "Spamhaus Domain", "status": f"Listed ({', '.join(lists)}) whitelist nedeniyle ceza yok"})
        else:
            if "DBL" in lists:
                results["total_penalty"] += 35
                results["sources"].append({"name": "Spamhaus DBL", "status": f"Domain listed ({', '.join(lists)})"})
                results["findings"].append(f"🛡️ Spamhaus DBL: Domain kara listede ({', '.join(lists)})")
            if spamhaus_domain_result.get("zrd"):
                results["total_penalty"] += 15
                results["sources"].append({"name": "Spamhaus ZRD", "status": "Sıfır itibar domain"})
                results["findings"].append("⚠️ Spamhaus ZRD: Sıfır itibar domain (yeni/şüpheli)")
            if "DBL" not in lists and not spamhaus_domain_result.get("zrd"):
                results["total_penalty"] += 35
                results["sources"].append({"name": "Spamhaus Domain", "status": f"Domain listed ({', '.join(lists)})"})
                results["findings"].append(f"🛡️ Spamhaus: Domain listed ({', '.join(lists)})")
            write_ioc(ioc_type="domain", ioc_value=domain, threat_type="spamhaus_dbl", confidence=75, source="spamhaus", raw_data=spamhaus_domain_result)
    elif spamhaus_domain_result:
        results["spamhaus_domain"] = spamhaus_domain_result
    else:
        results["spamhaus_domain"] = {"listed": False, "available": False, "status": "Sorgulama yapılamadı"}

    # Spamhaus IP
    if spamhaus_ip_result and spamhaus_ip_result.get("listed"):
        results["spamhaus_ip"] = spamhaus_ip_result
        ip_lists = spamhaus_ip_result.get("lists", [])
        if is_whitelisted:
            results["sources"].append({"name": "Spamhaus IP", "status": f"IP listed whitelist nedeniyle ceza yok"})
        else:
            if any(ll in ip_lists for ll in ("XBL", "eXBL")):
                results["total_penalty"] += 30
                results["sources"].append({"name": "Spamhaus XBL/eXBL", "status": f"IP listed ({', '.join(ip_lists)})"})
                results["findings"].append(f"🛡️ Spamhaus XBL/eXBL: IP kara listede ({', '.join(ip_lists)})")
            elif ip_lists:
                results["total_penalty"] += 20
                results["sources"].append({"name": "Spamhaus IP", "status": f"IP listed ({', '.join(ip_lists)})"})
                results["findings"].append(f"⚠️ Spamhaus: IP listed ({', '.join(ip_lists)})")
            write_ioc(ioc_type="ip", ioc_value=resolved_ip, threat_type="spamhaus_xbl", confidence=70, source="spamhaus", raw_data=spamhaus_ip_result)
    elif spamhaus_ip_result:
        results["spamhaus_ip"] = spamhaus_ip_result
    else:
        results["spamhaus_ip"] = {"listed": False, "available": False, "status": "Sorgulama yapılamadı"}

    # ThreatFox
    if threatfox_result and threatfox_result.get("found"):
        results["threatfox"] = threatfox_result
        if is_whitelisted:
            results["sources"].append({"name": "ThreatFox", "status": "IOC bulundu ancak whitelist nedeniyle ceza uygulanmadı"})
        else:
            results["total_penalty"] += 25
            results["sources"].append({"name": "ThreatFox", "status": f"IOC bulundu ({threatfox_result.get('malware_family', 'unknown')})"})
            results["findings"].append(
                f"🛡️ ThreatFox: IOC bulundu — {threatfox_result.get('malware_family', 'bilinmeyen')} "
                f"(confidence: {threatfox_result.get('confidence', 0)})"
            )
            write_ioc(ioc_type="domain", ioc_value=domain, threat_type=threatfox_result.get("threat_name", "unknown"), confidence=threatfox_result.get("confidence", 50), source="threatfox", raw_data=threatfox_result)
    elif threatfox_result:
        results["threatfox"] = threatfox_result
    else:
        results["threatfox"] = {"found": False, "available": False, "status": "Sorgulama yapılamadı"}

    # Screenshot belirsizlik cezası (bağlamsal)
    if screenshot_failed and not is_whitelisted:
        uncertainty_penalty = _screenshot_failed_penalty(min(100, results["total_penalty"]))
        if uncertainty_penalty > 0:
            results["total_penalty"] += uncertainty_penalty
            results["sources"].append({
                "name": "Screenshot Analyzer",
                "status": f"Ekran görüntüsü alınamadı (belirsizlik cezası +{uncertainty_penalty})"
            })
            results["findings"].append(
                f"📸 Screenshot Analyzer: Ekran görüntüsü alınamadı (belirsizlik cezası +{uncertainty_penalty})"
            )
        else:
            results["sources"].append({
                "name": "Screenshot Analyzer",
                "status": "Ekran görüntüsü alınamadı, düşük risk nedeniyle ceza uygulanmadı"
            })

    # Risk skorunu ve seviyesini hesapla
    risk_score = min(100, results["total_penalty"])
    
    if risk_score >= 70:
        risk_level = "critical"
    elif risk_score >= 50:
        risk_level = "high"
    elif risk_score >= 30:
        risk_level = "medium"
    elif risk_score >= 10:
        risk_level = "low"
    else:
        risk_level = "safe"
    
    is_safe = risk_score < 30
    
    # Sonuçları ekle
    results["risk_score"] = risk_score
    results["risk_level"] = risk_level
    results["is_safe"] = is_safe
    
    # Detaylı analiz sonuçları
    results["analysis"] = {
        "summary": generate_analysis_summary(results),
        "recommendations": generate_recommendations(results),
        "threat_details": extract_threat_details(results)
    }

    # Validated flag - tüm API'ler başarılıysa TRUE
    results["validated"] = all_available
    logger.debug(f"Threat Intel Result - Validated: {all_available}, Sources: {len(results['sources'])}")
    
    # Cache'e yaz - persistent storage
    try:
        sources_list = [s.get("name", "").lower() for s in results["sources"]]
        write_phishing_url(
            url=url,
            risk_score=results["risk_score"],
            risk_level=results["risk_level"],
            is_safe=results["is_safe"],
            sources=sources_list,
            raw_data=results,
            track_event=False,
        )
        logger.debug(f"URL cached to persistent DB: {url}")
    except Exception as e:
        logger.error(f"Failed to cache URL to DB: {e}")
    
    # ── Faz A: Bayesian probability kombiner ──────────────────────────────
    _pe: list = []

    def _ev(source_key: str, base_prob: float, reason: str, raw_evidence: dict) -> dict:
        wp = apply_source_weight(base_prob, source_key)
        return {"source_key": source_key, "probability": base_prob, "weighted_probability": wp, "reason": reason, "raw_evidence": raw_evidence}

    # Screenshot
    shot_d = results.get("screenshot_analysis")
    if shot_d is None:
        _pe.append(_ev("screenshot_unavailable", to_probability(15), "Ekran görüntüsü alınamadı", {"penalty": 15}))
    elif shot_d.get("ai_skipped"):
        _pe.append(_ev("screenshot_ai_skip", to_probability(10), f"AI atlandı ({shot_d.get('ai_skip_reason', 'bilinmiyor')})", {"penalty": 10}))
    else:
        rs = max(0, min(100, int(shot_d.get("risk_score", 0))))
        rl = str(shot_d.get("risk_level", "UNKNOWN")).upper()
        wp_raw = int(round(rs * 0.60))
        if rl == "CRITICAL":
            wp_raw = max(wp_raw, 70)
        elif rl == "HIGH":
            wp_raw = max(wp_raw, 50)
        elif rl == "MEDIUM":
            wp_raw = max(wp_raw, 25)
        if wp_raw > 0:
            sk = "screenshot_high" if rl in ("CRITICAL", "HIGH") else "screenshot_suspicious"
            _pe.append(_ev(sk, to_probability(wp_raw), f"Screenshot {rl} ({rs}/100)", {"risk_score": rs, "risk_level": rl}))

    # VirusTotal
    vt_d = results.get("virustotal") or {}
    if vt_d.get("available"):
        mal = vt_d.get("malicious", 0)
        sus = vt_d.get("suspicious", 0)
        if mal >= 3:
            _pe.append(_ev("virustotal_malicious", to_probability(40), f"{mal} motor tehlikeli işaretledi", {"malicious": mal}))
        elif mal >= 1:
            _pe.append(_ev("virustotal_malicious", to_probability(20), f"{mal} motor şüpheli buldu", {"malicious": mal}))
        elif sus >= 1:
            _pe.append(_ev("virustotal_suspicious", to_probability(10), f"{sus} motor şüpheli işaretledi", {"suspicious": sus}))

    # Google Safe Browsing
    gsb_d = results.get("google_safe_browsing") or {}
    if gsb_d.get("available") and gsb_d.get("threat"):
        _pe.append(_ev("google_safe_browsing", to_probability(50), f"Tehdit: {gsb_d.get('threat')}", {"threat": gsb_d.get("threat")}))

    # AbuseIPDB
    aipdb_d = results.get("abuseipdb") or {}
    abuse = aipdb_d.get("abuse_score", 0)
    if abuse >= 70:
        _pe.append(_ev("abuseipdb", to_probability(25), f"Yüksek suistimal skoru ({abuse}%)", {"abuse_score": abuse}))
    elif abuse >= 30:
        _pe.append(_ev("abuseipdb", to_probability(10), f"Orta suistimal skoru ({abuse}%)", {"abuse_score": abuse}))

    # URLhaus
    urlhaus_d = results.get("urlhaus") or {}
    if urlhaus_d.get("listed"):
        _pe.append(_ev("urlhaus", to_probability(40), f"URLhaus kara listede ({urlhaus_d.get('threat_type', 'unknown')})", {"threat_type": urlhaus_d.get("threat_type")}))

    # Spamhaus domain
    sp_dom = results.get("spamhaus_domain") or {}
    if sp_dom.get("listed"):
        dom_lists = sp_dom.get("lists", [])
        if "DBL" in dom_lists:
            _pe.append(_ev("spamhaus_dbl", to_probability(35), f"Spamhaus DBL ({', '.join(dom_lists)})", {"lists": dom_lists}))
        if sp_dom.get("zrd"):
            _pe.append(_ev("spamhaus_zrd", to_probability(15), "Sıfır itibar domain", {"zrd": True}))
        if "DBL" not in dom_lists and not sp_dom.get("zrd"):
            _pe.append(_ev("spamhaus_domain", to_probability(35), f"Spamhaus domain listed ({', '.join(dom_lists)})", {"lists": dom_lists}))

    # Spamhaus IP
    sp_ip = results.get("spamhaus_ip") or {}
    if sp_ip.get("listed"):
        ip_lists = sp_ip.get("lists", [])
        if any(ll in ip_lists for ll in ("XBL", "eXBL")):
            _pe.append(_ev("spamhaus_xbl", to_probability(30), f"Spamhaus XBL/eXBL ({', '.join(ip_lists)})", {"lists": ip_lists}))
        elif ip_lists:
            _pe.append(_ev("spamhaus_ip", to_probability(20), f"Spamhaus IP listed ({', '.join(ip_lists)})", {"lists": ip_lists}))

    # ThreatFox
    tf_d = results.get("threatfox") or {}
    if tf_d.get("found"):
        _pe.append(_ev("threatfox", to_probability(25), f"ThreatFox IOC ({tf_d.get('malware_family', 'unknown')})", {"malware_family": tf_d.get("malware_family"), "confidence": tf_d.get("confidence")}))

    combined_probability = combine_probabilities([e["weighted_probability"] for e in _pe])

    # ── Faz C: Korelasyon boost ───────────────────────────────
    _signals = detect_signals(
        domain=domain,
        page_text=page_text,
        screenshot_analysis=results.get("screenshot_analysis"),
        abuseipdb=results.get("abuseipdb"),
        urlhaus=results.get("urlhaus"),
        pre_penalty=pre_penalty,
    )
    boosted_probability, _boost_events = apply_correlation_boost(combined_probability, _signals)
    # ── /Faz C

    results["combined_risk_probability"] = boosted_probability
    results["scoring_model"] = SCORING_MODEL_VERSION
    results["scoring_details"] = {
        "penalty_events": _pe,
        "legacy_penalty": results.get("total_penalty", 0),
        "signal_count": len(_pe),
        "signals": _signals,
        "correlation_boosts": _boost_events,
        "pre_boost_probability": combined_probability,
    }
    # ── /Faz A+B+C ─────────────────────────────────────────────────────────────

    return results


def generate_analysis_summary(results):
    """Detaylı analiz özeti oluştur"""
    score = results.get("risk_score", 0)
    level = results.get("risk_level", "unknown")
    findings = results.get("findings", [])
    sources = results.get("sources", [])
    
    if level == "safe":
        return f"✅ URL güvenli görünüyor. {len(sources)} güvenlik kaynağı tarafından kontrol edildi ve herhangi bir tehdit tespit edilmedi."
    elif level == "low":
        return f"⚠️ Düşük risk seviyesi. {len(sources)} kaynaktan {len(findings)} şüpheli bulgu tespit edildi. Dikkatli olunması önerilir."
    elif level == "medium":
        return f"🔴 Orta risk seviyesi. {len(sources)} kaynaktan {len(findings)} bulgu tespit edildi. URL potansiyel tehdit içerebilir."
    elif level == "high":
        return f"🚨 Yüksek risk seviyesi! {len(sources)} kaynaktan {len(findings)} tehlikeli bulgu tespit edildi. Bu URL'den kaçınılmalıdır."
    elif level == "critical":
        return f"💀 KRİTİK TEHDİT! {len(sources)} kaynaktan {len(findings)} tehlikeli bulgu tespit edildi. URL kesinlikle güvenli değildir."
    else:
        return f"❓ Analiz yapılamadı. {len(sources)} kaynak kontrol edildi ancak skor hesaplanamadı."


def generate_recommendations(results):
    """Güvenlik önerileri oluştur"""
    level = results.get("risk_level", "unknown")
    score = results.get("risk_score", 0)
    
    if level == "safe":
        return [
            "✅ URL güvenli görünmektedir",
            "📧 E-postada gelen linkler için yine de dikkatli olun",
            "🔒 Her zaman HTTPS bağlantısını kontrol edin"
        ]
    elif level == "low":
        return [
            "⚠️ URL'ye dikkatli yaklaşın",
            "🔍 Ek güvenlik kontrolü yapın",
            "📧 Gönderenin doğruluğunu teyit edin"
        ]
    elif level == "medium":
        return [
            "🚫 Bu URL'ye tıklamaktan kaçının",
            "🔒 Antivirüs programınızı güncelleyin",
            "📞 Şüpheli durumda IT departmanınıza bildirin"
        ]
    elif level in ["high", "critical"]:
        return [
            "🛑 KESİNLİKLE TIKLAMAYIN!",
            "🗑️ E-postayı hemen silin",
            "🚨 IT güvenlik ekibine bildirin",
            "🔒 Şifrelerinizi değiştirin",
            "📱 Cihazınızda virüs taraması yapın"
        ]
    else:
        return [
            "❓ Analiz tamamlanamadı",
            "🔄 Daha sonra tekrar deneyin",
            "🔍 Manuel kontrol yapın"
        ]


def extract_threat_details(results):
    """Tehdit detaylarını çıkar"""
    details = []
    
    # VirusTotal detayları
    vt = results.get("virustotal") or {}
    if vt.get("available"):
        if vt.get("malicious", 0) > 0:
            details.append(f"🛡️ VirusTotal: {vt['malicious']}/{vt.get('total', 0)} motor tehlikeli")
        if vt.get("suspicious", 0) > 0:
            details.append(f"⚠️ VirusTotal: {vt['suspicious']} motor şüpheli")
    
    # Google Safe Browsing detayları
    gsb = results.get("google_safe_browsing") or {}
    if gsb.get("available") and gsb.get("threat"):
        details.append(f"🔍 Google: {gsb.get('threat_type', 'Bilinmeyen tehdit')}")
    
    # AbuseIPDB detayları
    abuse = results.get("abuseipdb") or {}
    if abuse.get("available"):
        if abuse.get("abuse_score", 0) > 0:
            details.append(f"📊 AbuseIPDB: %{abuse['abuse_score']} suistimal skoru")
        if abuse.get("total_reports", 0) > 0:
            details.append(f"📝 AbuseIPDB: {abuse['total_reports']} rapor")
    
    # Screenshot Analyzer detayları
    shot = results.get("screenshot_analysis", {}) or {}
    if shot:
        details.append(
            f"📸 Screenshot Analyzer: {shot.get('risk_level', 'UNKNOWN')} "
            f"({shot.get('risk_score', 50)}/100)"
        )
        indicators = shot.get("threat_indicators", [])
        if isinstance(indicators, list) and indicators:
            details.append(f"🧩 Görsel tehdit indikatörleri: {len(indicators)}")

    # URLhaus detayları
    urlhaus = results.get("urlhaus", {})
    if urlhaus and urlhaus.get("listed"):
        details.append(f"🔗 URLhaus: Kara listede ({urlhaus.get('threat_type', 'unknown')})")

    # Spamhaus detayları
    spamhaus_domain = results.get("spamhaus_domain", {})
    if spamhaus_domain and spamhaus_domain.get("listed"):
        lists = spamhaus_domain.get("lists", [])
        details.append(f"🛡️ Spamhaus Domain: Listed ({', '.join(lists)})")
    spamhaus_ip = results.get("spamhaus_ip", {})
    if spamhaus_ip and spamhaus_ip.get("listed"):
        ip_lists = spamhaus_ip.get("lists", [])
        details.append(f"🛡️ Spamhaus IP: Listed ({', '.join(ip_lists)})")

    # ThreatFox detayları
    threatfox = results.get("threatfox", {})
    if threatfox and threatfox.get("found"):
        details.append(f"🦊 ThreatFox: {threatfox.get('malware_family', 'unknown')} (confidence: {threatfox.get('confidence', 0)})")

    return details
