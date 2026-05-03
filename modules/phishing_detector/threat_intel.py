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
from datetime import datetime, timedelta
from pathlib import Path

from .cache_db import write_phishing_url, write_ioc
from .screenshot_analyzer import analyze as analyze_screenshot

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


# =========================================================
# 4. TOPLU TEHDİT İSTİHBARATI
# =========================================================

def run_threat_intelligence(url, http_meta=None, page_text: str = "", is_whitelisted: bool = False):
    """
    Tüm harici API'leri paralel olmayan şekilde çalıştırır.
    PRIMARY: Screenshot Analyzer (Playwright + Gemini Vision)
    LOCAL REPLACEMENTS: VirusTotal → local DB, AbuseIPDB → IP blacklist
    SECONDARY: Google Safe Browsing
    
    validated=True ise: TÜM API'ler başarılı (200 status)
    validated=False ise: En az bir API fail oldu (cache'e alınmaz)
    """
    results = {
        "screenshot_analysis": None,  # PRIMARY
        "virustotal": None,         # LOCAL REPLACEMENT
        "google_safe_browsing": None,
        "abuseipdb": None,          # LOCAL REPLACEMENT
        "total_penalty": 0,
        "findings": [],
        "sources": [],
        "validated": False  # Başlangıç: invalid, tüm API'ler başarılı olursa True olur
    }

    all_available = True

    # --- Screenshot Analyzer (PRIMARY) ---
    # pre_penalty=0 şimdilik; B1/B2/B3 uygulandığında burada toplam pre_penalty geçilecek
    try:
        shot = analyze_screenshot(url=url, http_meta=http_meta, page_text=page_text, pre_penalty=0)
        results["screenshot_analysis"] = shot
        if shot.get("gemini_skipped"):
            # Gemini atlandı: screenshot var ama AI analizi yok — küçük belirsizlik cezası
            results["total_penalty"] += 10
            skip_reason = shot.get("gemini_skip_reason", "bilinmiyor")
            results["sources"].append({
                "name": "Screenshot Analyzer",
                "status": f"Gemini atlandı ({skip_reason})"
            })
            results["findings"].append(
                f"📸 Screenshot Analyzer: Gemini atlandı — {skip_reason} (belirsizlik cezası +10)"
            )
        elif shot.get("available", True):
            risk_score = max(0, min(100, int(shot.get("risk_score", 50))))
            risk_level_str = str(shot.get("risk_level", "UNKNOWN")).upper()
            weighted_penalty = int(round(risk_score * 0.60))
            if risk_level_str == "CRITICAL":
                weighted_penalty = max(weighted_penalty, 70)
            elif risk_level_str == "HIGH":
                weighted_penalty = max(weighted_penalty, 50)
            elif risk_level_str == "MEDIUM":
                weighted_penalty = max(weighted_penalty, 25)
            results["sources"].append({
                "name": "Screenshot Analyzer",
                "status": f"{risk_level_str} ({risk_score}/100)"
            })
            results["total_penalty"] += weighted_penalty
            if weighted_penalty > 0:
                results["findings"].append(
                    f"📸 Screenshot Analyzer: {shot.get('verdict', 'Analiz tamamlandı')} "
                    f"(risk={risk_score}, ağırlıklı ceza={weighted_penalty})"
                )
            indicators = shot.get("threat_indicators", []) if isinstance(shot, dict) else []
            if indicators:
                _persist_screenshot_indicators(url, indicators, confidence=risk_score)
        else:
            all_available = False
            results["total_penalty"] += 15
            results["findings"].append("📸 Screenshot Analyzer: Ekran görüntüsü alınamadı (belirsizlik cezası uygulandı)")
    except Exception as e:
        logger.error(f"Screenshot Analyzer err: {e}")
        all_available = False
    
    # --- VirusTotal LOCAL REPLACEMENT ---
    try:
        from .threat_intel_local import check_virustotal_local as check_virustotal
        from app.database import SessionLocal
        
        logger.info(f"Calling local VirusTotal replacement for: {url}")
        db = SessionLocal()
        vt = check_virustotal(url, db)
        db.close()
        logger.info(f"Local VirusTotal result: {vt}")
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
        else:
            all_available = False
    except Exception as e:
        logger.error(f"VT err: {e}")
        all_available = False

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
        else:
            all_available = False
    except Exception as e:
        logger.error(f"GSB err: {e}")
        all_available = False

    # --- AbuseIPDB LOCAL REPLACEMENT ---
    try:
        from .threat_intel_local import check_abuseipdb_local as check_abuseipdb
        
        # Load IP blacklists on first use
        from .threat_intel_local import load_ip_blacklists
        load_ip_blacklists("/opt/phishing/ip_lists")
        
        aipdb = check_abuseipdb(url)
        results["abuseipdb"] = aipdb
        if aipdb.get("abuse_score", 0) >= 70:
            results["sources"].append({
                "name": "AbuseIPDB (Local)",
                "status": "IP blacklist match"
            })
            results["total_penalty"] += 25
            results["findings"].append(f"🛡️ AbuseIPDB (Local): Yüksek suistimal skoru ({aipdb['abuse_score']}%)")
        elif aipdb.get("abuse_score", 0) >= 30:
            results["sources"].append({
                "name": "AbuseIPDB (Local)",
                "status": "IP suspicious"
            })
            results["total_penalty"] += 10
            results["findings"].append(f"⚠️ AbuseIPDB (Local): Orta suistimal skoru ({aipdb['abuse_score']}%)")
    except Exception as e:
        logger.error(f"AIPDB local err: {e}")
        all_available = False

    # --- Spamhaus / URLhaus / ThreatFox (paralel) ---
    try:
        from .spamhaus_client import query_ip as spamhaus_query_ip, query_domain as spamhaus_query_domain
        from .urlhaus_client import query_url as urlhaus_query_url
        from .threatfox_client import query_ioc as threatfox_query_ioc

        # URL'den domain ve IP parse et
        parsed_url = urlparse(url if url.startswith("http") else "https://" + url)
        domain = (parsed_url.netloc or parsed_url.path or "").lower().replace("www.", "").split(":")[0]
        resolved_ip = None
        try:
            resolved_ip = socket.gethostbyname(domain)
        except Exception:
            pass

        # Paralel sorgular
        futures_map = {}
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures_map[executor.submit(urlhaus_query_url, url)] = "urlhaus"
            futures_map[executor.submit(spamhaus_query_domain, domain)] = "spamhaus_domain"
            if resolved_ip:
                futures_map[executor.submit(spamhaus_query_ip, resolved_ip)] = "spamhaus_ip"
            futures_map[executor.submit(threatfox_query_ioc, domain, "domain")] = "threatfox"

        urlhaus_result = None
        spamhaus_ip_result = None
        spamhaus_domain_result = None
        threatfox_result = None

        for future in as_completed(futures_map, timeout=30):
            source_name = futures_map[future]
            try:
                res = future.result()
            except Exception as exc:
                logger.warning(f"{source_name} paralel sorgu hatası: {exc}")
                continue

            if source_name == "urlhaus":
                urlhaus_result = res
            elif source_name == "spamhaus_ip":
                spamhaus_ip_result = res
            elif source_name == "spamhaus_domain":
                spamhaus_domain_result = res
            elif source_name == "threatfox":
                threatfox_result = res

        # URLhaus skorlama
        if urlhaus_result and urlhaus_result.get("listed"):
            results["urlhaus"] = urlhaus_result
            if is_whitelisted:
                results["sources"].append({
                    "name": "URLhaus",
                    "status": "Listed ancak whitelist nedeniyle ceza uygulanmadı"
                })
            else:
                results["total_penalty"] += 40
                results["sources"].append({
                    "name": "URLhaus",
                    "status": f"Listed ({urlhaus_result.get('threat_type', 'unknown')})"
                })
                results["findings"].append(
                    f"🛡️ URLhaus: URL kara listede ({urlhaus_result.get('threat_type', 'unknown')})"
                )
                # IOC olarak kaydet
                write_ioc(
                    ioc_type="url", ioc_value=url,
                    threat_type=urlhaus_result.get("threat_type", "phishing"),
                    confidence=80, source="urlhaus",
                    raw_data=urlhaus_result,
                )
        elif urlhaus_result:
            results["urlhaus"] = urlhaus_result

        # Spamhaus domain skorlama
        if spamhaus_domain_result and spamhaus_domain_result.get("listed"):
            results["spamhaus_domain"] = spamhaus_domain_result
            lists = spamhaus_domain_result.get("lists", [])
            if is_whitelisted:
                results["sources"].append({
                    "name": "Spamhaus Domain",
                    "status": f"Listed ({', '.join(lists)}) ancak whitelist nedeniyle ceza uygulanmadı"
                })
            else:
                if "DBL" in lists:
                    results["total_penalty"] += 35
                    results["sources"].append({
                        "name": "Spamhaus DBL",
                        "status": f"Domain listed ({', '.join(lists)})"
                    })
                    results["findings"].append(
                        f"🛡️ Spamhaus DBL: Domain kara listede ({', '.join(lists)})"
                    )
                if spamhaus_domain_result.get("zrd"):
                    results["total_penalty"] += 15
                    results["sources"].append({
                        "name": "Spamhaus ZRD",
                        "status": "Sıfır itibar domain"
                    })
                    results["findings"].append("⚠️ Spamhaus ZRD: Sıfır itibar domain (yeni/şüpheli)")
                if "DBL" not in lists and not spamhaus_domain_result.get("zrd"):
                    results["total_penalty"] += 35
                    results["sources"].append({
                        "name": "Spamhaus Domain",
                        "status": f"Domain listed ({', '.join(lists)})"
                    })
                    results["findings"].append(
                        f"🛡️ Spamhaus: Domain listed ({', '.join(lists)})"
                    )
                # IOC kaydet
                write_ioc(
                    ioc_type="domain", ioc_value=domain,
                    threat_type="spamhaus_dbl", confidence=75,
                    source="spamhaus", raw_data=spamhaus_domain_result,
                )
        elif spamhaus_domain_result:
            results["spamhaus_domain"] = spamhaus_domain_result

        # Spamhaus IP skorlama
        if spamhaus_ip_result and spamhaus_ip_result.get("listed"):
            results["spamhaus_ip"] = spamhaus_ip_result
            ip_lists = spamhaus_ip_result.get("lists", [])
            if is_whitelisted:
                results["sources"].append({
                    "name": "Spamhaus IP",
                    "status": f"IP listed ({', '.join(ip_lists)}) ancak whitelist nedeniyle ceza uygulanmadı"
                })
            else:
                if any(l in ip_lists for l in ("XBL", "eXBL")):
                    results["total_penalty"] += 30
                    results["sources"].append({
                        "name": "Spamhaus XBL/eXBL",
                        "status": f"IP listed ({', '.join(ip_lists)})"
                    })
                    results["findings"].append(
                        f"🛡️ Spamhaus XBL/eXBL: IP kara listede ({', '.join(ip_lists)})"
                    )
                elif ip_lists:
                    results["total_penalty"] += 20
                    results["sources"].append({
                        "name": "Spamhaus IP",
                        "status": f"IP listed ({', '.join(ip_lists)})"
                    })
                    results["findings"].append(
                        f"⚠️ Spamhaus: IP listed ({', '.join(ip_lists)})"
                    )
                # IOC kaydet
                write_ioc(
                    ioc_type="ip", ioc_value=resolved_ip,
                    threat_type="spamhaus_xbl", confidence=70,
                    source="spamhaus", raw_data=spamhaus_ip_result,
                )
        elif spamhaus_ip_result:
            results["spamhaus_ip"] = spamhaus_ip_result

        # ThreatFox skorlama
        if threatfox_result and threatfox_result.get("found"):
            results["threatfox"] = threatfox_result
            if is_whitelisted:
                results["sources"].append({
                    "name": "ThreatFox",
                    "status": "IOC bulundu ancak whitelist nedeniyle ceza uygulanmadı"
                })
            else:
                results["total_penalty"] += 25
                results["sources"].append({
                    "name": "ThreatFox",
                    "status": f"IOC bulundu ({threatfox_result.get('malware_family', 'unknown')})"
                })
                results["findings"].append(
                    f"🛡️ ThreatFox: IOC bulundu — {threatfox_result.get('malware_family', 'bilinmeyen')} "
                    f"(confidence: {threatfox_result.get('confidence', 0)})"
                )
                # IOC kaydet
                write_ioc(
                    ioc_type="domain", ioc_value=domain,
                    threat_type=threatfox_result.get("threat_name", "unknown"),
                    confidence=threatfox_result.get("confidence", 50),
                    source="threatfox", raw_data=threatfox_result,
                )
        elif threatfox_result:
            results["threatfox"] = threatfox_result

    except Exception as e:
        logger.error(f"Spamhaus/URLhaus/ThreatFox err: {e}")
        all_available = False

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
    vt = results.get("virustotal", {})
    if vt.get("available"):
        if vt.get("malicious", 0) > 0:
            details.append(f"🛡️ VirusTotal: {vt['malicious']}/{vt.get('total', 0)} motor tehlikeli")
        if vt.get("suspicious", 0) > 0:
            details.append(f"⚠️ VirusTotal: {vt['suspicious']} motor şüpheli")
    
    # Google Safe Browsing detayları
    gsb = results.get("google_safe_browsing", {})
    if gsb.get("available") and gsb.get("threat"):
        details.append(f"🔍 Google: {gsb.get('threat_type', 'Bilinmeyen tehdit')}")
    
    # AbuseIPDB detayları
    abuse = results.get("abuseipdb", {})
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
