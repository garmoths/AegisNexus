"""
Spamhaus Intelligence API Client
==================================
Spamhaus DQS/Intel API ile IP ve domain itibar sorgulama.
Auth: Login-based token (POST /api/v1/login → Bearer token).
"""

import os
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Dict, Optional

import requests
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")
logger = logging.getLogger(__name__)

SPAMHAUS_USERNAME = os.getenv("SPAMHAUS_USERNAME", "")
SPAMHAUS_PASSWORD = os.getenv("SPAMHAUS_PASSWORD", "")

LOGIN_URL = "https://api.spamhaus.org/api/v1/login"
API_BASE = "https://api.spamhaus.org/api/intel/v1"

# In-memory token cache
_token_cache: Optional[Dict] = None


def _is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _get_auth_token(timeout: int = 10) -> Optional[str]:
    """Login endpoint'inden Bearer token al. Cache'le, süresi dolunca yenile."""
    global _token_cache

    if _token_cache:
        expires_at = _token_cache.get("expires_at")
        if expires_at and datetime.now() < expires_at:
            return _token_cache["token"]

    if not SPAMHAUS_USERNAME or not SPAMHAUS_PASSWORD:
        logger.warning("SPAMHAUS_USERNAME/PASSWORD tanımlı değil")
        return None

    try:
        resp = requests.post(
            LOGIN_URL,
            json={
                "username": SPAMHAUS_USERNAME,
                "password": SPAMHAUS_PASSWORD,
                "realm": "intel",
            },
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            token = data.get("token") or data.get("access_token")
            if token:
                # Token TTL: 1 saat varsayılan (API dokümanına göre)
                ttl = int(data.get("expires_in", 3600))
                _token_cache = {
                    "token": token,
                    "expires_at": datetime.now() + timedelta(seconds=ttl - 60),
                }
                logger.info("Spamhaus auth token alındı")
                return token
        logger.warning(f"Spamhaus login başarısız: HTTP {resp.status_code}")
    except Exception as e:
        logger.error(f"Spamhaus login hatası: {e}")

    return None


def _api_headers() -> Dict[str, str]:
    token = _get_auth_token()
    if token:
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    return {}


def _clean_result() -> Dict:
    """Not listed / clean sonucu."""
    return {
        "listed": False,
        "status": "clean",
        "lists": [],
        "reputation": None,
        "botnet": None,
        "c2": None,
        "zrd": None,
    }


def query_ip(ip: str, timeout: int = 10) -> Dict:
    """
    Spamhaus IP sorgulama.
    SBL/XBL/eXBL/CBL liste durumu, reputation skoru, botnet adı, C2 bilgisi döndürür.
    404/not listed → clean dict, exception fırlatmaz.
    """
    if not _is_valid_ip(ip):
        return {**_clean_result(), "ip": ip, "error": "Geçersiz IP"}

    headers = _api_headers()
    if not headers:
        return {**_clean_result(), "ip": ip, "available": False, "status": "API key tanımlı değil"}

    # Cache kontrolü
    from .cache_db import read_threat_cache, write_threat_cache
    cache_key = f"spamhaus:ip:{ip}"
    cached = read_threat_cache(cache_key)
    if cached:
        return cached

    result = {**_clean_result(), "ip": ip}

    try:
        # XBL sorgulama
        resp = requests.get(
            f"{API_BASE}/byobject/cidr/XBL/listed/live/{ip}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                result["listed"] = True
                result["lists"].append("XBL")
                result["reputation"] = data.get("rep", data.get("reputation"))
                result["botnet"] = data.get("botnet", data.get("botnet_name"))
                result["c2"] = data.get("c2", data.get("control"))
        # 404 = not listed, exception yok

        # SBL sorgulama
        resp = requests.get(
            f"{API_BASE}/byobject/cidr/SBL/listed/live/{ip}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                result["listed"] = True
                result["lists"].append("SBL")

        # eXBL sorgulama
        resp = requests.get(
            f"{API_BASE}/byobject/cidr/eXBL/listed/live/{ip}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                result["listed"] = True
                result["lists"].append("eXBL")

        # CBL sorgulama
        resp = requests.get(
            f"{API_BASE}/byobject/cidr/CBL/listed/live/{ip}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                result["listed"] = True
                result["lists"].append("CBL")
                if not result["botnet"]:
                    result["botnet"] = data.get("botnet", data.get("botnet_name"))

        if result["listed"]:
            result["status"] = "listed"
            logger.info(f"Spamhaus IP listed: {ip} → {result['lists']}")
        else:
            logger.debug(f"Spamhaus IP clean: {ip}")

        result["available"] = True

    except requests.Timeout:
        logger.warning(f"Spamhaus IP timeout: {ip}")
        result["available"] = True
        result["status"] = "timeout"
    except Exception as e:
        logger.error(f"Spamhaus IP sorgu hatası: {e}")
        result["available"] = True
        result["status"] = "error"

    # Cache'e yaz (6 saat TTL)
    try:
        write_threat_cache(cache_key, result, ttl_seconds=21600)
    except Exception:
        pass

    return result


def query_domain(domain: str, timeout: int = 10) -> Dict:
    """
    Spamhaus domain sorgulama.
    DBL liste durumu, ZRD kontrolü, reputation skoru döndürür.
    404/not listed → clean dict, exception fırlatmaz.
    """
    domain = (domain or "").strip().lower().replace("www.", "")
    if not domain:
        return {**_clean_result(), "domain": domain, "error": "Boş domain"}

    headers = _api_headers()
    if not headers:
        return {**_clean_result(), "domain": domain, "available": False, "status": "API key tanımlı değil"}

    # Cache kontrolü
    from .cache_db import read_threat_cache, write_threat_cache
    cache_key = f"spamhaus:domain:{domain}"
    cached = read_threat_cache(cache_key)
    if cached:
        return cached

    result = {**_clean_result(), "domain": domain}

    try:
        # DBL sorgulama
        resp = requests.get(
            f"{API_BASE}/byobject/domain/DBL/listed/live/{domain}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                result["listed"] = True
                result["lists"].append("DBL")
                result["reputation"] = data.get("rep", data.get("reputation"))
                dbl_class = data.get("class", data.get("dbl_class", ""))
                result["dbl_class"] = dbl_class

        # ZRD (Zero Reputation Domain) sorgulama
        resp = requests.get(
            f"{API_BASE}/byobject/domain/ZRD/listed/live/{domain}",
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if data:
                result["zrd"] = True
                result["listed"] = True
                result["lists"].append("ZRD")
                result["reputation"] = 0  # ZRD = sıfır itibar

        if result["listed"]:
            result["status"] = "listed"
            logger.info(f"Spamhaus domain listed: {domain} → {result['lists']}")
        else:
            logger.debug(f"Spamhaus domain clean: {domain}")

        result["available"] = True

    except requests.Timeout:
        logger.warning(f"Spamhaus domain timeout: {domain}")
        result["available"] = True
        result["status"] = "timeout"
    except Exception as e:
        logger.error(f"Spamhaus domain sorgu hatası: {e}")
        result["available"] = True
        result["status"] = "error"

    # Cache'e yaz (6 saat TTL)
    try:
        write_threat_cache(cache_key, result, ttl_seconds=21600)
    except Exception:
        pass

    return result
