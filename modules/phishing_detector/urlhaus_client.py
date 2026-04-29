"""
abuse.ch URLhaus API Client
=============================
URLhaus API ile URL sorgulama.
Endpoint: https://urlhaus-api.abuse.ch/v1/url/ (POST, form-data).
Auth: ABUSE_API_KEY header.
"""

import os
import hashlib
import logging
from typing import Dict, Optional

import requests
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")
logger = logging.getLogger(__name__)

ABUSE_CH_API_KEY = os.getenv("ABUSE_API_KEY", os.getenv("ABUSE_API_KEYS", "")).strip()
if "," in ABUSE_CH_API_KEY:
    ABUSE_CH_API_KEY = ABUSE_CH_API_KEY.split(",")[0].strip()
if len(ABUSE_CH_API_KEY) < 10:
    ABUSE_CH_API_KEY = ""  # Geçersiz/boş key — header gönderme

URLHAUS_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"


def query_url(url: str, timeout: int = 15) -> Dict:
    """
    URLhaus ile URL sorgulama.
    query_status, threat tipi, tags, ilk görülme tarihi döndürür.
    Listed ise blacklisted: true, risk_boost: 40 ekler.
    Not listed → clean dict, exception fırlatmaz.
    """
    url = (url or "").strip()
    if not url:
        return {"listed": False, "status": "Boş URL", "blacklisted": False}

    # Cache kontrolü
    from .cache_db import read_threat_cache, write_threat_cache
    url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]
    cache_key = f"urlhaus:url:{url_hash}"
    cached = read_threat_cache(cache_key)
    if cached:
        return cached

    result = {
        "url": url,
        "listed": False,
        "blacklisted": False,
        "risk_boost": 0,
        "query_status": "not listed",
        "threat_type": None,
        "tags": [],
        "first_seen": None,
        "urlhaus_link": None,
        "available": True,
        "status": "clean",
    }

    try:
        resp = requests.post(
            URLHAUS_ENDPOINT,
            data={"url": url},
            timeout=timeout,
        )

        if resp.status_code != 200:
            logger.warning(f"URLhaus HTTP {resp.status_code} for {url}")
            result["status"] = f"HTTP {resp.status_code}"
            return result

        data = resp.json()
        query_status = data.get("query_status", "not listed")
        result["query_status"] = query_status

        if query_status == "ok" or data.get("threat"):
            threat = data.get("threat", "")
            tags = data.get("tags", [])
            first_seen = data.get("firstseen", data.get("first_seen", None))
            urlhaus_link = data.get("urlhaus_link", "")

            result["listed"] = True
            result["blacklisted"] = True
            result["risk_boost"] = 40
            result["threat_type"] = threat
            result["tags"] = tags if isinstance(tags, list) else [tags]
            result["first_seen"] = first_seen
            result["urlhaus_link"] = urlhaus_link
            result["status"] = f"listed ({threat})"
            result["host"] = data.get("host", "")
            result["url_status"] = data.get("url_status", "")

            logger.info(f"URLhaus listed: {url} → {threat}")
        else:
            logger.debug(f"URLhaus clean: {url}")

    except requests.Timeout:
        logger.warning(f"URLhaus timeout: {url}")
        result["status"] = "timeout"
    except Exception as e:
        logger.error(f"URLhaus sorgu hatası: {e}")
        result["status"] = "error"

    # Cache'e yaz (24 saat TTL)
    try:
        write_threat_cache(cache_key, result, ttl_seconds=86400)
    except Exception:
        pass

    return result
