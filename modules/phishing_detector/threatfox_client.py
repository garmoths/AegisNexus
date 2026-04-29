"""
abuse.ch ThreatFox API Client
================================
ThreatFox API ile IOC sorgulama ve toplu ingest.
Endpoint: https://threatfox-api.abuse.ch/api/v1/ (POST, JSON).
Auth: ABUSE_API_KEY header.
"""

import os
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")
logger = logging.getLogger(__name__)

ABUSE_CH_API_KEY = os.getenv("ABUSE_API_KEY", os.getenv("ABUSE_API_KEYS", "")).strip()
if "," in ABUSE_CH_API_KEY:
    ABUSE_CH_API_KEY = ABUSE_CH_API_KEY.split(",")[0].strip()

THREATFOX_ENDPOINT = "https://threatfox-api.abuse.ch/api/v1/"


def query_ioc(value: str, ioc_type: str = "domain", timeout: int = 15) -> Dict:
    """
    ThreatFox IOC sorgulama.
    ioc_type: "url", "domain", "ip:port"
    Eşleşen tehdit adı, malware ailesi, confidence level, ilk/son görülme döndürür.
    Not found → clean dict, exception fırlatmaz.
    """
    value = (value or "").strip()
    if not value:
        return {"found": False, "status": "Boş IOC değeri"}

    # Cache kontrolü
    from .cache_db import read_threat_cache, write_threat_cache
    cache_key = f"threatfox:ioc:{value}"
    cached = read_threat_cache(cache_key)
    if cached:
        return cached

    result = {
        "found": False,
        "ioc_type": ioc_type,
        "ioc_value": value,
        "threat_name": None,
        "malware_family": None,
        "confidence": 0,
        "first_seen": None,
        "last_seen": None,
        "tags": [],
        "status": "not found",
        "available": True,
    }

    try:
        headers = {"Content-Type": "application/json"}
        if ABUSE_CH_API_KEY:
            headers["Auth-Key"] = ABUSE_CH_API_KEY

        payload = {
            "query": "search_ioc",
            "search_term": value,
        }

        resp = requests.post(
            THREATFOX_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=timeout,
        )

        if resp.status_code != 200:
            logger.warning(f"ThreatFox HTTP {resp.status_code} for {value}")
            result["status"] = f"HTTP {resp.status_code}"
            return result

        data = resp.json()
        query_status = data.get("query_status", "not found")

        if query_status == "ok" and data.get("data"):
            entries = data["data"]
            if isinstance(entries, list) and entries:
                entry = entries[0]
                result["found"] = True
                result["threat_name"] = entry.get("threat_type", entry.get("threat_type_desc", ""))
                result["malware_family"] = entry.get("malware", entry.get("malware_printable", ""))
                result["confidence"] = int(entry.get("confidence_level", 0) or 0)
                result["first_seen"] = entry.get("first_seen_utc", entry.get("first_seen", ""))
                result["last_seen"] = entry.get("last_seen_utc", entry.get("last_seen", ""))
                result["tags"] = entry.get("tags", []) or []
                result["ioc_type"] = entry.get("ioc_type", ioc_type)
                result["status"] = "found"
                result["source_url"] = entry.get("threatfox_link", "")

                logger.info(f"ThreatFox found: {value} → {result['malware_family']}")
        else:
            logger.debug(f"ThreatFox not found: {value}")

    except requests.Timeout:
        logger.warning(f"ThreatFox timeout: {value}")
        result["status"] = "timeout"
    except Exception as e:
        logger.error(f"ThreatFox sorgu hatası: {e}")
        result["status"] = "error"

    # Cache'e yaz (12 saat TTL)
    try:
        write_threat_cache(cache_key, result, ttl_seconds=43200)
    except Exception:
        pass

    return result


def get_recent_iocs(limit: int = 100, timeout: int = 30) -> List[Dict]:
    """
    Son IOC'ları çekip normalize eder.
    fetch_all_sources.py akışında PhishingURL tablosuna yazılmak üzere
    PhishTank-benzeri formata çevirir.
    """
    if not ABUSE_CH_API_KEY:
        logger.warning("ThreatFox ingest atlandı: ABUSE_API_KEY tanımlı değil")
        return []

    try:
        headers = {"Content-Type": "application/json"}
        if ABUSE_CH_API_KEY:
            headers["Auth-Key"] = ABUSE_CH_API_KEY

        payload = {
            "query": "get_iocs",
            "days": 7,
            "limit": min(limit, 500),
        }

        resp = requests.post(
            THREATFOX_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=timeout,
        )

        if resp.status_code != 200:
            logger.warning(f"ThreatFox ingest HTTP {resp.status_code}")
            return []

        data = resp.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            return []

        entries = data["data"]
        if not isinstance(entries, list):
            return []

        # url_normalize opsiyonel — yoksa basit normalize yap
        try:
            from .url_normalize import normalize_url_record
            _has_normalize = True
        except ImportError:
            _has_normalize = False

        results: List[Dict] = []
        for entry in entries[:limit]:
            ioc_type = str(entry.get("ioc_type", "")).lower()
            # ThreatFox API'de alan adı "ioc", eski versiyonlarda "ioc_value"
            ioc_value = str(entry.get("ioc", entry.get("ioc_value", ""))).strip()
            if not ioc_value:
                continue
            threat_type = str(entry.get("threat_type", "phishing")).lower()
            malware = str(entry.get("malware", "")).strip()
            malware_printable = str(entry.get("malware_printable", malware)).strip()
            confidence = int(entry.get("confidence_level", 0) or 0)
            first_seen = entry.get("first_seen_utc", entry.get("first_seen", ""))

            # URL ve domain tipi IOC'ları PhishingURL'ye yaz, IP'leri de ekle
            url = None
            if ioc_type == "url" and ioc_value.startswith(("http://", "https://")):
                url = ioc_value
            elif ioc_type in ("domain", "hostname"):
                url = f"http://{ioc_value}"
            elif ioc_type == "ip:port":
                url = f"http://{ioc_value}"
            else:
                continue

            if _has_normalize:
                normalized = normalize_url_record(url)
                if not normalized.get("url_hash"):
                    continue
                url_hash = normalized["url_hash"]
                canonical_url = normalized.get("canonical_url") or url
                domain_norm = normalized.get("domain_norm")
            else:
                # Basit normalize fallback
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain_norm = (parsed.netloc or parsed.hostname or "").lower().split(":")[0]
                url_hash = str(hash(url))
                canonical_url = url

            results.append({
                "phish_id": f"threatfox_{abs(hash(ioc_value)) % 1000000000}",
                "url": canonical_url,
                "url_hash": url_hash,
                "domain_norm": domain_norm,
                "status": "valid",
                "online": True,
                "target": malware_printable or malware or "Unknown",
                "submission_time": first_seen or datetime.now(timezone.utc).isoformat(),
                "source": "threatfox",
                "ioc_type": ioc_type,
                "threat_type": threat_type,
                "confidence": confidence,
                "malware_family": malware_printable or malware,
            })

        logger.info(f"ThreatFox ingest: {len(results)} IOC normalize edildi")
        return results

    except Exception as e:
        logger.error(f"ThreatFox ingest hatası: {e}")
        return []
