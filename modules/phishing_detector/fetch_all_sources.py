"""
Multi-source phishing ingestion pipeline.
Collects phishing URLs from configured feeds and stores them in PhishingURL.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import time
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from sqlalchemy.orm import Session
from urllib3.util.retry import Retry

from app.models import PhishingURL
from .url_normalize import normalize_url_record

DEFAULT_GITHUB_FEEDS = {
    "github_spam404": "https://raw.githubusercontent.com/Spam404/lists/master/main-blacklist.txt",
    "github_phishing_new_today": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-NEW-today.txt",
    "github_phishingdb_new_today": "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt",
}

DEFAULT_CERTSTREAM_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "payment",
    "wallet",
    "signin",
    "support",
    "bank",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
]


def _http_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_github_feed_urls() -> Dict[str, str]:
    """GitHub feed URL'lerini env'den veya varsayilandan alir."""
    raw = os.getenv("PHISHING_GITHUB_FEEDS", "").strip()
    if not raw:
        return DEFAULT_GITHUB_FEEDS

    feeds: Dict[str, str] = {}
    for idx, item in enumerate(raw.split(","), start=1):
        url = item.strip()
        if not url:
            continue
        feeds[f"github_custom_{idx}"] = url
    return feeds or DEFAULT_GITHUB_FEEDS


def _line_to_candidate_url(raw_line: str) -> Optional[str]:
    line = (raw_line or "").strip().strip('"').strip("'")
    if not line or line.startswith("#"):
        return None

    if "," in line:
        line = line.split(",", 1)[0].strip()
    if " " in line:
        line = line.split(" ", 1)[0].strip()
    if not line:
        return None

    if line.startswith(("http://", "https://", "ftp://")):
        return line
    if line.startswith("www."):
        return f"http://{line}"
    if "." in line and "/" in line:
        return f"http://{line}"
    if re.fullmatch(r"[A-Za-z0-9.-]+\.[A-Za-z]{2,}", line):
        return f"http://{line}"
    return None


def parse_feed_lines_to_urls(content: str) -> List[str]:
    """Duz metin feed satirlarini URL listesine cevirir."""
    urls: Set[str] = set()
    for line in (content or "").splitlines():
        candidate = _line_to_candidate_url(line)
        if candidate:
            urls.add(candidate)
    return list(urls)


def fetch_openphish_data(session: Optional[requests.Session] = None) -> List[str]:
    """OpenPhish canlı feed."""
    http = session or _http_session()
    limit = int(os.getenv("PHISHING_OPENPHISH_LIMIT", "20000"))
    try:
        response = http.get("https://openphish.com/feed.txt", timeout=60)
        if response.status_code != 200:
            print(f"OpenPhish status: {response.status_code}")
            return []
        urls = parse_feed_lines_to_urls(response.text)
        return urls[: max(limit, 1)]
    except Exception as exc:
        print(f"OpenPhish hatasi: {exc}")
        return []


def fetch_urlhaus_data(session: Optional[requests.Session] = None) -> List[str]:
    """URLHaus CSV recent dump'tan phishing odaklı URL'ler."""
    http = session or _http_session()
    limit = int(os.getenv("PHISHING_URLHAUS_LIMIT", "3000"))
    phishing_only = os.getenv("PHISHING_URLHAUS_PHISHING_ONLY", "0").strip().lower() in {"1", "true", "yes"}
    try:
        response = http.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=90)
        if response.status_code != 200:
            print(f"URLHaus status: {response.status_code}")
            return []

        reader = csv.reader(io.StringIO(response.text))
        urls: List[str] = []
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            # Columns: id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
            url = row[2].strip() if len(row) > 2 else ""
            threat = row[5].strip().lower() if len(row) > 5 else ""
            tags = row[6].strip().lower() if len(row) > 6 else ""
            if not url.startswith(("http://", "https://")):
                continue
            if (not phishing_only) or ("phish" in threat or any("phish" in tag for tag in tags)):
                urls.append(url)
            if len(urls) >= limit:
                break
        return list(dict.fromkeys(urls))[: max(limit, 1)]
    except Exception as exc:
        print(f"URLHaus hatasi: {exc}")
        return []


def _extract_urls_from_kaggle_zip(zip_blob: bytes) -> List[str]:
    """Kaggle dataset zip içindeki URL adaylarını çıkarır."""
    urls: Set[str] = set()
    url_columns = {"url", "urls", "phishing_url", "link", "domain", "site", "website"}

    with zipfile.ZipFile(io.BytesIO(zip_blob)) as zf:
        for member in zf.namelist():
            lower_name = member.lower()
            if not lower_name.endswith((".csv", ".txt")):
                continue

            raw = zf.read(member)
            text = raw.decode("utf-8", errors="ignore")

            if lower_name.endswith(".csv"):
                reader = csv.DictReader(io.StringIO(text))
                if reader.fieldnames:
                    fields = {f.lower(): f for f in reader.fieldnames if f}
                    match_field = next((fields[c] for c in url_columns if c in fields), None)
                    if match_field:
                        for row in reader:
                            candidate = _line_to_candidate_url(str(row.get(match_field, "")))
                            if candidate:
                                urls.add(candidate)
                        continue

            for candidate in parse_feed_lines_to_urls(text):
                urls.add(candidate)

    return list(urls)


def fetch_kaggle_data(session: Optional[requests.Session] = None) -> List[str]:
    """
    Kaggle phishing dataset fetch.
    Supports either:
    - KAGGLE_API_TOKEN (new token style), or
    - KAGGLE_USERNAME + KAGGLE_KEY (legacy style).
    """
    username = os.getenv("KAGGLE_USERNAME", "").strip()
    key = os.getenv("KAGGLE_KEY", "").strip()
    api_token = os.getenv("KAGGLE_API_TOKEN", "").strip()
    dataset_ref = os.getenv("PHISHING_KAGGLE_DATASET", "taruntiwarihp/phishing-site-urls").strip()
    limit = int(os.getenv("PHISHING_KAGGLE_LIMIT", "100000"))

    if not api_token and (not username or not key):
        print("Kaggle atlandi: KAGGLE_API_TOKEN veya KAGGLE_USERNAME/KAGGLE_KEY tanimli degil")
        return []

    if "/" not in dataset_ref:
        print("Kaggle atlandi: PHISHING_KAGGLE_DATASET formati owner/dataset olmali")
        return []

    http = session or _http_session()
    endpoint = f"https://www.kaggle.com/api/v1/datasets/download/{dataset_ref}"

    try:
        headers: Dict[str, str] = {}
        auth = None
        if api_token:
            headers["Authorization"] = f"Bearer {api_token}"
        else:
            auth = (username, key)

        response = http.get(endpoint, headers=headers, auth=auth, timeout=180)
        if response.status_code != 200:
            print(f"Kaggle status: {response.status_code}")
            return []
        urls = _extract_urls_from_kaggle_zip(response.content)
        return urls[: max(limit, 1)]
    except Exception as exc:
        print(f"Kaggle hatasi: {exc}")
        return []


def fetch_otx_phishing_data(session: Optional[requests.Session] = None) -> List[str]:
    """AlienVault OTX subscribed pulses üzerinden phishing URL/domain toplar."""
    api_key = os.getenv("ALIENVAULT_OTX_API_KEY", "").strip()
    if not api_key:
        print("OTX atlandi: ALIENVAULT_OTX_API_KEY tanimli degil")
        return []

    limit = int(os.getenv("PHISHING_OTX_LIMIT", "200"))
    endpoint = f"https://otx.alienvault.com/api/v1/pulses/subscribed?limit={max(limit, 1)}"
    headers = {"X-OTX-API-KEY": api_key}
    http = session or _http_session()

    try:
        response = http.get(endpoint, headers=headers, timeout=60)
        if response.status_code != 200:
            print(f"OTX status: {response.status_code}")
            return []

        payload = response.json()
        urls: Set[str] = set()
        for pulse in payload.get("results", []):
            tags = [str(t).lower() for t in pulse.get("tags", [])]
            pulse_blob = " ".join(
                [
                    str(pulse.get("name", "")).lower(),
                    str(pulse.get("description", "")).lower(),
                    " ".join(tags),
                ]
            )
            phishing_hint = any(k in pulse_blob for k in ("phish", "credential", "login", "fraud"))

            for indicator in pulse.get("indicators", []):
                indicator_type = str(indicator.get("type", "")).lower()
                value = str(indicator.get("indicator", "")).strip()
                if not value:
                    continue

                if indicator_type == "url" and value.startswith(("http://", "https://")):
                    urls.add(value)
                elif indicator_type in {"domain", "hostname"} and phishing_hint:
                    urls.add(f"http://{value}")

        return list(urls)
    except Exception as exc:
        print(f"OTX hatasi: {exc}")
        return []


def _is_suspicious_certstream_domain(domain: str, keywords: Iterable[str]) -> bool:
    value = domain.lower()
    if any(keyword in value for keyword in keywords):
        return True
    if value.startswith("xn--"):
        return True
    if value.count("-") >= 3:
        return True
    if len(value) > 55:
        return True
    return False


def fetch_certstream_data(session: Optional[requests.Session] = None) -> List[str]:
    """
    CertStream websocket üzerinden kısa süreli şüpheli domain toplar.
    websocket-client paketi yoksa kaynak atlanır.
    """
    del session  # kept for uniform collector signature
    try:
        import websocket  # type: ignore
    except ImportError:
        print("CertStream atlandi: websocket-client paketi kurulu degil")
        return []

    ws_url = os.getenv("CERTSTREAM_WS_URL", "wss://certstream.calidog.io/")
    max_urls = int(os.getenv("CERTSTREAM_MAX_URLS", "500"))
    duration = int(os.getenv("CERTSTREAM_DURATION_SECONDS", "20"))
    custom_keywords = os.getenv("CERTSTREAM_KEYWORDS", "").strip()
    keywords = (
        [k.strip().lower() for k in custom_keywords.split(",") if k.strip()]
        if custom_keywords
        else DEFAULT_CERTSTREAM_KEYWORDS
    )

    found: Set[str] = set()
    observed_domains: Set[str] = set()
    start = time.time()
    ws = None
    try:
        ws = websocket.create_connection(ws_url, timeout=10)
        while (time.time() - start) < duration and len(found) < max_urls:
            raw = ws.recv()
            if not raw:
                continue

            message = json.loads(raw)
            if message.get("message_type") != "certificate_update":
                continue

            domains = message.get("data", {}).get("leaf_cert", {}).get("all_domains", []) or []
            for domain in domains:
                normalized = str(domain).lstrip("*.").strip().lower()
                if not normalized or "." not in normalized:
                    continue
                observed_domains.add(normalized)
                if _is_suspicious_certstream_domain(normalized, keywords):
                    found.add(f"http://{normalized}")
                if len(found) >= max_urls:
                    break
    except Exception as exc:
        print(f"CertStream hatasi: {exc}")
    finally:
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    if found:
        return list(found)

    allow_generic = os.getenv("CERTSTREAM_ALLOW_GENERIC_DOMAINS", "1").strip().lower() in {"1", "true", "yes"}
    if allow_generic and observed_domains:
        fallback = [f"http://{domain}" for domain in sorted(observed_domains)[:max_urls]]
        return fallback

    return []


def extract_target_from_url(url: str) -> str:
    """URL'den hedef marka tahmini."""
    try:
        domain = urlparse(url).netloc.lower()
        brands = {
            "facebook": "Facebook",
            "instagram": "Instagram",
            "twitter": "Twitter",
            "x.com": "X",
            "google": "Google",
            "gmail": "Gmail",
            "microsoft": "Microsoft",
            "outlook": "Microsoft",
            "office365": "Microsoft",
            "apple": "Apple",
            "icloud": "Apple",
            "amazon": "Amazon",
            "netflix": "Netflix",
            "paypal": "PayPal",
            "chase": "Chase Bank",
            "wellsfargo": "Wells Fargo",
            "bankofamerica": "Bank of America",
            "citi": "Citibank",
            "amex": "American Express",
            "linkedin": "LinkedIn",
            "github": "GitHub",
            "dropbox": "Dropbox",
            "adobe": "Adobe",
            "steam": "Steam",
            "epicgames": "Epic Games",
            "roblox": "Roblox",
            "tiktok": "TikTok",
            "whatsapp": "WhatsApp",
            "telegram": "Telegram",
            "discord": "Discord",
            "spotify": "Spotify",
            "ebay": "eBay",
            "binance": "Binance",
            "coinbase": "Coinbase",
        }
        for key, brand in brands.items():
            if key in domain:
                return brand
        return "Unknown"
    except Exception:
        return "Unknown"


def convert_to_phishtank_format(urls: List[str], source: str) -> List[Dict[str, Any]]:
    """URL listesini PhishTank-benzeri kayıt formatına çevirir."""
    now = datetime.now(timezone.utc).isoformat()
    entries: List[Dict[str, Any]] = []
    for url in urls:
        entries.append(
            {
                "phish_id": f"{source}_{abs(hash(url)) % 1000000000}",
                "url": url,
                "phish_detail_url": url,
                "status": "valid",
                "online": True,
                "target": extract_target_from_url(url),
                "submission_time": now,
                "source": source,
            }
        )
    return entries


def deduplicate_urls(urls: List[str], seen_hashes: Optional[Set[str]] = None) -> List[str]:
    """URL'leri normalize ederek hash bazlı tekilleştirir."""
    unique_urls: List[str] = []
    local_hashes: Set[str] = set()

    for raw_url in urls:
        normalized = normalize_url_record(raw_url)
        url_hash = normalized.get("url_hash")
        if not url_hash:
            continue
        if url_hash in local_hashes:
            continue
        if seen_hashes is not None and url_hash in seen_hashes:
            continue

        local_hashes.add(url_hash)
        if seen_hashes is not None:
            seen_hashes.add(url_hash)
        unique_urls.append(normalized.get("canonical_url") or raw_url)

    return unique_urls


def import_to_database(db: Session, entries: List[Dict[str, Any]], batch_size: int = 1000) -> Dict[str, int]:
    """Entry'leri veritabanina aktar."""
    added = 0
    updated = 0
    errors = 0

    for i, entry in enumerate(entries):
        try:
            phish_id = str(entry.get("phish_id", ""))
            if not phish_id:
                continue

            url = entry.get("url", "")
            normalized = normalize_url_record(url)
            url_hash = normalized.get("url_hash")
            if not url_hash:
                errors += 1
                continue

            existing_by_hash = db.query(PhishingURL).filter(PhishingURL.url_hash == url_hash).first()
            if existing_by_hash:
                existing_by_hash.url = normalized.get("canonical_url") or url
                existing_by_hash.domain_norm = normalized.get("domain_norm")
                existing_by_hash.status = entry.get("status", "unknown")
                existing_by_hash.online = entry.get("online", False)
                existing_by_hash.target = entry.get("target", "Unknown")
                updated += 1
            else:
                existing_by_id = db.query(PhishingURL).filter(PhishingURL.phish_id == phish_id).first()
                if existing_by_id:
                    existing_by_id.url = normalized.get("canonical_url") or url
                    existing_by_id.url_hash = url_hash
                    existing_by_id.domain_norm = normalized.get("domain_norm")
                    existing_by_id.status = entry.get("status", "unknown")
                    existing_by_id.online = entry.get("online", False)
                    existing_by_id.target = entry.get("target", "Unknown")
                    updated += 1
                    continue

                db.add(
                    PhishingURL(
                        phish_id=phish_id,
                        url=normalized.get("canonical_url") or url,
                        url_hash=url_hash,
                        domain_norm=normalized.get("domain_norm"),
                        status=entry.get("status", "unknown"),
                        online=entry.get("online", False),
                        target=entry.get("target", "Unknown"),
                        submission_time=datetime.now(timezone.utc),
                    )
                )
                added += 1

            if (i + 1) % batch_size == 0:
                db.commit()
        except Exception as exc:
            errors += 1
            if errors <= 5:
                print(f"Kayit hatasi: {exc}")

    db.commit()
    return {"total": len(entries), "added": added, "updated": updated, "errors": errors}


def fetch_and_import_github_feed(
    db: Session,
    feed_url: str,
    source_name: str,
    global_seen_hashes: Set[str],
    session: Optional[requests.Session] = None,
) -> Dict[str, Any]:
    """GitHub feed'ini çekip DB'ye batch import eder."""
    result: Dict[str, Any] = {"total": 0, "added": 0, "updated": 0, "errors": 0}
    http = session or _http_session()

    try:
        response = http.get(feed_url, timeout=120)
        if response.status_code != 200:
            result["error"] = f"HTTP {response.status_code}"
            return result

        urls = parse_feed_lines_to_urls(response.text)
        deduped_urls = deduplicate_urls(urls, global_seen_hashes)
        if not deduped_urls:
            result["error"] = "No parsable URLs"
            return result

        entries = convert_to_phishtank_format(deduped_urls, source_name)
        imported = import_to_database(db, entries)
        result.update(imported)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def _collect_and_import_source(
    db: Session,
    source_name: str,
    collector: Callable[..., List[str]],
    global_seen_hashes: Set[str],
    session: requests.Session,
) -> Dict[str, Any]:
    result: Dict[str, Any] = {"total": 0, "added": 0, "updated": 0, "errors": 0}
    try:
        raw_urls = collector(session=session)
        deduped_urls = deduplicate_urls(raw_urls, global_seen_hashes)
        if not deduped_urls:
            result["error"] = "No URLs collected"
            return result

        entries = convert_to_phishtank_format(deduped_urls, source_name)
        imported = import_to_database(db, entries)
        result.update(imported)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        return result


def fetch_threatfox_data(session: Optional[requests.Session] = None) -> List[str]:
    """ThreatFox API üzerinden son IOC'ları çeker ve URL listesine çevirir."""
    try:
        from .threatfox_client import get_recent_iocs
        limit = int(os.getenv("PHISHING_THREATFOX_LIMIT", "500"))
        iocs = get_recent_iocs(limit=limit)
        urls: List[str] = []
        for ioc in iocs:
            url = ioc.get("url", "")
            if url and url.startswith(("http://", "https://")):
                urls.append(url)
        return urls
    except Exception as exc:
        print(f"ThreatFox hatasi: {exc}")
        return []


def fetch_all_sources(db: Session) -> Dict[str, Any]:
    """Tum kaynaklardan phishing verilerini ceker."""
    from .alerts import get_alert_manager

    global_seen_hashes: Set[str] = set()
    all_results: Dict[str, Dict[str, Any]] = {}
    total_added = 0
    total_updated = 0
    session = _http_session()

    print("\n" + "=" * 60)
    print("🚀 PHISHING DATA AGGREGATOR (MULTI-SOURCE)")
    print("=" * 60)

    # 1) GitHub feeds
    print("\n📡 GitHub feed'leri")
    for source_name, feed_url in get_github_feed_urls().items():
        print(f"   ↳ {source_name}: {feed_url}")
        result = fetch_and_import_github_feed(
            db=db,
            feed_url=feed_url,
            source_name=source_name,
            global_seen_hashes=global_seen_hashes,
            session=session,
        )
        all_results[source_name] = result
        total_added += result.get("added", 0)
        total_updated += result.get("updated", 0)

        if result.get("total", 0) > 0:
            print(f"   ✅ {source_name}: {result['total']} URL, {result['added']} eklendi")
        else:
            print(f"   ⚠️  {source_name}: {result.get('error', 'veri alinamadi')}")

    # 2) Additional direct collectors
    collector_sources: List[tuple[str, Callable[..., List[str]]]] = [
        ("openphish", fetch_openphish_data),
        ("urlhaus", fetch_urlhaus_data),
        ("kaggle_phishing_site_urls", fetch_kaggle_data),
        ("certstream", fetch_certstream_data),
        ("alienvault_otx", fetch_otx_phishing_data),
        ("threatfox", fetch_threatfox_data),
    ]

    print("\n🌐 Diger kaynaklar")
    for source_name, collector in collector_sources:
        print(f"   ↳ {source_name}")
        result = _collect_and_import_source(
            db=db,
            source_name=source_name,
            collector=collector,
            global_seen_hashes=global_seen_hashes,
            session=session,
        )
        all_results[source_name] = result
        total_added += result.get("added", 0)
        total_updated += result.get("updated", 0)

        if result.get("total", 0) > 0:
            print(f"   ✅ {source_name}: {result['total']} URL, {result['added']} eklendi")
        else:
            print(f"   ⚠️  {source_name}: {result.get('error', 'veri alinamadi')}")

    # Optional alerting
    try:
        if total_added > 0:
            alert_mgr = get_alert_manager()
            alert_mgr.send_slack_alert(
                title="New Phishing URLs Detected",
                message=f"Multi-source run completed\nNew: {total_added}\nUpdated: {total_updated}",
                risk_level="🚨",
            )
    except Exception as exc:
        print(f"Slack alert atlandi: {exc}")

    active_sources = len([name for name, data in all_results.items() if data.get("total", 0) > 0])
    print("\n" + "=" * 60)
    print("📊 ÖZET")
    print("=" * 60)
    print(f"   Toplam yeni eklenen: {total_added}")
    print(f"   Toplam güncellenen: {total_updated}")
    print(f"   Aktif kaynak: {active_sources}")

    return {
        "status": "success",
        "sources": all_results,
        "total_added": total_added,
        "total_updated": total_updated,
        "active_sources": active_sources,
    }


if __name__ == "__main__":
    from shared.utils.db import SessionLocal

    db = SessionLocal()
    try:
        print(fetch_all_sources(db))
    finally:
        db.close()
