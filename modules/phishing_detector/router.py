"""
01 - Phishing Detector Module Router
Tehdit veritabanı, URL tarama ve analiz endpointleri
"""
import uuid
import logging
import hmac
import os
import requests
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any
from urllib.parse import urlparse
import re

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import case, event, func, or_
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
try:
    import redis
except ImportError:  # pragma: no cover - optional runtime dependency
    redis = None

from shared.utils.db import get_db
from app.models import IndicatorOfCompromise, PhishingURL, WhitelistDomain, PhishingForm, URLAnalizHistory
from app.security import require_admin_api_key
from .scanner import calculate_safety_score
from .url_normalize import normalize_url_record
from .fetch_all_sources import fetch_all_sources
from .cache_db import (
    get_cached_scan_result,
    get_phishing_history,
    get_latest_phishing,
    get_threat_type_distribution,
    get_phishing_stats,
    get_scan_history,
    write_phishing_url,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["01-phishing-detector"])
whitelist_router = APIRouter(tags=["01-whitelist"])

# Rate limiting depolama (in-memory)
RATE_LIMIT_STORAGE = {}
EXPORT_DOMAINS_CACHE_KEY = "phishing:export-domains:30d:v1"
EXPORT_DOMAINS_CACHE_TTL_SECONDS = 3600
EXPORT_DOMAINS_BATCH_SIZE = 2000
WHITELIST_GLOBAL_CACHE_KEY = "whitelist:global:v1"
WHITELIST_GLOBAL_CACHE_TTL_SECONDS = 3600
WHITELIST_EXPORT_BATCH_SIZE = 2000
REPORT_RATE_LIMIT_PER_MINUTE = 10
REPORT_RATE_LIMIT_WINDOW_SECONDS = 60
VERIFY_RATE_LIMIT_PER_HOUR = 2
VERIFY_RATE_LIMIT_WINDOW_SECONDS = 3600
REPORT_FORM_RATE_LIMIT_PER_MINUTE = 20
REPORT_FORM_RATE_LIMIT_WINDOW_SECONDS = 60
MAX_VERIFY_DOMAINS = 500
VALID_REPORT_REASONS = {"phishing", "malware", "scam", "spam", "other"}
REDIS_ERRORS = (redis.RedisError,) if redis else ()
REPORT_SCHEMA_READY = False
WHITELIST_SCHEMA_READY = False
WHITELIST_EVENTS_READY = False
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
DNS_CLOUDFLARE_DOH_URL = (os.getenv("DNS_CLOUDFLARE_DOH_URL") or "https://cloudflare-dns.com/dns-query").strip()
DNS_QUAD9_DOH_URL = (os.getenv("DNS_QUAD9_DOH_URL") or "https://dns.quad9.net/dns-query").strip()


def _get_redis_client() -> Any | None:
    if redis is None:
        return None
    redis_url = (os.getenv("REDIS_URL") or "").strip()
    if not redis_url:
        return None
    return redis.Redis.from_url(redis_url, decode_responses=True)


def _validate_optional_export_key(x_aegisnexus_key: str | None) -> None:
    if x_aegisnexus_key is None:
        return
    expected = (os.getenv("AEGISNEXUS_EXPORT_KEY") or os.getenv("ADMIN_API_KEY") or "").strip()
    if not expected or not hmac.compare_digest(x_aegisnexus_key, expected):
        raise HTTPException(status_code=401, detail="Invalid AegisNexus key")


def _detect_timestamp_column(db: Session) -> str:
    inspector = inspect(db.bind)
    columns = {col["name"] for col in inspector.get_columns(PhishingURL.__tablename__)}
    if "created_at" in columns:
        return "created_at"
    return "submission_time"


def _ensure_timestamp_index(db: Session, timestamp_column: str) -> None:
    idx_name = f"ix_phishing_urls_{timestamp_column}"
    ddl = text(
        f"CREATE INDEX IF NOT EXISTS {idx_name} ON {PhishingURL.__tablename__} ({timestamp_column})"
    )
    db.execute(ddl)
    db.commit()


def _stream_cached_domains(payload: str):
    for line in payload.splitlines():
        if line:
            yield f"{line}\n"


def _stream_domains_from_db(
    db: Session,
    timestamp_column: str,
    cutoff_ts: datetime,
    redis_client: Any | None,
):
    temp_cache_key = f"{EXPORT_DOMAINS_CACHE_KEY}:building"
    wrote_any = False
    cache_enabled = redis_client is not None
    cache_buffer: list[str] = []

    if cache_enabled:
        try:
            redis_client.delete(temp_cache_key)
        except REDIS_ERRORS:
            cache_enabled = False

    try:
        ts_column = getattr(PhishingURL, timestamp_column)
        query = (
            db.query(PhishingURL.domain_norm)
            .filter(
                ts_column >= cutoff_ts,
                PhishingURL.domain_norm.isnot(None),
                PhishingURL.domain_norm != "",
            )
            .distinct()
            .order_by(PhishingURL.domain_norm.asc())
            .yield_per(EXPORT_DOMAINS_BATCH_SIZE)
        )

        for (domain,) in query:
            line = f"{domain}\n"
            wrote_any = True
            yield line
            if cache_enabled:
                cache_buffer.append(line)
                if len(cache_buffer) >= EXPORT_DOMAINS_BATCH_SIZE:
                    try:
                        redis_client.append(temp_cache_key, "".join(cache_buffer))
                    except REDIS_ERRORS as exc:
                        logger.warning("Domain export cache write failed: %s", exc)
                        cache_enabled = False
                    finally:
                        cache_buffer.clear()

        if cache_enabled and cache_buffer:
            try:
                redis_client.append(temp_cache_key, "".join(cache_buffer))
            except REDIS_ERRORS as exc:
                logger.warning("Domain export cache write failed: %s", exc)
                cache_enabled = False

        if cache_enabled and wrote_any:
            redis_client.rename(temp_cache_key, EXPORT_DOMAINS_CACHE_KEY)
            redis_client.expire(EXPORT_DOMAINS_CACHE_KEY, EXPORT_DOMAINS_CACHE_TTL_SECONDS)
        elif cache_enabled:
            redis_client.delete(temp_cache_key)
    except SQLAlchemyError as exc:
        logger.error("Domain export query failed: %s", exc)
        if cache_enabled:
            try:
                redis_client.delete(temp_cache_key)
            except REDIS_ERRORS:
                pass
        raise HTTPException(status_code=500, detail="Could not export domains")
    except REDIS_ERRORS as exc:
        logger.warning("Domain export cache write failed: %s", exc)
        if cache_enabled:
            try:
                redis_client.delete(temp_cache_key)
            except REDIS_ERRORS:
                pass


def _ensure_whitelist_schema(db: Session) -> None:
    global WHITELIST_SCHEMA_READY
    if WHITELIST_SCHEMA_READY:
        return

    ddl_statements = [
        f"ALTER TABLE {WhitelistDomain.__tablename__} ADD COLUMN IF NOT EXISTS added_by VARCHAR(50)",
        f"ALTER TABLE {WhitelistDomain.__tablename__} ADD COLUMN IF NOT EXISTS is_active BOOLEAN DEFAULT TRUE",
        f"ALTER TABLE {WhitelistDomain.__tablename__} ADD COLUMN IF NOT EXISTS is_safe BOOLEAN DEFAULT TRUE",
        f"ALTER TABLE {WhitelistDomain.__tablename__} ADD COLUMN IF NOT EXISTS last_scanned_at TIMESTAMP",
        f"ALTER TABLE {WhitelistDomain.__tablename__} ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()",
        f"ALTER TABLE {WhitelistDomain.__tablename__} ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()",
        f"CREATE INDEX IF NOT EXISTS ix_{WhitelistDomain.__tablename__}_is_active ON {WhitelistDomain.__tablename__} (is_active)",
        f"CREATE INDEX IF NOT EXISTS ix_{WhitelistDomain.__tablename__}_is_safe ON {WhitelistDomain.__tablename__} (is_safe)",
        f"CREATE INDEX IF NOT EXISTS ix_{WhitelistDomain.__tablename__}_last_scanned_at ON {WhitelistDomain.__tablename__} (last_scanned_at)",
    ]
    for ddl in ddl_statements:
        db.execute(text(ddl))
    db.commit()
    WHITELIST_SCHEMA_READY = True


def _invalidate_whitelist_cache() -> None:
    redis_client = _get_redis_client()
    if redis_client is None:
        return
    try:
        redis_client.delete(WHITELIST_GLOBAL_CACHE_KEY)
    except REDIS_ERRORS as exc:
        logger.warning("Whitelist cache invalidation failed: %s", exc)


def _ensure_whitelist_event_hooks() -> None:
    global WHITELIST_EVENTS_READY
    if WHITELIST_EVENTS_READY:
        return

    def _on_whitelist_change(_mapper, _connection, _target):
        _invalidate_whitelist_cache()

    event.listen(WhitelistDomain, "after_insert", _on_whitelist_change)
    event.listen(WhitelistDomain, "after_update", _on_whitelist_change)
    event.listen(WhitelistDomain, "after_delete", _on_whitelist_change)
    WHITELIST_EVENTS_READY = True


def _stream_whitelist_domains_from_db(db: Session, redis_client: Any | None):
    temp_cache_key = f"{WHITELIST_GLOBAL_CACHE_KEY}:building"
    cache_enabled = redis_client is not None
    wrote_any = False
    cache_buffer: list[str] = []

    if cache_enabled:
        try:
            redis_client.delete(temp_cache_key)
        except REDIS_ERRORS:
            cache_enabled = False

    try:
        query = (
            db.query(WhitelistDomain.domain)
            .filter(
                WhitelistDomain.is_active.is_(True),
                WhitelistDomain.is_safe.is_(True),
                WhitelistDomain.last_scanned_at.isnot(None),
                WhitelistDomain.domain.isnot(None),
                WhitelistDomain.domain != "",
            )
            .distinct()
            .order_by(WhitelistDomain.domain.asc())
            .yield_per(WHITELIST_EXPORT_BATCH_SIZE)
        )

        for (domain,) in query:
            line = f"{domain}\n"
            wrote_any = True
            yield line
            if cache_enabled:
                cache_buffer.append(line)
                if len(cache_buffer) >= WHITELIST_EXPORT_BATCH_SIZE:
                    try:
                        redis_client.append(temp_cache_key, "".join(cache_buffer))
                    except REDIS_ERRORS as exc:
                        logger.warning("Whitelist cache write failed: %s", exc)
                        cache_enabled = False
                    finally:
                        cache_buffer.clear()

        if cache_enabled and cache_buffer:
            try:
                redis_client.append(temp_cache_key, "".join(cache_buffer))
            except REDIS_ERRORS as exc:
                logger.warning("Whitelist cache write failed: %s", exc)
                cache_enabled = False

        if cache_enabled and wrote_any:
            redis_client.rename(temp_cache_key, WHITELIST_GLOBAL_CACHE_KEY)
            redis_client.expire(WHITELIST_GLOBAL_CACHE_KEY, WHITELIST_GLOBAL_CACHE_TTL_SECONDS)
        elif cache_enabled:
            redis_client.delete(temp_cache_key)
    except SQLAlchemyError as exc:
        logger.error("Whitelist export query failed: %s", exc)
        if cache_enabled:
            try:
                redis_client.delete(temp_cache_key)
            except REDIS_ERRORS:
                pass
        raise HTTPException(status_code=500, detail="Could not export whitelist")


@whitelist_router.get("/global")
def export_global_whitelist(
    x_aegisnexus_key: str | None = Header(default=None, alias="X-AegisNexus-Key"),
    db: Session = Depends(get_db),
):
    _validate_optional_export_key(x_aegisnexus_key)
    _ensure_whitelist_schema(db)
    _ensure_whitelist_event_hooks()

    redis_client = _get_redis_client()
    if redis_client is not None:
        try:
            cached_payload = redis_client.get(WHITELIST_GLOBAL_CACHE_KEY)
        except REDIS_ERRORS:
            cached_payload = None
        if cached_payload:
            return StreamingResponse(
                _stream_cached_domains(cached_payload),
                media_type="text/plain",
                headers={"Cache-Control": "public, max-age=3600"},
            )

    stream = _stream_whitelist_domains_from_db(db=db, redis_client=redis_client)
    return StreamingResponse(
        stream,
        media_type="text/plain",
        headers={"Cache-Control": "public, max-age=3600"},
    )


_ensure_whitelist_event_hooks()


def _json_error(status_code: int, message: str, headers: dict[str, str] | None = None):
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "message": message},
        headers=headers or {},
    )


def _extract_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return (request.client.host if request.client else "unknown").strip() or "unknown"


def _normalize_domain(domain: str) -> str:
    return str(domain or "").strip().lower().strip(".")


def _query_doh_provider(endpoint: str, domain: str, timeout: int = 5) -> bool:
    response = requests.get(
        f"{endpoint}?name={domain}&type=A",
        headers={"Accept": "application/dns-json"},
        timeout=timeout,
    )
    response.raise_for_status()
    payload = response.json()
    status = payload.get("Status")
    return status in {2, 5}  # SERVFAIL, REFUSED


def _validate_verify_domains_payload(payload: dict[str, Any]) -> list[str]:
    domains = payload.get("domains")
    if not isinstance(domains, list):
        raise ValueError("domains zorunlu ve array olmalı")
    if len(domains) == 0:
        raise ValueError("domains boş olamaz")
    if len(domains) > MAX_VERIFY_DOMAINS:
        raise ValueError(f"domains en fazla {MAX_VERIFY_DOMAINS} kayıt içerebilir")

    normalized_domains: list[str] = []
    for value in domains:
        if not isinstance(value, str):
            raise ValueError("domains içinde sadece string değerler olmalı")
        domain = _normalize_domain(value)
        if not domain:
            raise ValueError("domain boş olamaz")
        if len(domain) > 253:
            raise ValueError("domain en fazla 253 karakter olabilir")
        if not DOMAIN_RE.match(domain):
            raise ValueError(f"geçersiz domain formatı: {value}")
        normalized_domains.append(domain)

    # Query tarafında gereksiz yükü azaltmak için uniq set kullanılır.
    return list(dict.fromkeys(normalized_domains))


def _validate_report_payload(payload: dict[str, Any]) -> tuple[str, str, str, str]:
    raw_url = str(payload.get("url") or "").strip()
    reason = str(payload.get("reason") or "").strip().lower()
    reported_by = str(payload.get("reported_by") or "").strip()

    if not raw_url:
        raise ValueError("url zorunlu")
    if len(raw_url) > 2048:
        raise ValueError("url en fazla 2048 karakter olabilir")

    parsed = urlparse(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url geçerli bir formatta olmalı")
    domain = (parsed.hostname or "").strip().lower()
    if not domain:
        raise ValueError("url geçerli bir domain içermeli")

    if not reason:
        raise ValueError("reason zorunlu")
    if reason not in VALID_REPORT_REASONS:
        raise ValueError("reason geçersiz")

    if not reported_by:
        raise ValueError("reported_by zorunlu")
    if len(reported_by) > 50:
        raise ValueError("reported_by en fazla 50 karakter olabilir")

    return raw_url, domain, reported_by, reason


def _ensure_report_columns(db: Session) -> None:
    global REPORT_SCHEMA_READY
    if REPORT_SCHEMA_READY:
        return

    ddl_statements = [
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS domain VARCHAR(512)",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS reported_by VARCHAR(50)",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS reason VARCHAR(50)",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS user_reported BOOLEAN DEFAULT FALSE",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS report_count INTEGER DEFAULT 0",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS last_reported_at TIMESTAMP",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS created_at TIMESTAMP DEFAULT NOW()",
        f"ALTER TABLE {PhishingURL.__tablename__} ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()",
        f"CREATE INDEX IF NOT EXISTS ix_{PhishingURL.__tablename__}_user_reported ON {PhishingURL.__tablename__} (user_reported)",
        f"CREATE INDEX IF NOT EXISTS ix_{PhishingURL.__tablename__}_created_at ON {PhishingURL.__tablename__} (created_at)",
    ]
    for ddl in ddl_statements:
        db.execute(text(ddl))
    db.commit()
    REPORT_SCHEMA_READY = True


def _check_report_rate_limit(redis_client: Any | None, client_ip: str) -> bool:
    if redis_client is None:
        return True
    key = f"rate:report:{client_ip}"
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, REPORT_RATE_LIMIT_WINDOW_SECONDS)
        return int(count) <= REPORT_RATE_LIMIT_PER_MINUTE
    except REDIS_ERRORS as exc:
        logger.warning("Report rate-limit unavailable: %s", exc)
        return True


def _check_verify_rate_limit(redis_client: Any | None, client_ip: str) -> bool:
    if redis_client is None:
        return True
    key = f"rate:verify:{client_ip}"
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, VERIFY_RATE_LIMIT_WINDOW_SECONDS)
        return int(count) <= VERIFY_RATE_LIMIT_PER_HOUR
    except REDIS_ERRORS as exc:
        logger.warning("Verify-user rate-limit unavailable: %s", exc)
        return True


def _check_report_form_rate_limit(redis_client: Any | None, client_ip: str) -> bool:
    if redis_client is None:
        return True
    key = f"rate:report-form:{client_ip}"
    try:
        count = redis_client.incr(key)
        if count == 1:
            redis_client.expire(key, REPORT_FORM_RATE_LIMIT_WINDOW_SECONDS)
        return int(count) <= REPORT_FORM_RATE_LIMIT_PER_MINUTE
    except REDIS_ERRORS as exc:
        logger.warning("Report-form rate-limit unavailable: %s", exc)
        return True


def _validate_report_form_payload(payload: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    """
    Validates phishing form report payload.
    Returns: (url, domain, form_data)
    """
    raw_url = str(payload.get("url") or "").strip()
    domain = str(payload.get("domain") or "").strip()
    form_data = payload.get("form_data")
    
    # Validate url
    if not raw_url:
        raise ValueError("url zorunlu")
    if len(raw_url) > 2048:
        raise ValueError("url en fazla 2048 karakter olabilir")
    
    # Validate domain
    if not domain:
        raise ValueError("domain zorunlu")
    if len(domain) > 512:
        raise ValueError("domain en fazla 512 karakter olabilir")
    
    # Validate form_data
    if not isinstance(form_data, dict):
        raise ValueError("form_data zorunlu ve object olmalı")
    
    action_url = form_data.get("action_url")
    if action_url is not None:
        action_url = str(action_url).strip()
        if len(action_url) > 2000:
            raise ValueError("action_url en fazla 2000 karakter olabilir")
    
    field_types = form_data.get("field_types")
    if not isinstance(field_types, list):
        raise ValueError("field_types array olmalı")
    for item in field_types:
        if not isinstance(item, str):
            raise ValueError("field_types sadece string değerler içermeli")
    
    risk_score = form_data.get("risk_score")
    if not isinstance(risk_score, int):
        raise ValueError("risk_score zorunlu ve integer olmalı")
    if risk_score < 0 or risk_score > 100:
        raise ValueError("risk_score 0-100 aralığında olmalı")
    
    flags = form_data.get("flags")
    if not isinstance(flags, list):
        raise ValueError("flags array olmalı")
    for item in flags:
        if not isinstance(item, str):
            raise ValueError("flags sadece string değerler içermeli")
    
    return raw_url, domain, {
        "action_url": action_url,
        "field_types": field_types,
        "risk_score": risk_score,
        "flags": flags
    }


@router.get("/export-domains")
def export_domains(
    x_aegisnexus_key: str | None = Header(default=None, alias="X-AegisNexus-Key"),
    db: Session = Depends(get_db),
):
    _validate_optional_export_key(x_aegisnexus_key)

    cutoff_ts = datetime.now(timezone.utc) - timedelta(days=30)
    timestamp_column = _detect_timestamp_column(db)
    _ensure_timestamp_index(db, timestamp_column)

    redis_client = _get_redis_client()
    if redis_client is not None:
        try:
            cached_payload = redis_client.get(EXPORT_DOMAINS_CACHE_KEY)
        except REDIS_ERRORS:
            cached_payload = None
        if cached_payload:
            return StreamingResponse(
                _stream_cached_domains(cached_payload),
                media_type="text/plain",
                headers={"Cache-Control": "public, max-age=3600"},
            )

    stream = _stream_domains_from_db(
        db=db,
        timestamp_column=timestamp_column,
        cutoff_ts=cutoff_ts,
        redis_client=redis_client,
    )
    return StreamingResponse(
        stream,
        media_type="text/plain",
        headers={"Cache-Control": "public, max-age=3600"},
    )


@router.post("/report")
def report_url(payload: dict[str, Any], request: Request, db: Session = Depends(get_db)):
    if not isinstance(payload, dict):
        return _json_error(400, "Geçersiz JSON body")

    try:
        raw_url, domain, reported_by, reason = _validate_report_payload(payload)
    except ValueError as exc:
        return _json_error(400, str(exc))

    try:
        _ensure_report_columns(db)
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Report schema ensure failed: %s", exc)
        return _json_error(500, "Sunucu hatası")

    client_ip = _extract_client_ip(request)
    redis_client = _get_redis_client()
    if not _check_report_rate_limit(redis_client, client_ip):
        return _json_error(
            429,
            "Çok fazla rapor gönderdiniz, lütfen bekleyin",
            headers={"Retry-After": str(REPORT_RATE_LIMIT_WINDOW_SECONDS)},
        )

    now = datetime.now(timezone.utc)
    try:
        existing = db.query(PhishingURL).filter(PhishingURL.url == raw_url).first()
        if existing:
            existing.report_count = int(existing.report_count or 0) + 1
            existing.last_reported_at = now
            existing.user_reported = True
            existing.updated_at = now
            db.commit()
            return {"success": True, "message": "Rapor alındı"}

        new_report = PhishingURL(
            url=raw_url,
            domain=domain,
            domain_norm=domain,
            reported_by=reported_by,
            reason=reason,
            user_reported=True,
            status="pending_review",
            report_count=1,
            last_reported_at=now,
            created_at=now,
            updated_at=now,
            online=False,
            target="user-report",
        )
        db.add(new_report)
        db.commit()
        return {"success": True, "message": "Rapor alındı"}
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Report save failed: %s", exc)
        return _json_error(500, "Sunucu hatası")


@router.post("/report-form")
def report_form(payload: dict[str, Any], request: Request, db: Session = Depends(get_db)):
    """
    Report a phishing form detected on a page.
    
    Body:
    {
        "url": "https://example.com/phishing",
        "domain": "example.com",
        "form_data": {
            "action_url": "https://attacker.com/steal",
            "field_types": ["password", "credit_card"],
            "risk_score": 85,
            "flags": ["form-has-password", "form-action-different-domain"]
        }
    }
    """
    if not isinstance(payload, dict):
        return _json_error(400, "Geçersiz JSON body")
    
    try:
        raw_url, domain, form_data = _validate_report_form_payload(payload)
    except ValueError as exc:
        return _json_error(400, str(exc))
    
    # Get client IP for rate limiting
    client_ip = _extract_client_ip(request)
    redis_client = _get_redis_client()
    
    # Check rate limit: 20 requests/minute per IP
    if not _check_report_form_rate_limit(redis_client, client_ip):
        return _json_error(
            429,
            "Çok fazla form raporu gönderdiniz, lütfen bekleyin",
            headers={"Retry-After": str(REPORT_FORM_RATE_LIMIT_WINDOW_SECONDS)},
        )
    
    now = datetime.now(timezone.utc)
    try:
        action_url = form_data.get("action_url")
        
        # Check for duplicate: same url + action_url combination
        if action_url:
            existing = db.query(PhishingForm).filter(
                PhishingForm.url == raw_url,
                PhishingForm.action_url == action_url
            ).first()
        else:
            existing = db.query(PhishingForm).filter(
                PhishingForm.url == raw_url
            ).first()
        
        if existing:
            # Increment detection count and update timestamp
            existing.detection_count = int(existing.detection_count or 1) + 1
            existing.updated_at = now
            db.commit()
            return {"success": True, "message": "Form raporu alındı"}
        
        # Create new form report
        new_report = PhishingForm(
            url=raw_url,
            domain=domain,
            action_url=action_url,
            field_types=form_data.get("field_types", []),
            risk_score=form_data.get("risk_score"),
            flags=form_data.get("flags", []),
            reported_by="extension",
            detection_count=1,
            status="pending_review",
            created_at=now,
            updated_at=now
        )
        db.add(new_report)
        db.commit()
        return {"success": True, "message": "Form raporu alındı"}
    except SQLAlchemyError as exc:
        db.rollback()
        logger.error("Form report save failed: %s", exc)
        return _json_error(500, "Sunucu hatası")


@whitelist_router.post("/verify-user")
def verify_user_whitelist(payload: dict[str, Any], request: Request, db: Session = Depends(get_db)):
    if not isinstance(payload, dict):
        return _json_error(400, "Geçersiz JSON body")

    try:
        domains = _validate_verify_domains_payload(payload)
    except ValueError as exc:
        return _json_error(400, str(exc))

    client_ip = _extract_client_ip(request)
    redis_client = _get_redis_client()
    if not _check_verify_rate_limit(redis_client, client_ip):
        return _json_error(
            429,
            "Çok fazla doğrulama isteği gönderdiniz, lütfen bekleyin",
            headers={"Retry-After": str(VERIFY_RATE_LIMIT_WINDOW_SECONDS)},
        )

    try:
        _ensure_whitelist_schema(db)
        rows = (
            db.query(WhitelistDomain.domain, WhitelistDomain.is_active, WhitelistDomain.is_safe)
            .filter(func.lower(WhitelistDomain.domain).in_(domains))
            .all()
        )
    except SQLAlchemyError as exc:
        logger.error("Verify-user query failed: %s", exc)
        return _json_error(500, "Sunucu hatası")

    indexed: dict[str, tuple[bool, bool]] = {}
    for domain, is_active, is_safe in rows:
        indexed[_normalize_domain(domain)] = (bool(is_active), bool(is_safe))

    results: list[dict[str, Any]] = []
    safe_count = 0
    unsafe_count = 0

    for domain in domains:
        state = indexed.get(domain)
        if state is None:
            results.append({"domain": domain, "is_safe": False, "reason": "not_in_whitelist"})
            unsafe_count += 1
            continue

        is_active, is_safe = state
        if not is_safe:
            results.append({"domain": domain, "is_safe": False, "reason": "flagged_by_scan"})
            unsafe_count += 1
            continue
        if not is_active:
            results.append({"domain": domain, "is_safe": False, "reason": "inactive"})
            unsafe_count += 1
            continue

        results.append({"domain": domain, "is_safe": True})
        safe_count += 1

    return {
        "results": results,
        "unsafe_count": unsafe_count,
        "safe_count": safe_count,
    }


class SiteAddRequest(BaseModel):
    url: str
    target: str
    status: str


class URLCheckRequest(BaseModel):
    url: str
    domain: str | None = None
    local_score: float | None = None
    risk_level: str | None = None
    flags: list[str] = []
    dns: dict[str, Any] | None = None
    gsb: dict[str, Any] | None = None
    bloom: dict[str, Any] | None = None
    force_fresh: bool = False
    db_only: bool = False


class URLCheckResponse(BaseModel):
    status: str
    score: float
    threat_level: str
    details: dict


class FormDataRequest(BaseModel):
    action_url: str | None = None
    field_types: list[str] = []
    risk_score: int
    flags: list[str] = []


class PhishingFormReportRequest(BaseModel):
    url: str
    domain: str
    form_data: FormDataRequest


# Rate limiting decorator
def rate_limit(max_requests: int, time_window: int):
    """Rate limiting decorator (requests per time_window seconds)"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            now = datetime.now()
            client_id = kwargs.get('db').__hash__() if 'db' in kwargs else str(args)
            
            if client_id not in RATE_LIMIT_STORAGE:
                RATE_LIMIT_STORAGE[client_id] = []
            
            # Eski requests'i temizle
            cutoff_time = now - timedelta(seconds=time_window)
            RATE_LIMIT_STORAGE[client_id] = [
                req_time for req_time in RATE_LIMIT_STORAGE[client_id]
                if req_time > cutoff_time
            ]
            
            # Limiti kontrol et
            if len(RATE_LIMIT_STORAGE[client_id]) >= max_requests:
                raise HTTPException(
                    status_code=429,
                    detail=f"Rate limit exceeded: {max_requests} requests per {time_window}s"
                )
            
            RATE_LIMIT_STORAGE[client_id].append(now)
            return func(*args, **kwargs)
        return wrapper
    return decorator


def _build_db_only_result(requested_url: str, db: Session) -> dict[str, Any]:
    normalized = normalize_url_record(requested_url)
    canonical_url = normalized.get("canonical_url", requested_url)
    domain_norm = normalized.get("domain_norm", "")
    url_hash = normalized.get("url_hash")

    cached_result = get_cached_scan_result(canonical_url, days=30) or get_cached_scan_result(requested_url, days=30)
    if cached_result:
        logger.info(f"[db_only] Cache hit: {requested_url} → score={cached_result.get('score')}")
        return {
            **cached_result,
            "db_only": True,
            "source": "cache_db",
            "cache": "30d-hit",
        }

    # Try exact hash match first (most reliable)
    matched = None
    if url_hash:
        matched = db.query(PhishingURL).filter(PhishingURL.url_hash == url_hash).first()
        logger.info(f"[db_only] Hash query: url_hash={url_hash} → {'HIT' if matched else 'MISS'}")
    
    # Fallback to domain_norm query
    if not matched and domain_norm:
        matched = db.query(PhishingURL).filter(PhishingURL.domain_norm == domain_norm).order_by(PhishingURL.id.desc()).first()
        logger.info(f"[db_only] Domain query: domain_norm={domain_norm} → {'HIT' if matched else 'MISS'}")
    
    logger.info(f"[db_only] Query params: canonical={canonical_url}, domain_norm={domain_norm}, url_hash={url_hash}")
    if not matched:
        logger.info(f"[db_only] DB miss: {requested_url}")
        return {
            "status": "ok",
            "url": requested_url,
            "domain": domain_norm,
            "score": 0,
            "risk_level": "SAFE",
            "decision": "safe",
            "details": ["db_miss"],
            "sources": [{"name": "phishing_urls_db", "status": "miss"}],
            "db_only": True,
            "source": "phishing_urls_db",
        }

    status_text = str(matched.status or "").strip().lower()
    # If online=True OR status suggests active threat → high score (CRITICAL)
    # Otherwise just being in the DB list → medium/low score
    is_online_threat = bool(matched.online) or status_text in {"online", "active", "phishing"}
    score = 85 if is_online_threat else 40
    risk_level = "CRITICAL" if is_online_threat else "MEDIUM"

    logger.info(f"[db_only] DB hit: {requested_url} → online={matched.online}, status={status_text}, score={score}")

    return {
        "status": "ok",
        "url": requested_url,
        "domain": matched.domain_norm or domain_norm,
        "score": score,
        "risk_level": risk_level,
        "decision": "block" if score >= 80 else "suspicious" if score >= 40 else "safe",
        "details": [f"db_match_status:{status_text or 'unknown'}"],
        "sources": [{"name": "phishing_urls_db", "status": "hit"}],
        "db_only": True,
        "source": "phishing_urls_db",
    }


def _score_to_risk_level(score: float) -> str:
    safe_score = max(0, min(100, int(score)))
    if safe_score <= 20:
        return "SAFE"
    if safe_score <= 40:
        return "LOW"
    if safe_score <= 60:
        return "MEDIUM"
    if safe_score <= 80:
        return "HIGH"
    return "CRITICAL"


@router.post("/add-site")
def add_site(
    item: SiteAddRequest,
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_api_key),
):
    """Yeni phishing sitesi ekle"""
    if not item.url or not item.target:
        raise HTTPException(status_code=400, detail="URL ve Hedef boş olamaz")

    phish_id_gen = f"PHISH-{uuid.uuid4().hex[:12].upper()}"

    normalized = normalize_url_record(item.url)
    stored_url = normalized.get("canonical_url", item.url.strip())

    new_site = PhishingURL(
        phish_id=phish_id_gen,
        url=stored_url,
        url_hash=normalized.get("url_hash"),
        domain_norm=normalized.get("domain_norm"),
        target=item.target,
        status=item.status,
        online=True if item.status == "ONLINE" else False,
    )

    try:
        db.add(new_site)
        db.commit()
        db.refresh(new_site)
        logger.info(f"Yeni phishing sitesi eklendi: {phish_id_gen}")
        return {
            "status": "success",
            "message": "Site başarıyla veritabanına eklendi!",
            "id": phish_id_gen,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        db.rollback()
        logger.error(f"Sitesi ekleme hatası: {str(e)}")
        raise HTTPException(status_code=500, detail="Kayıt hatası")


def _write_analiz_history(db: Session, url: str, result: dict[str, Any]) -> None:
    try:
        parsed = urlparse(url)
        domain = (parsed.hostname or "").strip().lower()
        if not domain:
            return

        risk_level = str(result.get("risk_level", "unknown")).lower()
        is_phishing = risk_level in {"high", "critical"}
        confidence = min(result.get("score", 0) / 100.0, 1.0) if result.get("score") else None

        record = URLAnalizHistory(
            url=url,
            domain=domain,
            risk_level=risk_level,
            is_phishing=is_phishing,
            confidence=confidence,
            analysis_result=result,
            url_checks=result.get("details") if isinstance(result.get("details"), (list, dict)) else None,
        )
        db.add(record)
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        logger.warning("URLAnalizHistory write failed: %s", exc)


@router.get("/analysis-history")
def get_analysis_history(domain: str, limit: int = 5, db: Session = Depends(get_db)):
    """Bir domain'in geçmiş analiz sonuçlarını döndür."""
    if not domain:
        raise HTTPException(status_code=400, detail="domain parametresi zorunlu")
    limit = max(1, min(limit, 50))

    try:
        rows = (
            db.query(URLAnalizHistory)
            .filter(func.lower(URLAnalizHistory.domain) == domain.strip().lower())
            .order_by(URLAnalizHistory.created_at.desc())
            .limit(limit)
            .all()
        )

        results = [
            {
                "url": row.url,
                "domain": row.domain,
                "risk_level": row.risk_level,
                "is_phishing": row.is_phishing,
                "confidence": row.confidence,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ]

        return {
            "success": True,
            "domain": domain.strip().lower(),
            "count": len(results),
            "results": results,
            "module": "01_phishing_detector",
        }
    except SQLAlchemyError as exc:
        logger.error("Analysis history query failed: %s", exc)
        return _json_error(500, "Sunucu hatası")


@router.get("/dns-check")
def dns_check(domain: str):
    normalized_domain = _normalize_domain(domain)
    if not normalized_domain:
        raise HTTPException(status_code=400, detail="domain parametresi zorunlu")

    cloudflare_blocked = False
    quad9_blocked = False

    try:
        cloudflare_blocked = _query_doh_provider(DNS_CLOUDFLARE_DOH_URL, normalized_domain)
    except Exception as exc:
        logger.warning("Cloudflare DNS check failed for %s: %s", normalized_domain, exc)

    try:
        quad9_blocked = _query_doh_provider(DNS_QUAD9_DOH_URL, normalized_domain)
    except Exception as exc:
        logger.warning("Quad9 DNS check failed for %s: %s", normalized_domain, exc)

    return {
        "domain": normalized_domain,
        "cloudflare_blocked": cloudflare_blocked,
        "quad9_blocked": quad9_blocked,
        "consensus_blocked": cloudflare_blocked and quad9_blocked,
        "source": "external_dns",
        "module": "01_phishing_detector",
    }


@router.post("/check-url")
@rate_limit(max_requests=60, time_window=60)
def check_url(request: URLCheckRequest, db: Session = Depends(get_db)):
    """URL güvenlik skorunu hesapla"""
    if not request.url:
        raise HTTPException(status_code=400, detail="URL boş olamaz")
    try:
        requested_url = request.url.strip()

        if request.db_only:
            db_result = _build_db_only_result(requested_url, db)
            sources = []
            for src in db_result.get("sources", []):
                if isinstance(src, dict):
                    name = src.get("name")
                    if name:
                        sources.append(str(name))
                elif isinstance(src, str):
                    sources.append(src)

            write_phishing_url(
                url=requested_url,
                risk_score=int(db_result.get("score", 0)),
                risk_level=str(db_result.get("risk_level", "unknown")).lower(),
                is_safe=bool(db_result.get("score", 0) >= 80),
                sources=sources,
                raw_data=db_result,
                track_event=True,
            )
            _write_analiz_history(db, requested_url, db_result)
            db_result["module"] = "01_phishing_detector"
            return db_result
        
        # Cache kontrolü - force_fresh ise bypass et
        if not request.force_fresh:
            cached_result = get_cached_scan_result(requested_url, days=30)
            if cached_result:
                sources = []
                for src in cached_result.get("sources", []):
                    if isinstance(src, dict):
                        name = src.get("name")
                        if name:
                            sources.append(str(name))
                    elif isinstance(src, str):
                        sources.append(src)
                write_phishing_url(
                    url=requested_url,
                    risk_score=int(cached_result.get("score", 0)),
                    risk_level=str(cached_result.get("risk_level", "unknown")),
                    is_safe=bool(cached_result.get("score", 0) >= 80),
                    sources=sources,
                    raw_data=cached_result,
                    track_event=True,
                )
                _write_analiz_history(db, requested_url, cached_result)
                cached_result["module"] = "01_phishing_detector"
                cached_result["cache"] = "30d-hit"
                logger.info(f"Cache hit: {requested_url} - Skor: {cached_result.get('score')}")
                return cached_result

        if request.local_score is not None:
            local_score = float(request.local_score or 0)
            local_score = max(0.0, min(100.0, local_score))
            merged_flags = [str(flag) for flag in (request.flags or []) if str(flag).strip()]

            db_result = _build_db_only_result(requested_url, db)
            db_details = [str(item) for item in db_result.get("details", [])]
            db_sources = db_result.get("sources", [])
            db_hit = "db_miss" not in db_details

            score = local_score
            if db_hit:
                score = max(score, float(db_result.get("score", 0) or 0))
                merged_flags.append("db-match")

            if request.dns and isinstance(request.dns, dict):
                dns = request.dns
                if dns.get("consensus_blocked"):
                    score = min(100.0, score + 40)
                elif dns.get("cloudflare_blocked") or dns.get("quad9_blocked"):
                    score = min(100.0, score + 20)
            if request.gsb and isinstance(request.gsb, dict) and request.gsb.get("threat_found"):
                score = min(100.0, max(score, 90.0))
                merged_flags.append("gsb-threat")

            normalized_score = max(0, min(100, int(round(score))))
            risk_level = _score_to_risk_level(normalized_score)
            result = {
                "status": "ok",
                "url": requested_url,
                "domain": request.domain or _normalize_domain(urlparse(requested_url).hostname or ""),
                "score": normalized_score,
                "risk_level": risk_level,
                "flags": sorted(set(merged_flags)),
                "is_phishing": bool(db_hit or normalized_score >= 60),
                "source": "server",
                "dns": request.dns or {},
                "gsb": request.gsb or {},
                "bloom": request.bloom or {},
                "decision": "block" if normalized_score >= 80 else "suspicious" if normalized_score >= 40 else "safe",
                "details": db_details if db_hit else ["local_only"],
                "sources": db_sources if db_hit else [{"name": "local_payload", "status": "used"}],
            }
        else:
            result = calculate_safety_score(requested_url, db)
            
            # DNS kontrolleri (Quad9/Cloudflare) - backend'de score'a ekle
            try:
                domain_to_check = urlparse(requested_url).netloc.split(":")[0] or ""
                if domain_to_check:
                    cloudflare_blocked = False
                    quad9_blocked = False
                    
                    try:
                        cloudflare_blocked = _query_doh_provider(DNS_CLOUDFLARE_DOH_URL, domain_to_check)
                    except Exception as e:
                        logger.warning(f"Cloudflare DNS check failed: {e}")
                    
                    try:
                        quad9_blocked = _query_doh_provider(DNS_QUAD9_DOH_URL, domain_to_check)
                    except Exception as e:
                        logger.warning(f"Quad9 DNS check failed: {e}")
                    
                    if cloudflare_blocked and quad9_blocked:
                        result["score"] = min(100, result.get("score", 0) + 40)
                        if "details" not in result:
                            result["details"] = []
                        result["details"].append("🚨 DNS: Hem Cloudflare hem Quad9 tarafından engellendi")
                        if "sources" not in result:
                            result["sources"] = []
                        result["sources"].append({"name": "DNS Filtering", "status": "Consensus Blocked"})
                    elif cloudflare_blocked or quad9_blocked:
                        result["score"] = min(100, result.get("score", 0) + 20)
                        blocked_by = []
                        if cloudflare_blocked:
                            blocked_by.append("Cloudflare")
                        if quad9_blocked:
                            blocked_by.append("Quad9")
                        if "details" not in result:
                            result["details"] = []
                        result["details"].append(f"⚠️ DNS: {', '.join(blocked_by)} tarafından engellendi")
                        if "sources" not in result:
                            result["sources"] = []
                        result["sources"].append({"name": "DNS Filtering", "status": "Provider Blocked"})
                    result["dns"] = {
                        "cloudflare_blocked": cloudflare_blocked,
                        "quad9_blocked": quad9_blocked,
                        "consensus_blocked": cloudflare_blocked and quad9_blocked,
                        "source": "external_dns",
                    }
            except Exception as e:
                logger.warning(f"DNS check failed for {requested_url}: {e}")
        
        sources = []
        for src in result.get("sources", []):
            if isinstance(src, dict):
                name = src.get("name")
                if name:
                    sources.append(str(name))
        write_phishing_url(
            url=requested_url,
            risk_score=int(result.get("score", 0)),
            risk_level=str(result.get("risk_level", "unknown")),
            is_safe=bool(result.get("score", 0) >= 80),
            sources=sources,
            raw_data=result,
            track_event=True,
        )
        _write_analiz_history(db, requested_url, result)
        result["module"] = "01_phishing_detector"
        logger.info(f"URL kontrol yapıldı: {requested_url} - Skor: {result.get('score')}")
        return result
    except Exception as e:
        logger.error(f"URL kontrol hatası: {str(e)}")
        write_phishing_url(
            url=request.url.strip(),
            risk_score=50,
            risk_level="degraded",
            is_safe=False,
            sources=["degraded"],
            raw_data={"error": str(e)},
            track_event=True,
        )
        # Fail-soft: UI'nin tamamen kırılmasını engellemek için degrade yanıt döndür.
        return {
            "status": "degraded",
            "url": request.url,
            "score": 50,
            "risk_level": "medium",
            "details": ["Harici kaynak hatası veya gecikmesi nedeniyle kısmi sonuç döndürüldü."],
            "sources": [],
            "module": "01_phishing_detector",
        }


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    """Toplam zararlı site sayısı"""
    try:
        # Try cache_db first
        cache_stats = get_phishing_stats()
        if cache_stats["total_urls"] > 0:
            return {
                "stats": cache_stats,
                "module": "01_phishing_detector"
            }
        
        # Fallback to SQLAlchemy
        count = db.query(PhishingURL).count()
        return {
            "stats": {
                "total_urls": count,
                "phishing_count": count,
                "safe_count": 0,
                "today_scans": 0
            },
            "module": "01_phishing_detector"
        }
    except Exception:
        return {"stats": {"total_urls": 0, "phishing_count": 0, "safe_count": 0, "today_scans": 0}, "module": "01_phishing_detector"}


@router.get("/stats-summary")
def get_stats_summary(db: Session = Depends(get_db)):
    """Tek istekte phishing, whitelist, IOC ve form özet istatistiklerini döndür."""
    phishing_url_count = db.query(func.count(PhishingURL.id)).scalar() or 0
    phishing_url_online_count = (
        db.query(func.count(PhishingURL.id))
        .filter(
            or_(
                PhishingURL.online.is_(True),
                func.lower(PhishingURL.status).in_(["online", "active"]),
            )
        )
        .scalar()
        or 0
    )
    whitelist_domain_count = db.query(func.count(WhitelistDomain.id)).scalar() or 0

    active_ioc_filter = or_(
        IndicatorOfCompromise.status == "active",
        IndicatorOfCompromise.status.is_(None),
    )
    ioc_active_count = (
        db.query(func.count(IndicatorOfCompromise.id))
        .filter(active_ioc_filter)
        .scalar()
        or 0
    )

    ioc_by_type = {"ip": 0, "domain": 0, "url": 0, "hash": 0}
    ioc_type_rows = (
        db.query(
            func.lower(IndicatorOfCompromise.ioc_type).label("ioc_type"),
            func.count(IndicatorOfCompromise.id).label("count"),
        )
        .filter(active_ioc_filter)
        .group_by(func.lower(IndicatorOfCompromise.ioc_type))
        .all()
    )
    for row in ioc_type_rows:
        ioc_type = str(row.ioc_type or "").strip().lower()
        if ioc_type in ioc_by_type:
            ioc_by_type[ioc_type] = int(row.count or 0)

    form_pending_review_count = (
        db.query(func.count(PhishingForm.id))
        .filter(PhishingForm.status == "pending_review")
        .scalar()
        or 0
    )

    return {
        "phishing_url_count": int(phishing_url_count),
        "phishing_url_online_count": int(phishing_url_online_count),
        "whitelist_domain_count": int(whitelist_domain_count),
        "ioc_active_count": int(ioc_active_count),
        "ioc_by_type": ioc_by_type,
        "form_pending_review_count": int(form_pending_review_count),
        "last_updated": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/latest-paged")
def get_latest(limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    """Son eklenen tehditler"""
    try:
        limit = max(limit, 1)
        page = max(page, 1)
        offset = (page - 1) * limit
        status_rank = case(
            (func.lower(PhishingURL.status).in_(["active", "online"]), 0),
            (func.lower(PhishingURL.status) == "valid", 1),
            else_=2,
        )
        total = db.query(PhishingURL).count()
        items = (
            db.query(PhishingURL)
            .order_by(status_rank.asc(), PhishingURL.id.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        rows = [
            {
                "id": item.id,
                "url": item.url,
                "domain": item.domain_norm or item.url,
                "target": item.target or "Phishing",
                "status": item.status or "unknown",
                "submission_time": item.submission_time.isoformat() if item.submission_time else None,
            }
            for item in items
        ]
        total_pages = (total + limit - 1) // limit if limit else 1
        return {
            "data": rows,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "page_size": limit,
            "module": "01_phishing_detector"
        }
    except Exception:
        return {"data": [], "page": 1, "total_pages": 1, "total": 0, "module": "01_phishing_detector"}


@router.get("/search")
def search_urls(url: str, limit: int = 20, page: int = 1, db: Session = Depends(get_db)):
    """URL içinde arama yap (case-insensitive) - fast search without count()"""
    try:
        if not url:
            raise HTTPException(status_code=400, detail="Arama sorgusu boş olamaz")
        
        offset = (page - 1) * limit
        # Fast search - no count() for performance
        results = db.query(PhishingURL).filter(
            PhishingURL.url.ilike(f"%{url}%")
        ).order_by(PhishingURL.id.desc()).offset(offset).limit(limit).all()
        
        if not results and page == 1:
            logger.info(f"Arama sonuç yok: {url}")
            return {
                "status": "SAFE",
                "data": [],
                "page": 1,
                "total_pages": 0,
                "total": 0,
                "module": "01_phishing_detector"
            }
        
        # Approximate pagination - if we got full limit, there are more results
        has_more = len(results) == limit
        total = len(results) + (1 if has_more else 0)  # Approximate
        total_pages = page + (1 if has_more else 0)
        
        logger.info(f"Arama yapıldı: {url} - Sonuç: {len(results)}")
        return {
            "status": "DANGER" if results else "SAFE",
            "data": results,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Arama hatası: {str(e)}")
        return {
            "status": "ERROR",
            "data": [],
            "page": 1,
            "total_pages": 0,
            "total": 0,
            "module": "01_phishing_detector"
        }


@router.post("/update-db")
def update_phishtank_database(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_api_key),
):
    """Deprecated: Lokal PhishTank import kaldirildi."""
    return {
        "status": "deprecated",
        "message": "Lokal PhishTank JSON import kaldirildi. /fetch-all endpoint'ini kullanin.",
        "module": "01_phishing_detector"
    }





@router.post("/fetch-all")
def fetch_all_phishing_data(
    db: Session = Depends(get_db),
    _: None = Depends(require_admin_api_key),
):
    """Tum kaynaklardan phishing verileri cek (GitHub, OpenPhish, URLHaus, Kaggle, CertStream, OTX)"""
    try:
        result = fetch_all_sources(db)
        return {
            "status": "success",
            "message": f"Tum kaynaklardan {result['total_added']} yeni veri eklendi",
            "data": result,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "module": "01_phishing_detector"
        }


@router.get("/history")
def get_phishing_scan_history(limit: int = 50, days: int = 30, db: Session = Depends(get_db)):
    """URL tarama geçmişini getir (threat_intel_cache.db)."""
    try:
        history_page = get_scan_history(limit=limit, page=1, days=days)
        return {
            "history": history_page["data"],
            "limit": limit,
            "days": days,
            "total": history_page["total"],
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"History fetch error: {e}")
        # Fallback to cache if main DB fails
        try:
            history = get_phishing_history(limit=limit, days=days)
            return {
                "history": history,
                "limit": limit,
                "days": days,
                "module": "01_phishing_detector"
            }
        except:
            return {
                "history": [],
                "limit": limit,
                "days": days,
                "module": "01_phishing_detector"
            }


@router.get("/scan-history")
def get_scan_history_paged(limit: int = 20, page: int = 1, days: int = 30):
    """Paginated URL scan history for frontend chips/list."""
    try:
        result = get_scan_history(limit=limit, page=page, days=days)
        result["module"] = "01_phishing_detector"
        return result
    except Exception as e:
        logger.error(f"Scan history fetch error: {e}")
        return {
            "data": [],
            "page": 1,
            "total_pages": 0,
            "total": 0,
            "limit": limit,
            "module": "01_phishing_detector",
        }


@router.get("/latest")
def get_latest_phishing_urls(limit: int = 20, db: Session = Depends(get_db)):
    """Son phishing URL'leri getir (gerçek PhishingURL tablosundan)"""
    try:
        # Use real PhishingURL table instead of cache
        items = db.query(PhishingURL).order_by(PhishingURL.id.desc()).limit(limit).all()
        
        latest = []
        for item in items:
            latest.append({
                'url': item.url,
                'domain': item.domain_norm or item.url,
                'risk_score': 85,  # Default high risk for known phishing
                'submission_time': item.submission_time.isoformat() if item.submission_time else datetime.now().isoformat(),
                'target': item.target or 'Phishing',
                'phish_id': item.phish_id,
                'status': item.status
            })
        
        return {
            "latest": latest,
            "limit": limit,
            "total": db.query(PhishingURL).count(),
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Latest fetch error: {e}")
        # Fallback to cache if main DB fails
        try:
            latest = get_latest_phishing(limit=limit)
            return {
                "latest": latest,
                "limit": limit,
                "module": "01_phishing_detector"
            }
        except:
            return {
                "latest": [],
                "limit": limit,
                "module": "01_phishing_detector"
            }


@router.get("/threat-types")
def get_threat_types_distribution():
    """Tehdit tipi dağılımını getir (cache_db'den)"""
    try:
        types = get_threat_type_distribution()
        return {
            "types": types,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Threat types fetch error: {e}")
        return {
            "types": {},
            "module": "01_phishing_detector"
        }


@router.get("/skipped-urls")
def get_skipped_urls(days: int = 30):
    """Sources dolu ama risk_score=0 olan URL'leri tespit et"""
    try:
        from .cache_db import detect_skipped_urls
        skipped = detect_skipped_urls(days=days)
        return {
            "skipped": skipped,
            "count": len(skipped),
            "days": days,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Skipped URLs fetch error: {e}")
        return {
            "skipped": [],
            "count": 0,
            "days": days,
            "module": "01_phishing_detector"
        }


@router.get("/cleanup/analyze")
def analyze_cleanup(days: int = 30):
    """Kayıtları analiz et ve temizleme kriterlerine göre grupla"""
    try:
        from .cache_db import analyze_records
        analysis = analyze_records(days=days)
        return {
            "analysis": analysis,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Cleanup analysis error: {e}")
        return {
            "analysis": {
                "total_records": 0,
                "categories": {},
                "error": str(e)
            },
            "module": "01_phishing_detector"
        }


@router.post("/cleanup")
def perform_cleanup(days: int = 30, unscanned: bool = True, no_sources: bool = False, no_raw_data: bool = False, dry_run: bool = False):
    """Profesyonel cleanup - kriter bazlı temizleme"""
    try:
        from .cache_db import cleanup_records
        criteria = {
            'days': days,
            'unscanned': unscanned,
            'no_sources': no_sources,
            'no_raw_data': no_raw_data
        }
        result = cleanup_records(criteria, dry_run=dry_run)
        return {
            "result": result,
            "module": "01_phishing_detector"
        }
    except Exception as e:
        logger.error(f"Cleanup error: {e}")
        return {
            "result": {
                "deleted": 0,
                "error": str(e)
            },
            "module": "01_phishing_detector"
        }


@router.get("/stats-summary")
def get_stats_summary(db: Session = Depends(get_db)):
    """Veritabanı özet istatistikleri — extension popup için."""
    try:
        phishing_count = db.query(func.count(PhishingURL.id)).scalar() or 0
        phishing_online = db.query(func.count(PhishingURL.id)).filter(PhishingURL.online == True).scalar() or 0
        whitelist_count = db.query(func.count(WhitelistDomain.id)).scalar() or 0
        ioc_active = db.query(func.count(IndicatorOfCompromise.id)).filter(
            or_(IndicatorOfCompromise.status == "active", IndicatorOfCompromise.status.is_(None))
        ).scalar() or 0

        ioc_by_type_rows = (
            db.query(IndicatorOfCompromise.ioc_type, func.count(IndicatorOfCompromise.id))
            .filter(or_(IndicatorOfCompromise.status == "active", IndicatorOfCompromise.status.is_(None)))
            .group_by(IndicatorOfCompromise.ioc_type)
            .all()
        )
        ioc_by_type = {row[0]: row[1] for row in ioc_by_type_rows if row[0]}

        form_pending = db.query(func.count(PhishingForm.id)).filter(
            PhishingForm.status == "pending_review"
        ).scalar() or 0

        return {
            "phishing_url_count": phishing_count,
            "phishing_url_online_count": phishing_online,
            "whitelist_domain_count": whitelist_count,
            "ioc_active_count": ioc_active,
            "ioc_by_type": ioc_by_type,
            "form_pending_review_count": form_pending,
            "last_updated": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.error("Stats summary error: %s", e)
        raise HTTPException(status_code=500, detail="Stats query failed")
