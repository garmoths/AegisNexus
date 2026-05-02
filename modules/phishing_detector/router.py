"""
01 - Phishing Detector Module Router
Tehdit veritabanı, URL tarama ve analiz endpointleri
"""
import uuid
import logging
import hmac
import os
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any
from urllib.parse import urlparse
import re

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import case, event, func
from sqlalchemy import inspect, text
from sqlalchemy.exc import SQLAlchemyError
try:
    import redis
except ImportError:  # pragma: no cover - optional runtime dependency
    redis = None

from shared.utils.db import get_db
from app.models import PhishingURL, WhitelistDomain
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
MAX_VERIFY_DOMAINS = 500
VALID_REPORT_REASONS = {"phishing", "malware", "scam", "spam", "other"}
REDIS_ERRORS = (redis.RedisError,) if redis else ()
REPORT_SCHEMA_READY = False
WHITELIST_SCHEMA_READY = False
WHITELIST_EVENTS_READY = False
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


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
    force_fresh: bool = False


class URLCheckResponse(BaseModel):
    status: str
    score: float
    threat_level: str
    details: dict


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


@router.post("/check-url")
@rate_limit(max_requests=60, time_window=60)
def check_url(request: URLCheckRequest, db: Session = Depends(get_db)):
    """URL güvenlik skorunu hesapla"""
    if not request.url:
        raise HTTPException(status_code=400, detail="URL boş olamaz")
    try:
        requested_url = request.url.strip()
        
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
                cached_result["module"] = "01_phishing_detector"
                cached_result["cache"] = "30d-hit"
                logger.info(f"Cache hit: {requested_url} - Skor: {cached_result.get('score')}")
                return cached_result

        result = calculate_safety_score(requested_url, db)
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
