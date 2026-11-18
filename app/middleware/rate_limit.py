"""Shared per-client request and expensive-operation budgets."""
import hashlib
import logging
from urllib.parse import urlsplit

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware

from app import runtime_store as store
from app.auth import find_api_key as _resolve
from app.config import get_settings
from app.database import SessionLocal
from app.errors import error_response

logger = logging.getLogger(__name__)

RATE_LIMITS = {'free': 10, 'premium': 60, 'corporate': 300, 'admin': 0}
WINDOW_SECONDS = 60


def consume(request):
    raw_key = request.headers.get('x-api-key')
    session = request.cookies.get('aegis_session')
    client = request.client.host if request.client else 'unknown'
    identity, tier = 'ip:' + client, 'free'
    if raw_key or session:
        with SessionLocal() as db:
            key = _resolve(db, raw_key, session)
            if key:
                identity, tier = 'user:' + str(key.user_id), key.role.value
    # IP cap also applies when an attacker rotates keys or submits invalid credentials.
    _, accepted = store.increment('rate:ip:' + hashlib.sha256(client.encode()).hexdigest(), ttl=60, limit=300)
    if not accepted:
        return False
    if request.method not in ('POST', 'PATCH', 'DELETE'):
        return True
    limit = RATE_LIMITS.get(tier, 10)
    if request.url.path.startswith('/api/v2/auth/recovery'):
        limit = 3
    if not limit:
        return True
    return store.increment('rate:cost:' + identity, ttl=60, limit=limit)[1]


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith('/api/'):
            return await call_next(request)
        if request.cookies.get('aegis_session') and not request.headers.get('x-api-key') and request.method in ('POST', 'PATCH', 'DELETE'):
            origin = request.headers.get('origin')
            allowed = set(get_settings().cors_allow_origins)
            if origin and urlsplit(origin).netloc != request.headers.get('host') and origin not in allowed:
                return error_response(403, 'İstek kaynağına izin verilmedi.', code='origin_not_allowed')
        try:
            accepted = await run_in_threadpool(consume, request)
        except Exception:
            logger.exception('Rate-limit store unavailable')
            return error_response(503, 'İstek bütçesi doğrulanamadı.')
        if not accepted:
            return error_response(429, 'Dakikalık işlem sınırına ulaştınız.', headers={'Retry-After': '60'})
        return await call_next(request)
