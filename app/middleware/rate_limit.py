"""API rate limiting middleware — rol bazlı istek sınırlaması.

Her API key için dakikada izin verilen istek sayısı:
  free:       10/dk
  premium:    60/dk
  corporate: 300/dk
  admin:    sınırsız
"""
import time
from collections import defaultdict
from typing import Dict, Tuple

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.database import SessionLocal
from app.models import APIKey, UserRole

RATE_LIMITS: Dict[str, int] = {
    "free": 10,
    "premium": 60,
    "corporate": 300,
    "admin": 0,  # sınırsız
}

# key_prefix → (window_start, count)
_windows: Dict[str, Tuple[float, int]] = defaultdict(lambda: (0.0, 0))
WINDOW_SECONDS = 60


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        raw_key = request.headers.get("x-api-key") or request.headers.get("X-API-Key")
        if not raw_key:
            # Key yoksa rate limit uygulanmaz (public endpoint'ler)
            return await call_next(request)

        import hashlib
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()

        with SessionLocal() as db:
            api_key = db.query(APIKey).filter_by(key_hash=key_hash, is_active=True).first()
            if not api_key:
                return await call_next(request)

            tier = api_key.rate_limit_tier or api_key.role.value
            limit = RATE_LIMITS.get(tier, 10)

            if limit == 0:
                # Admin — sınırsız
                return await call_next(request)

            prefix = api_key.key_prefix
            now = time.time()
            window_start, count = _windows[prefix]

            if now - window_start > WINDOW_SECONDS:
                _windows[prefix] = (now, 1)
            else:
                count += 1
                _windows[prefix] = (window_start, count)

                if count > limit:
                    return Response(
                        content='{"detail":"Dakikalık istek limitini aştınız. Lütfen bekleyin.","error":"rate_limit"}',
                        status_code=429,
                        media_type="application/json",
                        headers={"Retry-After": str(WINDOW_SECONDS)},
                    )

        return await call_next(request)
