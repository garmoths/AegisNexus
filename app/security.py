import hmac
import os

from fastapi import Header, HTTPException


def require_admin_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """
    Minimal admin protection for mutating/high-cost endpoints.
    Clients must send X-API-Key header matching ADMIN_API_KEY.
    """
    expected = (os.getenv("ADMIN_API_KEY") or "").strip()
    if not expected:
        raise HTTPException(status_code=503, detail="ADMIN_API_KEY is not configured")
    if not x_api_key or not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(status_code=401, detail="Invalid API key")
