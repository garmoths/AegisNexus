"""API key tabanlı kimlik doğrulama ve yetkilendirme.

Her istekte X-API-Key header'ı okunur, key_hash ile eşleşen aktif APIKey bulunur.
Role göre yetki ve rate-limit uygulanır.
"""
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_db
from app.models import APIKey, User, UserRole


# ── Yardımcı ──────────────────────────────────────────────

def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Ham API key ve hash'ini üretir. (raw_key, key_hash, key_prefix)"""
    raw = f"aeg_{secrets.token_urlsafe(32)}"
    return raw, _hash_key(raw), raw[:8]


# ── API Key çözümleme ────────────────────────────────────

def resolve_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> APIKey:
    """X-API-Key header'ından APIKey objesini çöz.
    401 dönerse key yok/yanlış/pasif demektir.
    """
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="X-API-Key header gerekli.",
        )
    key_hash = _hash_key(x_api_key)
    api_key = db.query(APIKey).filter_by(key_hash=key_hash, is_active=True).first()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz veya devre dışı API anahtarı.",
        )
    # last_used_at güncelle
    api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return api_key


def resolve_optional_api_key(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    db: Session = Depends(get_db),
) -> Optional[APIKey]:
    """Opsiyonel — key varsa çöz, yoksa None döner."""
    if not x_api_key:
        return None
    key_hash = _hash_key(x_api_key)
    return db.query(APIKey).filter_by(key_hash=key_hash, is_active=True).first()


# ── Rol bazlı yetki ──────────────────────────────────────

def require_role(*roles: UserRole):
    """Belirli rolleri gerektiren dependency fabrikası."""
    def _check(api_key: APIKey = Depends(resolve_api_key)) -> APIKey:
        if api_key.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Bu işlem için '{', '.join(r.value for r in roles)}' rolü gerekli.",
            )
        return api_key
    return _check


require_admin = require_role(UserRole.admin)
require_premium_or_above = require_role(UserRole.premium, UserRole.corporate, UserRole.admin)
require_corporate_or_above = require_role(UserRole.corporate, UserRole.admin)
