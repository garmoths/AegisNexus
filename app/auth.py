"""API key tabanlı kimlik doğrulama ve yetkilendirme.

Her istekte X-API-Key header'ı okunur, key_hash ile eşleşen aktif APIKey bulunur.
Role göre yetki ve rate-limit uygulanır.
"""
import hashlib
import secrets
from datetime import UTC, datetime

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import APIKey, User, UserRole, UserSession

# ── Yardımcı ──────────────────────────────────────────────

def _hash_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """Ham API key ve hash'ini üretir. (raw_key, key_hash, key_prefix)"""
    raw = f"aeg_{secrets.token_urlsafe(32)}"
    return raw, _hash_key(raw), raw[:8]


# ── API Key çözümleme ────────────────────────────────────

def _resolve(db, raw_key=None, session_token=None):
    query = db.query(APIKey).join(User, APIKey.user_id == User.id).filter(APIKey.is_active.is_(True), User.is_active.is_(True))
    if raw_key:
        return query.filter(APIKey.key_hash == _hash_key(raw_key)).first()
    if session_token:
        return (query.join(UserSession, UserSession.api_key_id == APIKey.id)
                .filter(UserSession.token_hash == _hash_key(session_token),
                        UserSession.expires_at > datetime.now(UTC)).first())
    return None


def resolve_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    aegis_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> APIKey:
    key = _resolve(db, x_api_key, aegis_session)
    if key is None:
        raise HTTPException(status_code=401, detail="Geçerli bir oturum veya API anahtarı gerekli.")
    key.last_used_at = datetime.now(UTC)
    db.commit()
    return key


def resolve_optional_api_key(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    aegis_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> APIKey | None:
    return _resolve(db, x_api_key, aegis_session)


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
