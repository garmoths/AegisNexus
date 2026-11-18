"""Authentication and authorization — one model for the whole API.

A request is authenticated by either
  * an ``X-API-Key`` header (programmatic clients), or
  * the ``aegis_session`` HttpOnly cookie issued by ``POST /api/v2/auth/login``.

Both resolve to an active :class:`~app.models.APIKey` whose ``role`` drives
authorization (``free`` < ``premium`` < ``corporate`` < ``admin``). Raw keys and
session tokens are never stored, only their SHA-256 hashes. Admin accounts are
created with ``make create-admin`` (``python -m app.cli create-admin``).
"""
from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import APIKey, User, UserRole, UserSession

SESSION_COOKIE = 'aegis_session'


def hash_secret(raw: str) -> str:
    """SHA-256 hex digest used for API keys, session and recovery tokens.

    The secrets are 256-bit random values, so a fast hash is appropriate (no
    password stretching needed) and lookups stay indexable.
    """
    return hashlib.sha256(raw.encode()).hexdigest()


# Backwards-compatible alias used by older call sites and tests.
_hash_key = hash_secret


def generate_api_key() -> tuple[str, str, str]:
    """Return ``(raw_key, key_hash, key_prefix)`` for a new API key."""
    raw = f"aeg_{secrets.token_urlsafe(32)}"
    return raw, hash_secret(raw), raw[:8]


def find_api_key(db: Session, raw_key: str | None = None, session_token: str | None = None) -> APIKey | None:
    """Resolve an API key or a live session token to its active key (or ``None``)."""
    query = (db.query(APIKey).join(User, APIKey.user_id == User.id)
             .filter(APIKey.is_active.is_(True), User.is_active.is_(True)))
    if raw_key:
        return query.filter(APIKey.key_hash == hash_secret(raw_key)).first()
    if session_token:
        return (query.join(UserSession, UserSession.api_key_id == APIKey.id)
                .filter(UserSession.token_hash == hash_secret(session_token),
                        UserSession.expires_at > datetime.now(UTC)).first())
    return None


_resolve = find_api_key  # kept for existing imports


def resolve_api_key(
    x_api_key: str | None = Header(default=None, alias='X-API-Key'),
    aegis_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> APIKey:
    """Dependency: the authenticated principal, or 401."""
    key = find_api_key(db, x_api_key, aegis_session)
    if key is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Geçerli bir oturum veya API anahtarı gerekli.')
    key.last_used_at = datetime.now(UTC)
    db.commit()
    return key


def resolve_optional_api_key(
    x_api_key: str | None = Header(default=None, alias='X-API-Key'),
    aegis_session: str | None = Cookie(default=None),
    db: Session = Depends(get_db),
) -> APIKey | None:
    """Dependency: the principal if one was supplied, otherwise ``None`` (anonymous)."""
    return find_api_key(db, x_api_key, aegis_session)


def require_role(*roles: UserRole):
    """Dependency factory: 403 unless the principal has one of ``roles``."""
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
