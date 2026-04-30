"""Auth endpoint'leri — API key tabanlı kayıt, giriş, anahtar rotasyonu.

Tüm endpoint'ler /api/v2/auth altında.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.auth import generate_api_key, _hash_key, resolve_api_key, require_admin
from app.database import SessionLocal, get_db
from app.models import APIKey, User, UserRole

router = APIRouter(tags=["auth"])


# ── Pydantic şemaları ─────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str | None = None
    role: UserRole = UserRole.free

class RegisterResponse(BaseModel):
    email: str
    api_key: str
    role: str
    message: str

class LoginRequest(BaseModel):
    email: EmailStr
    api_key: str

class LoginResponse(BaseModel):
    email: str
    role: str
    is_active: bool

class RotateKeyResponse(BaseModel):
    new_api_key: str
    message: str

class MessageResponse(BaseModel):
    message: str


# ── Endpoint'ler ──────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse, summary="Yeni kullanıcı kaydı")
def register(body: RegisterRequest, db: Session = Depends(get_db)):
    """Email ile kaydol, API key al. Şifre yok."""
    existing = db.query(User).filter_by(email=body.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Bu e-posta adresi zaten kayıtlı.",
        )

    user = User(email=body.email, full_name=body.full_name, role=body.role)
    db.add(user)
    db.flush()

    raw_key, key_hash, key_prefix = generate_api_key()
    api_key = APIKey(
        user_id=user.id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        label="Varsayılan",
        role=body.role,
        rate_limit_tier=body.role.value,
    )
    db.add(api_key)
    db.commit()

    return RegisterResponse(
        email=user.email,
        api_key=raw_key,
        role=user.role.value,
        message="API anahtarınız güvenli bir yerde saklayın. Tekrar gösterilmeyecek.",
    )


@router.post("/login", response_model=LoginResponse, summary="API key ile giriş")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    """Email + API key doğrula, rol döner."""
    user = db.query(User).filter_by(email=body.email, is_active=True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kullanıcı bulunamadı veya hesap pasif.",
        )

    key_hash = _hash_key(body.api_key)
    api_key = db.query(APIKey).filter_by(
        user_id=user.id, key_hash=key_hash, is_active=True
    ).first()
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz API anahtarı.",
        )

    api_key.last_used_at = datetime.now(timezone.utc)
    db.commit()

    return LoginResponse(email=user.email, role=user.role.value, is_active=user.is_active)


@router.post("/rotate-key", response_model=RotateKeyResponse, summary="API anahtarını yenile")
def rotate_key(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """Mevcut key ile yeni key üret, eskiyi deaktif et."""
    raw_key, key_hash, key_prefix = generate_api_key()
    new_key = APIKey(
        user_id=api_key.user_id,
        key_hash=key_hash,
        key_prefix=key_prefix,
        label=f"Rotated from {api_key.key_prefix}",
        role=api_key.role,
        rate_limit_tier=api_key.rate_limit_tier,
    )
    db.add(new_key)

    api_key.is_active = False
    db.commit()

    return RotateKeyResponse(
        new_api_key=raw_key,
        message="Yeni API anahtarınız güvenli bir yerde saklayın. Eski anahtar devre dışı bırakıldı.",
    )


@router.post("/logout", response_model=MessageResponse, summary="API anahtarını devre dışı bırak")
def logout(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """Aktif API key'i deaktif et."""
    api_key.is_active = False
    db.commit()
    return MessageResponse(message="API anahtarı devre dışı bırakıldı.")
