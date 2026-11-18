"""Auth endpoint'leri — API key tabanlı kayıt, giriş, anahtar rotasyonu.

Tüm endpoint'ler /api/v2/auth altında.
"""
import secrets
from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from app.auth import _hash_key, generate_api_key, resolve_api_key
from app.config import get_settings
from app.database import get_db
from app.models import APIKey, RecoveryToken, User, UserRole, UserSession

router = APIRouter(tags=["auth"])


# ── Pydantic şemaları ─────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    full_name: str | None = None
    # Public registration must never grant paid or administrative privileges.
    role: Literal[UserRole.free] = UserRole.free

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
def login(body: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
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

    api_key.last_used_at = datetime.now(UTC)
    db.commit()

    token = secrets.token_urlsafe(48)
    db.add(UserSession(token_hash=_hash_key(token), api_key_id=api_key.id, expires_at=datetime.now(UTC) + timedelta(hours=24)))
    db.commit()
    response.set_cookie('aegis_session', token, httponly=True, secure=request.url.scheme == 'https', samesite='strict', max_age=86400, path='/')
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
    db.query(UserSession).filter_by(api_key_id=api_key.id).delete()
    db.commit()

    return RotateKeyResponse(
        new_api_key=raw_key,
        message="Yeni API anahtarınız güvenli bir yerde saklayın. Eski anahtar devre dışı bırakıldı.",
    )


@router.post("/logout", response_model=MessageResponse)
def logout(request: Request, response: Response, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    token = request.cookies.get('aegis_session')
    if token:
        db.query(UserSession).filter_by(token_hash=_hash_key(token)).delete()
    else:
        api_key.is_active = False
    db.commit()
    response.delete_cookie('aegis_session', path='/')
    return MessageResponse(message='Oturum kapatıldı.')


@router.get('/me')
def me(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    user = db.get(User, api_key.user_id)
    return {'email': user.email, 'full_name': user.full_name, 'role': user.role.value}


class RecoveryRequest(BaseModel):
    email: EmailStr


class RecoveryComplete(BaseModel):
    token: str = Field(min_length=32, max_length=200)


@router.post('/recovery/request')
def recovery_request(body: RecoveryRequest, db: Session = Depends(get_db)):
    if not get_settings().recovery_mail_enabled:
        raise HTTPException(503, 'E-posta kurtarma servisi yapılandırılmadı. Yöneticiyle iletişime geçin.')
    user = db.query(User).filter_by(email=body.email, is_active=True).first()
    if user:
        from app.mailer import send_recovery
        token = secrets.token_urlsafe(48)
        entry = RecoveryToken(user_id=user.id, token_hash=_hash_key(token), expires_at=datetime.now(UTC) + timedelta(minutes=15))
        db.add(entry)
        try:
            send_recovery(body.email, token)
            db.commit()
        except Exception:
            db.rollback()
            raise HTTPException(503, 'Kurtarma e-postası gönderilemedi.')
    return {'message': 'Adres kayıtlıysa kurtarma kodu e-posta ile gönderildi.'}


@router.post('/recovery/complete')
def recovery_complete(body: RecoveryComplete, db: Session = Depends(get_db)):
    now = datetime.now(UTC)
    token = db.query(RecoveryToken).filter(RecoveryToken.token_hash == _hash_key(body.token), RecoveryToken.used_at.is_(None), RecoveryToken.expires_at > now).first()
    if token is None:
        raise HTTPException(400, 'Kurtarma kodu geçersiz veya süresi dolmuş.')
    # Conditional UPDATE also makes simultaneous redemption single-use.
    if db.query(RecoveryToken).filter_by(id=token.id, used_at=None).update({'used_at': now}) != 1:
        db.rollback()
        raise HTTPException(400, 'Kod zaten kullanıldı.')
    user = db.get(User, token.user_id)
    if not user.is_active:
        raise HTTPException(403, 'Hesap pasif.')
    keys = db.query(APIKey).filter_by(user_id=user.id).all()
    ids = [key.id for key in keys]
    if ids:
        db.query(UserSession).filter(UserSession.api_key_id.in_(ids)).delete(synchronize_session=False)
    for key in keys:
        key.is_active = False
    raw, hashed, prefix = generate_api_key()
    db.add(APIKey(user_id=user.id, key_hash=hashed, key_prefix=prefix, role=user.role, rate_limit_tier=user.role.value))
    db.commit()
    return {'api_key': raw, 'message': 'Yeni anahtarı kaydedin. Eski anahtarlar iptal edildi.'}
