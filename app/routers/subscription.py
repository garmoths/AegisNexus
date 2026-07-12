"""Abonelik endpoint'leri — mevcut plan, upgrade (stub).

GET  /api/v2/subscription/me       — Mevcut plan bilgisi
POST /api/v2/subscription/upgrade  — Plan yükseltme (mock/İyzico stub)
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import resolve_api_key
from app.database import get_db
from app.models import APIKey, Subscription, UserRole

router = APIRouter(tags=["subscription"])


class UpgradeRequest(BaseModel):
    plan: UserRole  # premium veya corporate

class UpgradeResponse(BaseModel):
    status: str
    message: str
    plan: str | None = None


# ── Plan ücretleri (stub) ─────────────────────────────────

PLAN_PRICES = {
    UserRole.premium: {"monthly_try": 99, "label": "Premium"},
    UserRole.corporate: {"monthly_try": 499, "label": "Kurumsal"},
}


@router.get("/me", summary="Mevcut abonelik bilgisi")
def subscription_me(api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    sub = (
        db.query(Subscription)
        .filter_by(user_id=api_key.user_id, is_active=True)
        .order_by(Subscription.id.desc())
        .first()
    )
    return {
        "role": api_key.role.value,
        "plan": sub.plan.value if sub else api_key.role.value,
        "started_at": sub.started_at.isoformat() if sub and sub.started_at else None,
        "expires_at": sub.expires_at.isoformat() if sub and sub.expires_at else None,
        "is_active": sub.is_active if sub else False,
    }


@router.post("/upgrade", response_model=UpgradeResponse, summary="Plan yükselt (mock)")
def subscription_upgrade(body: UpgradeRequest, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """İyzico entegrasyonu stub — gerçek ödeme henüz yok."""
    if body.plan not in (UserRole.premium, UserRole.corporate):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Yükseltme için 'premium' veya 'corporate' plan seçilmeli.",
        )

    if api_key.role in (UserRole.admin,) or (api_key.role == UserRole.corporate and body.plan == UserRole.premium):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mevcut planınızdan daha düşük bir plan seçemezsiniz.",
        )

    price_info = PLAN_PRICES.get(body.plan, {})

    return UpgradeResponse(
        status="pending",
        message=f"Ödeme sistemi yakında aktif olacak. {price_info.get('label', body.plan.value)} plan ({price_info.get('monthly_try', '?')} TL/ay) için support@example.com adresine yazın.",
        plan=body.plan.value,
    )
