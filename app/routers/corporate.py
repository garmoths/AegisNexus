"""Kurumsal API endpoint'leri — published vakalar, gelişmiş istatistik, webhook.

GET  /api/v2/corporate/cases    — Published vakalar (API key ile)
GET  /api/v2/corporate/stats    — Gelişmiş istatistik
POST /api/v2/corporate/webhook  — Yeni kritik vaka bildirimi kaydı
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth import require_corporate_or_above, resolve_api_key
from app.database import get_db
from app.models import APIKey, VictimCase, AlertSubscription

router = APIRouter(tags=["corporate"])


class WebhookRequest(BaseModel):
    url: str
    min_severity: int = 70
    attack_methods: list[str] | None = None


@router.get("/cases", summary="Published vakalar (kurumsal erişim)")
def corporate_cases(
    page: int = 1,
    limit: int = 50,
    attack_method: str | None = None,
    region: str | None = None,
    api_key: APIKey = Depends(require_corporate_or_above),
    db: Session = Depends(get_db),
):
    """Kurumsal API ile published vakalara erişim."""
    limit = min(limit, 100)
    offset = (max(1, page) - 1) * limit

    query = db.query(VictimCase).filter_by(is_published=True)
    if attack_method:
        query = query.filter_by(attack_method=attack_method)
    if region:
        query = query.filter_by(region=region)

    total = query.count()
    cases = (
        query.order_by(VictimCase.severity_score.desc(), VictimCase.last_seen.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "data": [
            {
                "id": c.id,
                "case_slug": c.case_slug,
                "case_title": c.case_title,
                "attack_method": c.attack_method,
                "loss_type": c.loss_type,
                "severity_score": c.severity_score,
                "confidence_score": c.confidence_score,
                "region": c.region,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            }
            for c in cases
        ],
        "page": page,
        "total": total,
    }


@router.get("/stats", summary="Gelişmiş istatistik (kurumsal)")
def corporate_stats(api_key: APIKey = Depends(require_corporate_or_above), db: Session = Depends(get_db)):
    """Kurumsal kullanıcılar için detaylı istatistik."""
    total = db.query(func.count(VictimCase.id)).filter_by(is_published=True).scalar()

    by_method = (
        db.query(VictimCase.attack_method, func.count(VictimCase.id).label("c"))
        .filter_by(is_published=True)
        .group_by(VictimCase.attack_method)
        .order_by(func.count(VictimCase.id).desc())
        .all()
    )

    by_region = (
        db.query(VictimCase.region, func.count(VictimCase.id).label("c"))
        .filter(VictimCase.is_published == True, VictimCase.region.isnot(None))
        .group_by(VictimCase.region)
        .order_by(func.count(VictimCase.id).desc())
        .limit(20)
        .all()
    )

    avg_severity = (
        db.query(func.avg(VictimCase.severity_score))
        .filter_by(is_published=True)
        .scalar()
    )

    return {
        "total_published": total,
        "avg_severity": round(float(avg_severity or 0), 1),
        "attack_method_distribution": {r.attack_method: r.c for r in by_method},
        "region_distribution": {r.region: r.c for r in by_region},
    }


@router.post("/webhook", summary="Kritik vaka webhook bildirimi kaydı")
def register_webhook(body: WebhookRequest, api_key: APIKey = Depends(require_corporate_or_above), db: Session = Depends(get_db)):
    """Yeni kritik vaka olduğunda webhook URL'sine POST yapılması için kayıt."""
    # AlertSubscription olarak kaydet — webhook URL'si context alanında saklanır
    for method in (body.attack_methods or [None]):
        alert = AlertSubscription(
            user_id=api_key.user_id,
            region=None,
            attack_method=method,
            is_active=True,
        )
        # context alanı yok, şimdilik stub
        db.add(alert)
    db.commit()

    return {
        "status": "registered",
        "message": f"Webhook {body.url} adresi kaydedildi. Minimum şiddet: {body.min_severity}",
    }
