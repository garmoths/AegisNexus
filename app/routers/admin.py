"""Admin endpoint'leri — toplu sınıflandırma, kullanıcı yönetimi, rol değiştirme.

POST /api/v2/admin/classify           — Gemini ile toplu sınıflandırma
GET  /api/v2/admin/users              — Kullanıcı listesi
PATCH /api/v2/admin/users/{user_id}   — Kullanıcı rol değiştirme
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth import require_admin
from app.database import get_db
from app.models import APIKey, User, UserRole, VictimCase

router = APIRouter(tags=["admin"])


class RoleChangeRequest(BaseModel):
    role: UserRole


@router.post("/classify", summary="Gemini ile toplu sınıflandırma (admin)")
def classify_pending_cases(api_key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    """Sınıflandırılmamış veya güncellenmesi gereken vakaları Gemini ile sınıflandır."""
    pending = (
        db.query(VictimCase)
        .filter_by(is_published=False)
        .order_by(VictimCase.id.desc())
        .limit(50)
        .all()
    )

    classified = 0
    errors = 0

    try:
        from modules.victim_atlas.gemini_service import classify_case
        for case in pending:
            try:
                result = classify_case(case.narrative_summary)
                if result.get("attack_method"):
                    case.attack_method = result["attack_method"]
                if result.get("loss_type"):
                    case.loss_type = result["loss_type"]
                if result.get("severity"):
                    case.severity_score = int(result["severity"])
                if result.get("confidence"):
                    case.confidence_score = int(result["confidence"])
                if result.get("tags"):
                    from app.models import CaseTag
                    for tag in result["tags"][:5]:
                        db.add(CaseTag(case_id=case.id, tag=tag))
                if result.get("region"):
                    case.region = result["region"]
                case.is_published = True
                classified += 1
            except Exception:
                errors += 1
        db.commit()
    except ImportError:
        return {
            "classified": 0,
            "errors": 0,
            "message": "Gemini servisi henüz yapılandırılmadı.",
        }

    return {
        "classified": classified,
        "errors": errors,
        "total_pending": len(pending),
    }


@router.get("/users", summary="Kullanıcı listesi (admin)")
def list_users(page: int = 1, limit: int = 50, api_key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    limit = min(limit, 100)
    offset = (max(1, page) - 1) * limit

    users = db.query(User).order_by(User.id.asc()).offset(offset).limit(limit).all()
    total = db.query(func.count(User.id)).scalar()

    return {
        "data": [
            {
                "id": u.id,
                "email": u.email,
                "full_name": u.full_name,
                "role": u.role.value,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in users
        ],
        "page": page,
        "total": total,
    }


@router.patch("/users/{user_id}", summary="Kullanıcı rol değiştirme (admin)")
def change_user_role(user_id: int, body: RoleChangeRequest, api_key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    user = db.query(User).get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı.")

    old_role = user.role.value
    user.role = body.role
    # Kullanıcının aktif API key'lerinin rolünü de güncelle
    active_keys = db.query(APIKey).filter_by(user_id=user.id, is_active=True).all()
    for key in active_keys:
        key.role = body.role
        key.rate_limit_tier = body.role.value
    db.commit()

    return {
        "id": user.id,
        "email": user.email,
        "old_role": old_role,
        "new_role": body.role.value,
        "api_keys_updated": len(active_keys),
    }
