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
from app.models import APIKey, User, UserRole

router = APIRouter(tags=["admin"])


class RoleChangeRequest(BaseModel):
    role: UserRole


@router.get("/users", summary="Kullanıcı listesi (admin)")
def list_users(page: int = 1, limit: int = 50, api_key: APIKey = Depends(require_admin), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 100))
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
