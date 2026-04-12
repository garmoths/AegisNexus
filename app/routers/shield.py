from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.password_shield import generate_password

router = APIRouter(tags=["shield"])


class PasswordRequest(BaseModel):
    length: int = Field(20, ge=8, le=128)
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    symbols: bool = True


@router.post("/api/shield/password")
def shield_password(body: PasswordRequest):
    pwd, meta = generate_password(
        body.length,
        uppercase=body.uppercase,
        lowercase=body.lowercase,
        digits=body.digits,
        symbols=body.symbols,
    )
    return {"password": pwd, "meta": meta}
