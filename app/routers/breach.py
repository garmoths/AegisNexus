from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.breach_intel import lookup_breaches

router = APIRouter(tags=["breach"])


class BreachRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=320)


@router.post("/api/breach/lookup")
def breach_lookup(body: BreachRequest):
    return lookup_breaches(body.email)
