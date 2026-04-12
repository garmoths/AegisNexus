from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.infra_report import build_infra_report

router = APIRouter(tags=["infra"])


class InfraRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


@router.post("/api/infra/report")
def infra_report(body: InfraRequest):
    return build_infra_report(body.url)
