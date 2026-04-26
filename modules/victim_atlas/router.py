from fastapi import APIRouter, Depends, HTTPException

from app.security import require_admin_api_key

from .database import ensure_initialized, get_case, get_cases, get_ingest_health, get_stats
from .ingest import run_daily_pipeline, run_hotset_maintenance

router = APIRouter(tags=["07-victim-atlas"])


@router.get("/cases")
def list_cases(
    page: int = 1,
    limit: int = 20,
    attack_method: str | None = None,
    loss_type: str | None = None,
    severity_min: int = 0,
    confidence_min: int = 60,
    q: str | None = None,
    hot_set_only: bool = True,
):
    ensure_initialized()
    payload = get_cases(
        page=page,
        limit=limit,
        attack_method=attack_method,
        loss_type=loss_type,
        severity_min=severity_min,
        confidence_min=confidence_min,
        q=q,
        hot_set_only=hot_set_only,
    )
    payload["module"] = "07_victim_atlas"
    return payload


@router.get("/cases/{case_id}")
def get_case_detail(case_id: int):
    ensure_initialized()
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"data": case, "module": "07_victim_atlas"}


@router.get("/stats")
def victim_atlas_stats():
    ensure_initialized()
    return {"stats": get_stats(), "module": "07_victim_atlas"}


@router.get("/ingest/health")
def ingest_health(_: None = Depends(require_admin_api_key)):
    ensure_initialized()
    return {"health": get_ingest_health(), "module": "07_victim_atlas"}


@router.post("/ingest/run")
def run_ingest(_: None = Depends(require_admin_api_key)):
    ensure_initialized()
    return {"result": run_daily_pipeline(), "module": "07_victim_atlas"}


@router.post("/ingest/prune")
def run_prune(_: None = Depends(require_admin_api_key)):
    ensure_initialized()
    return {"result": run_hotset_maintenance(), "module": "07_victim_atlas"}
