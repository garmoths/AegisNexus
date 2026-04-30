from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth import require_admin, resolve_api_key, resolve_optional_api_key
from app.database import SessionLocal, get_db
from app.models import APIKey, VictimCase
from app.security import require_admin_api_key

from .database import ensure_initialized, get_case, get_cases, get_ingest_health, get_stats
from .ingest import run_daily_pipeline, run_hotset_maintenance

router = APIRouter(tags=["07-victim-atlas"])


# ── Pydantic şemaları ─────────────────────────────────────

class CaseCreateRequest(BaseModel):
    case_title: str
    attack_method: str
    loss_type: str
    target_platform: str = "web"
    critical_warning: str
    narrative_summary: str
    defense_steps: list[str]
    confidence_score: int = 70
    severity_score: int = 50
    region: str | None = None

class CasePatchRequest(BaseModel):
    case_title: str | None = None
    attack_method: str | None = None
    loss_type: str | None = None
    target_platform: str | None = None
    critical_warning: str | None = None
    narrative_summary: str | None = None
    defense_steps: list[str] | None = None
    confidence_score: int | None = None
    severity_score: int | None = None
    region: str | None = None
    is_published: bool | None = None


# ── Public endpoint'ler ───────────────────────────────────

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
    region: str | None = None,
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
    # Region filtresi (DB fonksiyonuna eklenmemişse burada uygula)
    if region and payload.get("data"):
        payload["data"] = [c for c in payload["data"] if c.get("region") == region]
        payload["total"] = len(payload["data"])
        payload["total_pages"] = max(1, (payload["total"] + limit - 1) // limit)
    payload["module"] = "07_victim_atlas"
    return payload


@router.get("/cases/{case_id}")
def get_case_detail(case_id: int):
    ensure_initialized()
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Vaka bulunamadı.")
    return {"data": case, "module": "07_victim_atlas"}


@router.get("/cases/{case_id}/protection-card", summary="Gemini korunma kartı üret")
def get_protection_card(case_id: int, api_key: APIKey = Depends(resolve_api_key)):
    """Vaka için kişiselleştirilmiş Gemini korunma kartı."""
    ensure_initialized()
    case = get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Vaka bulunamadı.")
    try:
        from modules.victim_atlas.gemini_service import generate_protection_card
        card = generate_protection_card(case)
        return {"data": card, "module": "07_victim_atlas"}
    except ImportError:
        return {"data": {"message": "Gemini servisi henüz yapılandırılmadı."}, "module": "07_victim_atlas"}


# ── Admin endpoint'leri ───────────────────────────────────

@router.post("/cases", status_code=status.HTTP_201_CREATED, summary="Yeni vaka ekle (admin)")
def create_case(body: CaseCreateRequest, _: None = Depends(require_admin_api_key), db: Session = Depends(get_db)):
    from .database import upsert_case
    slug = body.case_title.lower().replace(" ", "-")[:60] + f"-{int(datetime.now(timezone.utc).timestamp())}"
    case_data = {
        "case_slug": slug,
        "case_title": body.case_title,
        "attack_method": body.attack_method,
        "loss_type": body.loss_type,
        "target_platform": body.target_platform,
        "critical_warning": body.critical_warning,
        "narrative_summary": body.narrative_summary,
        "defense_steps": body.defense_steps,
        "confidence_score": body.confidence_score,
        "severity_score": body.severity_score,
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    case_id, created = upsert_case(case_data)
    # Region güncelle
    if body.region:
        case = db.query(VictimCase).get(case_id)
        if case:
            case.region = body.region
            db.commit()
    return {"data": {"id": case_id, "created": created}, "module": "07_victim_atlas"}


@router.patch("/cases/{case_id}", summary="Vaka güncelle (admin)")
def patch_case(case_id: int, body: CasePatchRequest, _: None = Depends(require_admin_api_key), db: Session = Depends(get_db)):
    case = db.query(VictimCase).get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Vaka bulunamadı.")
    update_data = body.model_dump(exclude_unset=True)
    if "defense_steps" in update_data:
        case.defense_steps_json = update_data.pop("defense_steps")
    for key, value in update_data.items():
        setattr(case, key, value)
    case.updated_at = datetime.now(timezone.utc)
    db.commit()
    return {"data": {"id": case_id, "updated": True}, "module": "07_victim_atlas"}


# ── İstatistik ve ingest ─────────────────────────────────

@router.get("/stats")
def victim_atlas_stats():
    ensure_initialized()
    return {"stats": get_stats(), "module": "07_victim_atlas"}


@router.get("/stats/overview", summary="Genel istatistik bakışı")
def stats_overview(api_key: APIKey = Depends(resolve_optional_api_key), db: Session = Depends(get_db)):
    from app.routers.stats import stats_overview as _impl
    return _impl(api_key=api_key, db=db)


@router.get("/stats/heatmap", summary="İl bazlı vaka yoğunluğu (GeoJSON)")
def stats_heatmap(api_key: APIKey = Depends(resolve_optional_api_key), db: Session = Depends(get_db)):
    from app.routers.stats import stats_heatmap as _impl
    return _impl(api_key=api_key, db=db)


@router.get("/stats/weekly-digest", summary="Haftalık bülten")
def stats_weekly_digest(api_key: APIKey = Depends(resolve_optional_api_key), db: Session = Depends(get_db)):
    from app.routers.stats import stats_weekly_digest as _impl
    return _impl(api_key=api_key, db=db)


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
