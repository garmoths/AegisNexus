import hashlib
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, constr
from sqlalchemy.orm import Session

from app.auth import require_admin, resolve_api_key, resolve_optional_api_key
from app.database import SessionLocal, get_db
from app.models import APIKey, CaseComment, VictimCase
from app.security import require_admin_api_key

from .database import ensure_initialized, get_case, get_cases, get_ingest_health, get_stats
from .ingest import run_daily_pipeline, run_hotset_maintenance

router = APIRouter(tags=["07-victim-atlas"])

POPULATION_WEIGHTED_DEMO_REGIONS = [
    ("İstanbul", 15655924), ("Ankara", 5782285), ("İzmir", 4479525), ("Bursa", 3214571),
    ("Antalya", 2696884), ("Konya", 2320794), ("Adana", 2270298), ("Şanlıurfa", 2213964),
    ("Gaziantep", 2154051), ("Kocaeli", 2102907), ("Mersin", 1938389), ("Diyarbakır", 1818805),
    ("Hatay", 1544640), ("Manisa", 1475716), ("Kayseri", 1441523), ("Samsun", 1376964),
    ("Balıkesir", 1273686), ("Kahramanmaraş", 1116618), ("Van", 1127612), ("Aydın", 1161430),
    ("Tekirdağ", 1167359), ("Denizli", 1059079), ("Sakarya", 1098259), ("Muğla", 1066257),
    ("Eskişehir", 915418), ("Mardin", 888874), ("Trabzon", 824352), ("Malatya", 742725),
    ("Ordu", 763190), ("Erzurum", 749993), ("Afyonkarahisar", 751344), ("Sivas", 650401),
    ("Adıyaman", 604978), ("Tokat", 606934), ("Zonguldak", 591492), ("Elazığ", 604411),
    ("Kütahya", 575674), ("Batman", 647205), ("Osmaniye", 559405), ("Çanakkale", 570499),
    ("Şırnak", 557605), ("Ağrı", 511238), ("Giresun", 461712), ("Isparta", 449777),
    ("Yozgat", 420699), ("Edirne", 419913), ("Aksaray", 438504), ("Kastamonu", 388990),
    ("Düzce", 409865), ("Niğde", 377080), ("Uşak", 377001), ("Bitlis", 353988),
    ("Rize", 350506), ("Amasya", 339529), ("Siirt", 347412), ("Bolu", 324789),
    ("Nevşehir", 315994), ("Kars", 274829), ("Kırklareli", 377156), ("Bingöl", 282556),
    ("Hakkari", 287625), ("Karaman", 263960), ("Kırıkkale", 283053), ("Burdur", 277452),
    ("Karabük", 255242), ("Kırşehir", 244519), ("Erzincan", 243399), ("Bilecik", 228673),
    ("Sinop", 229716), ("Iğdır", 209738), ("Bartın", 207238), ("Çankırı", 195766),
    ("Artvin", 172356), ("Gümüşhane", 148539), ("Kilis", 155179), ("Ardahan", 92319),
    ("Tunceli", 89886), ("Bayburt", 86274), ("Yalova", 304780),
]


def _deterministic_demo_region(case: VictimCase) -> str:
    total_weight = sum(weight for _, weight in POPULATION_WEIGHTED_DEMO_REGIONS)
    digest = hashlib.sha256(f"{case.id}:{case.case_slug}:{case.attack_method}".encode("utf-8")).hexdigest()
    cursor = int(digest[:12], 16) % total_weight
    cumulative = 0
    for region, weight in POPULATION_WEIGHTED_DEMO_REGIONS:
        cumulative += weight
        if cursor < cumulative:
            return region
    return POPULATION_WEIGHTED_DEMO_REGIONS[0][0]


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


@router.post("/admin/fill-regions", summary="Gemini ile boş il alanlarını doldur (admin)")
def fill_missing_regions(
    limit: int = 50,
    _: None = Depends(require_admin_api_key),
    db: Session = Depends(get_db),
):
    """NULL region değeri olan vakaları Gemini'ye göndererek Türkiye ili tahmini yap."""
    try:
        from .gemini_service import _call_gemini, _extract_json
    except ImportError:
        raise HTTPException(status_code=503, detail="Gemini servisi kullanılamıyor.")

    TURKISH_CITIES = {
        "adana", "adıyaman", "afyonkarahisar", "ağrı", "amasya", "ankara", "antalya",
        "artvin", "aydın", "balıkesir", "bilecik", "bingöl", "bitlis", "bolu", "burdur",
        "bursa", "çanakkale", "çankırı", "çorum", "denizli", "diyarbakır", "edirne",
        "elazığ", "erzincan", "erzurum", "eskişehir", "gaziantep", "giresun", "gümüşhane",
        "hakkari", "hatay", "isparta", "mersin", "istanbul", "izmir", "kars", "kastamonu",
        "kayseri", "kırklareli", "kırşehir", "kocaeli", "konya", "kütahya", "malatya",
        "manisa", "kahramanmaraş", "mardin", "muğla", "muş", "nevşehir", "niğde",
        "ordu", "rize", "sakarya", "samsun", "siirt", "sinop", "sivas", "tekirdağ",
        "tokat", "trabzon", "tunceli", "şanlıurfa", "uşak", "van", "yozgat", "zonguldak",
        "aksaray", "bayburt", "karaman", "kırıkkale", "batman", "şırnak", "bartın",
        "ardahan", "iğdır", "yalova", "karabük", "kilis", "osmaniye", "düzce",
    }

    cases = (
        db.query(VictimCase)
        .filter(
            (VictimCase.region.is_(None)) | (VictimCase.region == ""),
            VictimCase.is_published.is_(True),
        )
        .order_by(VictimCase.id.desc())
        .limit(limit)
        .all()
    )
    if not cases:
        return {"updated": 0, "message": "Bölge atanmamış yayınlanmış vaka bulunamadı."}

    system = (
        "Sen Türkiye'deki siber dolandırıcılık vakalarını analiz eden bir uzmansın. "
        "Verilen vaka metninden Türkiye ilini tahmin et. "
        "Yalnızca JSON döndür: {\"region\": \"<il adı>\"} veya {\"region\": null} eğer il belirlenemiyorsa."
    )
    updated = 0
    errors = 0
    for case in cases:
        text = f"Başlık: {case.case_title}\nYöntem: {case.attack_method}\nÖzet: {case.narrative_summary[:300]}"
        try:
            raw = _call_gemini(system, text)
            result = _extract_json(raw)
            region = result.get("region")
            if region and isinstance(region, str):
                norm = region.strip().lower()
                # Türkiye ili doğrulama
                if any(norm in city or city in norm for city in TURKISH_CITIES):
                    case.region = region.strip().title()
                    updated += 1
        except Exception:
            errors += 1
            continue
    db.commit()
    return {"updated": updated, "errors": errors, "total_checked": len(cases), "module": "07_victim_atlas"}


@router.post("/admin/fill-regions-demo", summary="Boş il alanlarını deterministik demo verisiyle doldur (admin)")
def fill_missing_regions_demo(
    limit: int = 500,
    overwrite: bool = False,
    _: None = Depends(require_admin_api_key),
    db: Session = Depends(get_db),
):
    query = db.query(VictimCase).filter(VictimCase.is_published.is_(True))
    if not overwrite:
        query = query.filter((VictimCase.region.is_(None)) | (VictimCase.region == ""))

    cases = query.order_by(VictimCase.id.asc()).limit(max(1, min(int(limit), 2000))).all()
    updated = 0
    distribution: dict[str, int] = {}
    for case in cases:
        region = _deterministic_demo_region(case)
        case.region = region
        updated += 1
        distribution[region] = distribution.get(region, 0) + 1

    db.commit()
    return {
        "updated": updated,
        "total_checked": len(cases),
        "overwrite": overwrite,
        "distribution": distribution,
        "module": "07_victim_atlas",
    }


# ── Yorum endpoint'leri ───────────────────────────────────

class CommentRequest(BaseModel):
    nickname: str
    text: str


@router.get("/cases/{case_id}/comments")
def list_comments(case_id: int, db: Session = Depends(get_db)):
    comments = (
        db.query(CaseComment)
        .filter(CaseComment.case_id == case_id)
        .order_by(CaseComment.upvotes.desc(), CaseComment.created_at.desc())
        .limit(50)
        .all()
    )
    return {
        "data": [
            {
                "id": c.id,
                "nickname": c.nickname,
                "text": c.text,
                "upvotes": c.upvotes,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in comments
        ]
    }


@router.post("/cases/{case_id}/comments", status_code=status.HTTP_201_CREATED)
def add_comment(case_id: int, body: CommentRequest, request: Request, db: Session = Depends(get_db)):
    if not db.query(VictimCase).filter(VictimCase.id == case_id).first():
        raise HTTPException(status_code=404, detail="Vaka bulunamadı.")
    nickname = (body.nickname or "Anonim").strip()[:60]
    text = (body.text or "").strip()
    if len(text) < 5:
        raise HTTPException(status_code=422, detail="Yorum en az 5 karakter olmalı.")
    if len(text) > 1000:
        raise HTTPException(status_code=422, detail="Yorum en fazla 1000 karakter olabilir.")
    ip = request.client.host if request.client else "unknown"
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()
    comment = CaseComment(
        case_id=case_id,
        nickname=nickname,
        text=text,
        ip_hash=ip_hash,
        created_at=datetime.now(timezone.utc),
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    return {"data": {"id": comment.id, "nickname": comment.nickname}}


@router.post("/cases/{case_id}/comments/{comment_id}/upvote")
def upvote_comment(case_id: int, comment_id: int, db: Session = Depends(get_db)):
    comment = db.query(CaseComment).filter(
        CaseComment.id == comment_id, CaseComment.case_id == case_id
    ).first()
    if not comment:
        raise HTTPException(status_code=404, detail="Yorum bulunamadı.")
    comment.upvotes = (comment.upvotes or 0) + 1
    db.commit()
    return {"upvotes": comment.upvotes}
