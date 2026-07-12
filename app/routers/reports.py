"""Kullanıcı rapor endpoint'leri — Gemini analiz, rapor listesi, PDF indirme.

POST /api/v2/reports/analyze  — Kullanıcı metni → Gemini analiz
GET  /api/v2/reports           — Kullanıcının kendi raporları
GET  /api/v2/reports/{id}/pdf  — PDF indir (free: ayda 3, premium: sınırsız)
"""
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.auth import resolve_api_key, require_premium_or_above
from app.database import get_db
from app.models import APIKey, UserReport, UserRole

router = APIRouter(tags=["reports"])


class AnalyzeRequest(BaseModel):
    description: str

class AnalyzeResponse(BaseModel):
    id: int
    attack_type: str | None = None
    risk_score: int | None = None
    protection_plan: str | None = None
    ai_analysis: dict | None = None
    message: str


# ── PDF quota ─────────────────────────────────────────────

FREE_MONTHLY_PDF_QUOTA = 3


def _check_pdf_quota(api_key: APIKey, db: Session) -> bool:
    if api_key.role in (UserRole.premium, UserRole.corporate, UserRole.admin):
        return True
    now = datetime.now(timezone.utc)
    month_key = f"{now.year}-{now.month:02d}"
    used = (
        db.query(func.count(UserReport.id))
        .filter(
            UserReport.user_id == api_key.user_id,
            UserReport.report_quota_month == month_key,
            UserReport.pdf_path.isnot(None),
        )
        .scalar()
    )
    return used < FREE_MONTHLY_PDF_QUOTA


# ── Endpoint'ler ──────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse, summary="Kullanıcı anlatımını Gemini ile analiz et")
def analyze_report(body: AnalyzeRequest, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    """Kullanıcının anlattığı olayı Gemini analiz eder, korunma planı üretir."""
    try:
        from modules.victim_atlas.gemini_service import analyze_user_report
        result = analyze_user_report(body.description)
    except ImportError:
        result = {
            "attack_type": "unknown",
            "risk_score": 50,
            "protection_plan": "Gemini servisi henüz yapılandırılmadı. Lütfen daha sonra tekrar deneyin.",
            "ai_analysis": {},
        }
    except Exception as e:
        result = {
            "attack_type": "error",
            "risk_score": 0,
            "protection_plan": f"Analiz sırasında hata oluştu: {str(e)[:200]}",
            "ai_analysis": {"error": str(e)},
        }

    now = datetime.now(timezone.utc)
    report = UserReport(
        user_id=api_key.user_id,
        user_description=body.description,
        ai_analysis=result.get("ai_analysis"),
        protection_plan=result.get("protection_plan"),
        report_quota_month=f"{now.year}-{now.month:02d}",
    )
    db.add(report)
    db.commit()

    return AnalyzeResponse(
        id=report.id,
        attack_type=result.get("attack_type"),
        risk_score=result.get("risk_score"),
        protection_plan=result.get("protection_plan"),
        ai_analysis=result.get("ai_analysis"),
        message="Analiz tamamlandı.",
    )


@router.get("/", summary="Kullanıcının raporlarını listele")
def list_reports(page: int = 1, limit: int = 20, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    offset = (max(1, page) - 1) * min(limit, 100)
    reports = (
        db.query(UserReport)
        .filter_by(user_id=api_key.user_id)
        .order_by(UserReport.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    total = db.query(func.count(UserReport.id)).filter_by(user_id=api_key.user_id).scalar()
    return {
        "data": [
            {
                "id": r.id,
                "user_description": r.user_description[:200],
                "attack_type": (r.ai_analysis or {}).get("attack_type"),
                "risk_score": (r.ai_analysis or {}).get("risk_score"),
                "protection_plan": r.protection_plan[:200] if r.protection_plan else None,
                "has_pdf": bool(r.pdf_path),
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reports
        ],
        "page": page,
        "total": total,
    }


@router.get("/{report_id}/pdf", summary="Rapor PDF indir")
def download_pdf(report_id: int, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    report = db.query(UserReport).filter_by(id=report_id, user_id=api_key.user_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Rapor bulunamadı.")

    if not _check_pdf_quota(api_key, db):
        raise HTTPException(
            status_code=429,
            detail=f"Ücretsiz plan için aylık PDF limiti ({FREE_MONTHLY_PDF_QUOTA}) doldu. Premium'a geçin.",
        )

    if not report.pdf_path:
        # PDF henüz üretilmemişse stub döner
        raise HTTPException(
            status_code=404,
            detail="PDF henüz üretilmedi. Lütfen bir süre sonra tekrar deneyin.",
        )

    pdf_file = Path(report.pdf_path)
    if not pdf_file.exists():
        raise HTTPException(status_code=404, detail="PDF dosyası bulunamadı.")

    from fastapi.responses import FileResponse
    return FileResponse(pdf_file, media_type="application/pdf", filename=f"rapor_{report_id}.pdf")
