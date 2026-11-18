"""Private reports, actionable cases and quota-accounted PDF exports."""
from datetime import UTC, datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import runtime_store as store
from app.auth import resolve_api_key
from app.config import get_settings
from app.database import get_db
from app.models import APIKey, EventOutbox, PDFDownload, UserReport, UserRole

router = APIRouter(tags=['reports'])
FREE_MONTHLY_PDF_QUOTA = 3


class AnalyzeRequest(BaseModel):
    description: str = Field(min_length=10, max_length=20000)


class ReportPatch(BaseModel):
    status: str = Field(pattern='^(open|in_progress|resolved)$')
    completed_steps: list[int] = Field(default_factory=list, max_length=30)


def serialize(report):
    return {'id': report.id, 'user_description': report.user_description,
            'attack_type': (report.ai_analysis or {}).get('attack_type'),
            'risk_score': (report.ai_analysis or {}).get('risk_score'),
            'protection_plan': report.protection_plan, 'ai_analysis': report.ai_analysis,
            'status': report.status, 'action_steps': report.action_steps,
            'pdf_status': report.pdf_status, 'has_pdf': bool(report.pdf_path),
            'created_at': report.created_at.isoformat() if report.created_at else None}


def owned(report_id, key, db):
    report = db.query(UserReport).filter_by(id=report_id, user_id=key.user_id).first()
    if report is None:
        raise HTTPException(404, 'Rapor bulunamadı.')
    return report


@router.post('/analyze')
def analyze_report(body: AnalyzeRequest, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    try:
        from modules.ai_analyzer.incident_analysis import analyze_user_report
        result = analyze_user_report(body.description)
    except Exception:
        raise HTTPException(503, 'Analiz kaynağı kullanılamıyor. Lütfen daha sonra tekrar deneyin.')
    # Keep the structured fields as well as raw model evidence; list/detail use the same schema.
    analysis = {**result.get('ai_analysis', {}), **{k: v for k, v in result.items() if k != 'ai_analysis'}}
    steps = [line.strip() for line in (result.get('protection_plan') or '').splitlines() if line.strip()]
    report = UserReport(user_id=api_key.user_id, user_description=body.description, ai_analysis=analysis,
                        protection_plan=result.get('protection_plan'), action_steps=[{'text': step, 'done': False} for step in steps[:30]],
                        pdf_status='pending')
    db.add(report)
    db.flush()
    db.add(EventOutbox(event='report.pdf_requested', payload={'report_id': report.id}))
    db.commit()
    return {**serialize(report), 'message': 'Analiz kaydedildi. PDF hazırlanıyor.'}


@router.get('/')
def list_reports(page: int = Query(1, ge=1), limit: int = Query(20, ge=1, le=100), api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    query = db.query(UserReport).filter_by(user_id=api_key.user_id)
    return {'data': [serialize(r) for r in query.order_by(UserReport.created_at.desc()).offset((page-1)*limit).limit(limit).all()],
            'total': query.count(), 'page': page}


@router.get('/{report_id}')
def report_detail(report_id: int, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    return serialize(owned(report_id, api_key, db))


@router.patch('/{report_id}')
def update_report(report_id: int, body: ReportPatch, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    report = owned(report_id, api_key, db)
    if any(i < 0 or i >= len(report.action_steps or []) for i in body.completed_steps):
        raise HTTPException(422, 'Geçersiz aksiyon adımı.')
    report.status = body.status
    report.action_steps = [{**step, 'done': i in body.completed_steps} for i, step in enumerate(report.action_steps or [])]
    db.commit()
    return serialize(report)


def _check_pdf_quota(api_key, db):
    if api_key.role in (UserRole.premium, UserRole.corporate, UserRole.admin):
        return True
    month = datetime.now(UTC).strftime('%Y-%m')
    return db.query(PDFDownload).filter_by(user_id=api_key.user_id, month=month).count() < FREE_MONTHLY_PDF_QUOTA


@router.get('/{report_id}/pdf')
def download_pdf(report_id: int, api_key: APIKey = Depends(resolve_api_key), db: Session = Depends(get_db)):
    report = owned(report_id, api_key, db)
    # A short cross-process lease prevents concurrent free exports exceeding the quota.
    lease = 'pdf-export:' + str(api_key.user_id)
    if not store.claim(lease, True, 60):
        raise HTTPException(409, 'Başka bir PDF işlemi sürüyor.')
    try:
        month = datetime.now(UTC).strftime('%Y-%m')
        previous = db.query(PDFDownload).filter_by(user_id=api_key.user_id, report_id=report_id, month=month).first()
        if previous is None and not _check_pdf_quota(api_key, db):
            raise HTTPException(429, 'Aylık 3 farklı PDF dışa aktarma sınırı doldu.')
        directory = Path(get_settings().pdf_output_dir).resolve()
        path = Path(report.pdf_path).resolve() if report.pdf_path else None
        if path is None or not path.is_relative_to(directory) or not path.exists() or path.read_bytes()[:5] != b'%PDF-':
            from app.pdf_reports import generate_pdf
            report.pdf_path = generate_pdf(report)
            report.pdf_status = 'ready'
            path = Path(report.pdf_path)
        if previous is None:
            db.add(PDFDownload(user_id=api_key.user_id, report_id=report_id, month=month))
        db.commit()
        return FileResponse(path, media_type='application/pdf', filename=f'rapor_{report_id}.pdf')
    finally:
        store.delete(lease)
