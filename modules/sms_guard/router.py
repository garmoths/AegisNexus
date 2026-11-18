"""SMS Guard endpoints (``/api/v2/sms``).

POST /analyze scores an SMS with explainable rules plus an IOC cross-check.
Operators (Turkcell, TT, Vodafone) can call it from their SMS filtering pipelines.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db

from .service import SMSAnalyzeRequest, SMSAnalyzeResponse, _analyze_sms

router = APIRouter(tags=["sms-guard"])


# ── Endpoints ─────────────────────────────────────────────

@router.post(
    "/analyze",
    response_model=SMSAnalyzeResponse,
    summary="SMS güvenlik analizi",
    description=(
        "Gelen SMS metnini smishing/phishing açısından analiz eder. "
        "Açıklanabilir kural skoru + IOC veritabanı çapraz kontrolü + Türkçe keyword analizi. "
        "Operatör entegrasyonu için: SMS içeriğini POST edin, risk skoru + aksiyon alın."
    ),
)
def analyze_sms(req: SMSAnalyzeRequest, db: Session = Depends(get_db)):
    if not req.text.strip():
        raise HTTPException(status_code=400, detail="SMS metni boş olamaz.")
    return _analyze_sms(req.text, req.sender, db)


@router.get(
    "/info",
    summary="SMS Guard modül bilgisi",
)
def sms_guard_info():
    return {
        "module": "07-sms-guard",
        "version": "1.0.0",
        "description": "Türkçe SMS smishing/phishing analiz motoru",
        "capabilities": [
            "URL kısaltıcı tespiti",
            "IP tabanlı URL tespiti",
            "IOC veritabanı çapraz kontrol",
            "Türkçe phishing anahtar kelime analizi",
            "Aciliyet/baskı taktiği tespiti",
            "Resmi kurum taklidi şüphesi",
        ],
        "integration": {
            "endpoint": "POST /api/v2/sms/analyze",
            "input": {"text": "SMS içeriği", "sender": "Gönderen (opsiyonel)"},
            "output": {"risk_score": "0-100", "category": "smishing|şüpheli|belirsiz|temiz", "action": "BLOCK|WARN|MONITOR|ALLOW"},
        },
        "use_cases": ["Operatör SMS filtresi", "Kurumsal güvenlik gateway", "Bireysel SMS kontrolü"],
    }
