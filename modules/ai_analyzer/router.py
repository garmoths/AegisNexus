"""AI analyzer endpoints (``/api/v2/ai-analyzer``).

Message/e-mail analysis with the hybrid detector, URL checks and the caller's
private URL-analysis history. Logic lives in :mod:`modules.ai_analyzer.service`.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Body, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.auth import resolve_api_key, resolve_optional_api_key
from app.database import get_db
from app.models import APIKey

from . import service
from .engine import AIAnalyzerEngine
from .llm_client import llm_client
from .url_checker import URLSecurityChecker

router = APIRouter(tags=["ai-analyzer"])
MODULE = service.MODULE


class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., description="Analiz edilecek mesaj/metin", min_length=10, max_length=20000)
    message_type: Literal["text", "email"] = Field("text", description="Mesaj tipi: text veya email")
    context: str | None = Field(None, description="Geriye dönük uyumluluk için eski alan")
    sender: str | None = Field(None, description="Geriye dönük uyumluluk için eski alan")
    subject: str | None = Field(None, description="Geriye dönük uyumluluk için eski alan")

class QuickScanRequest(BaseModel):
    message: str = Field(..., description="Hızlı tarama için mesaj", min_length=5, max_length=20000)

class URLCheckRequest(BaseModel):
    url: str = Field(..., description="Kontrol edilecek URL", max_length=2048)

class AnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    security_assessment: dict
    detailed_analysis: dict
    recommendations: list[dict]
    summary: str
    analysis_mode: str | None = None
    evidence: list[str] | None = None
    matched_categories: list[str] | None = None
    parsed_email: dict | None = None
    email_signals: dict | None = None



class ExtractedURLs(BaseModel):
    status: Literal['success'] = 'success'
    urls_found: int
    urls: list[str]
    module: str = MODULE


class HistoryRow(BaseModel):
    id: int
    url: str
    domain: str
    risk_level: str
    is_phishing: bool | None
    confidence: float | None
    created_at: str | None


class HistoryPage(BaseModel):
    data: list[HistoryRow]
    total: int
    module: str = MODULE


def get_analyzer(db: Session = Depends(get_db)) -> AIAnalyzerEngine:
    return AIAnalyzerEngine(db)


@router.post("/analyze", response_model=AnalysisResponse, summary="Hybrid phishing / scam analysis of a message")
def analyze_message(request: MessageAnalysisRequest, analyzer: AIAnalyzerEngine = Depends(get_analyzer),
                    db: Session = Depends(get_db), api_key: APIKey | None = Depends(resolve_optional_api_key)):
    """
    Three-part hybrid score: URL module (40%: DB similarity, SSL), text + emotion
    module (35%: LLM, urgency, VAD) and a reliability term (25%):

    `S* = Amplify(C × (0.4·s_url + 0.35·s_text) + (1−C)·0.5)`

    `message_type: "email"` parses headers, links and attachments from a raw e-mail first.
    """
    return service.analyze_with_fallback(analyzer, message=request.message, message_type=request.message_type,
                                         context=request.context, sender=request.sender, subject=request.subject)


@router.post("/quick-scan", summary="Fast rule-based scan")
def quick_scan(request: QuickScanRequest, analyzer: AIAnalyzerEngine = Depends(get_analyzer)) -> dict[str, Any]:
    return {"status": "success", "scan_result": analyzer.quick_scan(request.message), "module": MODULE}


@router.post("/check-url", summary="Local URL heuristics and phishing-DB lookup")
def check_url_security(request: URLCheckRequest, db: Session = Depends(get_db),
                       api_key: APIKey | None = Depends(resolve_optional_api_key)) -> dict[str, Any]:
    result = URLSecurityChecker(db).check_url(request.url)
    service.record_url_analysis(db, api_key, result)
    return {"status": "success", "url_check": result, "module": MODULE}


@router.post("/extract-urls", response_model=ExtractedURLs, summary="Find URLs in text")
def extract_urls_from_text(text: str = Body(..., embed=True, max_length=200_000)):
    urls = URLSecurityChecker().extract_urls(text)
    return ExtractedURLs(urls_found=len(urls), urls=urls)


@router.get("/health")
def health_check():
    """
    💓 **Sağlık Kontrolü**

    AI Analyzer modülünün durumunu kontrol eder.
    """
    analysis_method = getattr(llm_client, "analyze_text", None)
    ml_ready = callable(analysis_method)

    return {
        "status": "healthy",
        "module": "07_ai_analyzer",
        "features": [
            "llm_analysis",
            "url_check",
            "quick_scan",
            "full_analysis"
        ],
        "llm_available": ml_ready,
        "primary_llm": "ml_random_forest" if ml_ready else "none"
    }

@router.get("/examples")
def get_analysis_examples():
    """
    📚 **Örnek Analizler**

    Modülün tespit edebileceği tehdit örnekleri.
    """
    return {
        "examples": [
            {
                "type": "Phishing Email",
                "sample": "Banka hesabınız askıya alındı! Hemen doğrulamak için tıklayın...",
                "indicators": ["aciliyet", "tehdit", "link"],
                "expected_threat_level": "high"
            },
            {
                "type": "SMS Scam",
                "sample": "Tebrikler! 100.000 TL kazandınız. Hemen arayın: 0555...",
                "indicators": ["aşırı kazanç", "arama isteği"],
                "expected_threat_level": "high"
            },
            {
                "type": "Social Engineering",
                "sample": "CEO dolandırıcılığı: Acil para transferi gerekiyor!",
                "indicators": ["otorite", "aciliyet"],
                "expected_threat_level": "critical"
            }
        ],
        "module": "07_ai_analyzer"
    }



@router.get("/history", response_model=HistoryPage, summary="Your URL analysis history")
def get_analiz_history(limit: int = Query(10, ge=1, le=100), db: Session = Depends(get_db),
                       api_key: APIKey = Depends(resolve_api_key)):
    return service.history(db, api_key, limit)


@router.get("/history/{history_id}", summary="One URL analysis from your history")
def get_analiz_detail(history_id: int, db: Session = Depends(get_db),
                      api_key: APIKey = Depends(resolve_api_key)) -> dict[str, Any]:
    return service.history_detail(db, api_key, history_id)
