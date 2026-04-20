"""
AI Analyzer API Router
07 - AI Security Assistant Endpoints
"""
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel, Field
from typing import Optional, List
from sqlalchemy.orm import Session

from shared.utils.db import get_db
from .engine import AIAnalyzerEngine
from .llm_client import llm_client

router = APIRouter(
    prefix="/ai-analyzer",
    tags=["07-ai-analyzer"],
    responses={404: {"description": "Not found"}}
)

# Request/Response Models
class MessageAnalysisRequest(BaseModel):
    message: str = Field(..., description="Analiz edilecek mesaj/metin", min_length=10)
    context: str = Field("email", description="Mesaj tipi: email, sms, whatsapp, social_media")
    sender: Optional[str] = Field(None, description="Gönderen bilgisi")
    subject: Optional[str] = Field(None, description="Konu (email için)")

class QuickScanRequest(BaseModel):
    message: str = Field(..., description="Hızlı tarama için mesaj", min_length=5)

class URLCheckRequest(BaseModel):
    url: str = Field(..., description="Kontrol edilecek URL")

class AnalysisResponse(BaseModel):
    analysis_id: str
    timestamp: str
    security_assessment: dict
    detailed_analysis: dict
    recommendations: List[dict]
    summary: str

# Initialize engine
def get_analyzer(db: Session = Depends(get_db)):
    return AIAnalyzerEngine(db)

@router.post("/analyze", response_model=AnalysisResponse)
def analyze_message(
    request: MessageAnalysisRequest,
    analyzer: AIAnalyzerEngine = Depends(get_analyzer)
):
    """
    🔍 **Tam AI Analizi**
    
    Metni/mesajı analiz eder ve detaylı güvenlik raporu sunar.
    
    **Özellikler:**
    - LLM tabanlı phishing/scam tespiti
    - URL güvenlik kontrolü (veritabanı + API)
    - Psikolojik manipülasyon analizi
    - Kişiselleştirilmiş öneriler
    
    **Kullanım:**
    ```json
    {
      "message": "Banka hesabınız askıya alındı! Hemen tıklayın...",
      "context": "email",
      "sender": "fake-banka@example.com",
      "subject": "Acil: Hesap Durumu"
    }
    ```
    """
    try:
        result = analyzer.analyze_message(
            message=request.message,
            context=request.context,
            sender=request.sender,
            subject=request.subject
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analiz hatası: {str(e)}")

@router.post("/quick-scan")
def quick_scan(
    request: QuickScanRequest,
    analyzer: AIAnalyzerEngine = Depends(get_analyzer)
):
    """
    ⚡ **Hızlı Tarama**
    
    Saniyeler içinde kritik riskleri tespit eder.
    
    **Dönüş:**
    - `is_safe`: true/false
    - `threat_level`: low/medium/high/critical
    - `malicious_urls`: [şüpheli URL'ler]
    """
    try:
        result = analyzer.quick_scan(request.message)
        return {
            "status": "success",
            "scan_result": result,
            "module": "07_ai_analyzer"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Tarama hatası: {str(e)}")

@router.post("/check-url")
def check_url_security(
    request: URLCheckRequest,
    db: Session = Depends(get_db)
):
    """
    🔗 **URL Güvenlik Kontrolü**
    
    URL'nin güvenliğini kontrol eder:
    - Phishing veritabanında ara
    - TLD kontrolü
    - IP tabanlı URL kontrolü
    """
    from .url_checker import URLSecurityChecker
    
    try:
        checker = URLSecurityChecker(db)
        result = checker.check_url(request.url)
        return {
            "status": "success",
            "url_check": result,
            "module": "07_ai_analyzer"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL kontrol hatası: {str(e)}")

@router.post("/extract-urls")
def extract_urls_from_text(
    text: str = Body(..., embed=True)
):
    """
    🔍 **Metinden URL Çıkar**
    
    Metin içindeki tüm URL'leri bulur ve listeler.
    """
    from .url_checker import URLSecurityChecker
    
    try:
        checker = URLSecurityChecker()
        urls = checker.extract_urls(text)
        return {
            "status": "success",
            "urls_found": len(urls),
            "urls": urls,
            "module": "07_ai_analyzer"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"URL çıkarma hatası: {str(e)}")

@router.get("/health")
def health_check():
    """
    💓 **Sağlık Kontrolü**
    
    AI Analyzer modülünün durumunu kontrol eder.
    """
    return {
        "status": "healthy",
        "module": "07_ai_analyzer",
        "features": [
            "llm_analysis",
            "url_check",
            "quick_scan",
            "full_analysis"
        ],
        "llm_available": bool(
            llm_client.openai_key or llm_client.claude_key
        )
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
