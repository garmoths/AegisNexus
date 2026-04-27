"""
AI Analyzer API Router
07 - AI Security Assistant Endpoints
"""
import re
from fastapi import APIRouter, Depends, HTTPException, Body
from pydantic import BaseModel, Field
from typing import Optional, List
from sqlalchemy.orm import Session

from shared.utils.db import get_db
from app.models import URLAnalizHistory
from .engine import AIAnalyzerEngine
from .llm_client import llm_client
from .advanced_phishing_detector import detect_phishing

router = APIRouter(
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
    🔍 **Tam AI Analizi** (Advanced Hybrid Algorithm)

    3 modüllü hibrit skorlama sistemi ile phishing tespiti:
    - URL Modülü (40%): DB benzerlik + SSL kontrol
    - Metin+Duygu Modülü (35%): Gemini LLM + aciliyet + VAD duygu analizi
    - Güvenilirlik Skoru (25%): Veri kalitesi değerlendirmesi

    **Matematiksel Formül:**
    S* = Amplify(C × (0.4×s_url + 0.35×s_text) + (1-C)×0.5)

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
    import logging
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"Analyzing message with advanced algorithm: {request.message[:50]}...")
        
        # Extract URL from message if any
        url = None
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', request.message)
        if urls:
            url = urls[0]
        
        # Use new advanced detector (PRIMARY)
        advanced_result = detect_phishing(request.message, url)
        
        # Get legacy analyzer data for additional context (but NOT for score)
        legacy_result = analyzer.analyze_message(
            message=request.message,
            context=request.context,
            sender=request.sender,
            subject=request.subject
        )
        
        # Use NEW algorithm's score directly (no override)
        final_score = advanced_result["score"] * 100  # Scale 0-100
        final_verdict = advanced_result["verdict"]
        final_confidence = advanced_result["confidence"]  # Already 0-1 range
        
        # Update legacy result with new algorithm's scores
        legacy_result["security_assessment"]["risk_level"] = final_verdict.lower()
        legacy_result["security_assessment"]["score"] = round(final_score, 2)
        
        # Fix: is_phishing should be based on new algorithm's verdict
        is_phishing = final_verdict == "PHİSHİNG"
        legacy_result["security_assessment"]["is_phishing"] = is_phishing
        legacy_result["security_assessment"]["is_scam"] = is_phishing
        
        # Fix: Use new algorithm's confidence (0-1 range)
        legacy_result["security_assessment"]["confidence"] = round(final_confidence, 2)
        
        # Fix: Override safety_status based on new verdict
        if final_verdict == "PHİSHİNG":
            legacy_result["security_assessment"]["safety_status"] = "TEHLİKELİ"
            legacy_result["security_assessment"]["action_required"] = "ACİL"
            legacy_result["security_assessment"]["threat_level"] = "critical"
        elif final_verdict == "ŞÜPHELİ":
            legacy_result["security_assessment"]["safety_status"] = "ŞÜPHELİ"
            legacy_result["security_assessment"]["action_required"] = "DİKKAT"
            legacy_result["security_assessment"]["threat_level"] = "high"
        elif final_verdict == "DÜŞÜK RİSK":
            legacy_result["security_assessment"]["safety_status"] = "ŞÜPHELİ"
            legacy_result["security_assessment"]["action_required"] = "DİKKAT"
            legacy_result["security_assessment"]["threat_level"] = "medium"
        else:  # TEMİZ
            legacy_result["security_assessment"]["safety_status"] = "GÜVENLİ"
            legacy_result["security_assessment"]["action_required"] = "YOK"
            legacy_result["security_assessment"]["threat_level"] = "low"
        
        legacy_result["detailed_analysis"]["advanced_breakdown"] = advanced_result["breakdown"]
        legacy_result["detailed_analysis"]["hard_override"] = advanced_result["hard_override"]
        legacy_result["summary"] = f"[{final_verdict}] {advanced_result['reason']} (Skor: {advanced_result['score']:.2f}, Güven: {advanced_result['confidence']:.2f})"
        
        logger.info(f"Advanced analysis completed: {final_verdict} (score: {final_score:.1f})")
        return legacy_result
    except Exception as e:
        logger.error(f"Analysis error: {str(e)}", exc_info=True)
        # Fallback to legacy analyzer only if new one fails completely
        try:
            result = analyzer.analyze_message(
                message=request.message,
                context=request.context,
                sender=request.sender,
                subject=request.subject
            )
            # Remove hardcoded 75 override in fallback too
            return result
        except:
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


@router.get("/history")
async def get_analiz_history(
    limit: int = 10,
    db: Session = Depends(get_db)
):
    """
    Son URL analizlerini getir.
    """
    try:
        history = db.query(URLAnalizHistory).order_by(
            URLAnalizHistory.created_at.desc()
        ).limit(limit).all()
        
        return {
            "data": [
                {
                    "id": h.id,
                    "url": h.url,
                    "domain": h.domain,
                    "risk_level": h.risk_level,
                    "is_phishing": h.is_phishing,
                    "confidence": h.confidence,
                    "created_at": h.created_at.isoformat() if h.created_at else None
                }
                for h in history
            ],
            "total": len(history),
            "module": "07_ai_analyzer"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history/{history_id}")
async def get_analiz_detail(
    history_id: int,
    db: Session = Depends(get_db)
):
    """
    Analiz detaylarını getir.
    """
    try:
        history = db.query(URLAnalizHistory).filter(
            URLAnalizHistory.id == history_id
        ).first()
        
        if not history:
            raise HTTPException(status_code=404, detail="Analiz bulunamadı")
        
        return {
            "id": history.id,
            "url": history.url,
            "domain": history.domain,
            "risk_level": history.risk_level,
            "is_phishing": history.is_phishing,
            "confidence": history.confidence,
            "analysis_result": history.analysis_result,
            "llm_analysis": history.llm_analysis,
            "url_checks": history.url_checks,
            "created_at": history.created_at.isoformat() if history.created_at else None,
            "module": "07_ai_analyzer"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
