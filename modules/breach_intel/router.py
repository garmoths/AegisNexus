"""
03 - Breach Intelligence Module Router
Veri Radarı, OSINT Zombi Detector, Psychology Profiler, Password Suggestion
"""
from __future__ import annotations

import logging
import base64
import os
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional, List

from shared.utils.db import get_db


def _check_maintenance():
    """Breach Intel modülü dış API (HIBP, Groq) bağımlılıkları nedeniyle bakımda."""
    if os.getenv("BREACH_INTEL_MAINTENANCE", "0") == "1":
        raise HTTPException(
            status_code=503,
            detail={
                "module": "03_breach_intel",
                "reason": "maintenance",
                "message": "Bu modül dış API bağımlılıkları nedeniyle bakımda. Yakında tekrar deneyin.",
            },
        )
from .engine import breach_engine
from .hibp_client import lookup_breaches
from .osint_checker import analyze_zombie_accounts
from .psychology_analyzer import analyze_breach_in_dark_web
from .radar_generator import RadarGenerator, create_d3_visualization_html
from .llm_reporter import BreachReportGenerator
from app.security import require_admin_api_key
from .dark_web_scanner import DarkWebScanner
from .psychology_analyzer import PsychologyAnalyzerLLM
from .utils import (
    BreachRiskCalculator,
    BreachRecommendationEngine,
    format_breach_summary,
    create_kvkk_report,
)
from .domain_checker import check_email_domain
from .kvkk_pdf import generate_kvkk_pdf

logger = logging.getLogger(__name__)
router = APIRouter(tags=["03-breach-intel"], dependencies=[Depends(_check_maintenance)])


class EmailCheckRequest(BaseModel):
    email: str


class LLMReportRequest(BaseModel):
    domain: str
    email_count: int
    risk_score: int
    company_name: Optional[str] = "Unknown"
    data_types: Optional[List[str]] = []
    source: Optional[str] = "unknown"


class FullBreachAnalysisRequest(BaseModel):
    email: str
    include_osint: bool = True
    include_dark_web_analysis: bool = True
    include_radar: bool = True


class YouthSupportRequest(BaseModel):
    email: str
    age_group: Optional[str] = "18-25"


# =========================================================
# ENDPOINT 1: TAM ANALIZ (Aegis Imperius)
# =========================================================

@router.post("/full-analysis")
def full_breach_analysis(
    req: FullBreachAnalysisRequest,
    db: Session = Depends(get_db)
):
    """
    🔴 AEGİS İMPERİUS - Tam Breach Intel Analizi
    
    Tüm modülleri çalıştırır:
    1. HaveIBeenPwned sızıntı kontrolü
    2. OSINT Zombi Hesap Temizleyici
    3. Psychology Profiler (Dark Web)
    4. Veri Radarı Görselleştirmesi
    5. Password Shield yönlendirmesi
    """
    
    logger.info(f"Tam analiz başlatılıyor: {req.email}")
    
    # 1. HIBP Kontrolü
    hibp_result = lookup_breaches(req.email)
    
    if not hibp_result.get("ok"):
        return {
            "status": "error",
            "message": hibp_result.get("error"),
            "hint": hibp_result.get("hint"),
            "module": "03_breach_intel"
        }
    
    breaches = hibp_result.get("breaches", [])
    analysis_result = {
        "email": req.email,
        "status": "success",
        "analysis_modules": {},
        "summary": {},
        "recommendations": []
    }
    
    # 2. OSINT - Zombi Hesaplar (isteğe bağlı)
    zombie_accounts = []
    if req.include_osint:
        try:
            zombie_result = analyze_zombie_accounts(req.email)
            zombie_accounts = zombie_result.get("accounts", [])
            analysis_result["analysis_modules"]["zombie_detector"] = {
                "status": "completed",
                "zombie_accounts_found": len(zombie_accounts),
                "accounts": zombie_accounts,
                "risk_level": zombie_result.get("risk_level"),
                "recommendation": zombie_result.get("recommendation")
            }
            logger.info(f"Zombi hesaplar: {len(zombie_accounts)} bulundu")
        except Exception as e:
            logger.error(f"OSINT hatası: {e}")
            analysis_result["analysis_modules"]["zombie_detector"] = {
                "status": "error",
                "message": str(e)
            }
    
    # 3. Psychology Profiler - Dark Web (isteğe bağlı)
    threat_profile = None
    if req.include_dark_web_analysis and breaches:
        try:
            # Simülasyon: forum postları örneği
            mock_listings = [
                "Selling 700M LinkedIn database - Includes passwords, emails, job titles. $500",
                "LEAKED: MySpace records available. Email + password hash combos. PM for details",
                "NEW: Database dump from 2008 contains personal info, emails, birthdates"
            ]
            
            threat_result = analyze_breach_in_dark_web(req.email, mock_listings)
            threat_profile = threat_result.get("threat_type")
            
            analysis_result["analysis_modules"]["psychology_profiler"] = {
                "status": "completed",
                "threat_type": threat_profile,
                "overall_risk": threat_result.get("overall_risk_level"),
                "recommendations": threat_result.get("recommendations"),
                "hacker_profile": threat_result.get("profile")
            }
            logger.info(f"Threat tipi: {threat_profile.get('type') if threat_profile else 'None'}")
        except Exception as e:
            logger.error(f"Psychology profiler hatası: {e}")
            analysis_result["analysis_modules"]["psychology_profiler"] = {
                "status": "error",
                "message": str(e)
            }
    
    # 4. Veri Radarı (isteğe bağlı)
    if req.include_radar and breaches:
        try:
            radar_gen = RadarGenerator()
            radar_data = radar_gen.generate_radar_data(
                req.email,
                breaches,
                zombie_accounts,
                threat_profile
            )
            
            analysis_result["analysis_modules"]["radar"] = {
                "status": "completed",
                "total_nodes": len(radar_data.get("nodes", [])),
                "total_links": len(radar_data.get("links", [])),
                "overall_risk": radar_data.get("metadata", {}).get("overall_risk_level")
            }
            
            logger.info(f"Radar: {len(radar_data['nodes'])} node, {len(radar_data['links'])} link")
        except Exception as e:
            logger.error(f"Radar hatası: {e}")
            analysis_result["analysis_modules"]["radar"] = {
                "status": "error",
                "message": str(e)
            }
    
    # 5. Özet ve Öneriler
    avg_severity = (
        sum(
            BreachRiskCalculator.calculate_breach_severity(b.get("data_classes", []))
            for b in breaches
        ) / len(breaches)
        if breaches
        else 0
    )
    
    # Domain phishing kontrolü
    try:
        domain_risk = check_email_domain(req.email)
    except Exception as _e:
        logger.warning(f"Domain check failed: {_e}")
        domain_risk = {"domain": None, "is_suspicious": False, "risk_score": 0, "signals": []}

    analysis_result["summary"] = {
        "breached": hibp_result.get("breached", False),
        "breach_count": len(breaches),
        "breaches": breaches,
        "average_breach_severity": avg_severity,
        "breach_summary": format_breach_summary(req.email, breaches),
        "turkish_summary": hibp_result.get("report_tr"),
        "domain_risk": domain_risk,
    }
    
    # Öneriler
    recommendations = BreachRecommendationEngine.get_recommendations(
        req.email,
        breaches,
        zombie_accounts,
        threat_profile
    )
    
    analysis_result["recommendations"] = recommendations
    
    # Next Steps
    analysis_result["next_steps"] = [
        "1. Bu raporu dikkatlice oku",
        "2. Tavsiye edilen şifreler 'Password Shield' ile oluştur → /api/password-shield/generate",
        "3. Belirlenen hesapları güvenli hale getir veya kapat",
        "4. Gerekirse KVKK başvurusu yap → /api/breach/generate-kvkk-report",
        "5. Düzenli olarak Aegis Nexus ile kontrol et"
    ]
    
    analysis_result["module"] = "03_breach_intel"
    
    return analysis_result


# =========================================================
# ENDPOINT 2: BASIT KONTROL (Quick Check)
# =========================================================

@router.post("/check-email")
def check_email_breach(
    req: EmailCheckRequest,
    db: Session = Depends(get_db)
):
    """
    Basit E-posta Sızıntı Kontrolü (Quick Check)
    Sadece HIBP ve temel risk analizi
    """
    hibp_result = lookup_breaches(req.email)
    
    if not hibp_result.get("ok"):
        return {
            "status": "error",
            "message": hibp_result.get("error"),
            "hint": hibp_result.get("hint"),
            "module": "03_breach_intel"
        }
    
    breaches = hibp_result.get("breaches", [])
    
    # Şantaj riski analizi
    shantaj_analysis = breach_engine.analyze_shantaj_risk(req.email, breaches)
    
    # KVKK raporu hazırla (eğer sızıntı varsa)
    kvkk_report = None
    if breaches:
        kvkk_report = breach_engine.generate_kvkk_report(req.email, breaches)
    
    # Domain phishing kontrolü
    try:
        domain_risk = check_email_domain(req.email)
    except Exception as _e:
        logger.warning(f"Domain check failed: {_e}")
        domain_risk = {"domain": None, "is_suspicious": False, "risk_score": 0, "signals": []}

    return {
        "status": "success",
        "email": req.email,
        "breached": hibp_result.get("breached", False),
        "breach_count": hibp_result.get("breach_count", 0),
        "breaches": breaches,
        "domain_risk": domain_risk,
        "shantaj_risk_analysis": shantaj_analysis,
        "kvkk_report": kvkk_report,
        "turkish_summary": hibp_result.get("report_tr"),
        "module": "03_breach_intel",
        "next_steps": [
            "Kriptografik Kalkan ile yeni şifre oluştur → /api/password-shield/generate",
            "Şüpheli hesaplarda 2FA aktif et",
            "KVKK başvurusu yap (rapor hazır)" if breaches else "Düzenli kontrol yapmaya devam et"
        ]
    }


# =========================================================
# ENDPOINT 3: ZOMBI HESAPLAR
# =========================================================

@router.post("/zombie-detector")
def detect_zombie_accounts(
    req: EmailCheckRequest
):
    """
    OSINT ile Zombi Hesapları Tespit Et
    Unutulmuş hesapları LinkedIn, Facebook, Twitter, Reddit vb. platformlarda bulur
    """
    try:
        result = analyze_zombie_accounts(req.email)
        return {
            "status": "success",
            "email": req.email,
            "data": result,
            "module": "03_breach_intel"
        }
    except Exception as e:
        logger.error(f"Zombi detector hatası: {e}")
        return {
            "status": "error",
            "message": str(e),
            "module": "03_breach_intel"
        }


# =========================================================
# ENDPOINT 4: KVKK RAPORU
# =========================================================

@router.post("/generate-kvkk-report")
def generate_kvkk_application(
    req: EmailCheckRequest,
    db: Session = Depends(get_db)
):
    """KVKK kişisel veri ihlali başvurusu için otomatik rapor oluştur"""
    hibp_result = lookup_breaches(req.email)
    
    if not hibp_result.get("breached"):
        return {
            "status": "info",
            "message": "Bu e-posta için bilinen bir sızıntı yok. KVKK başvurusuna gerek yok.",
            "module": "03_breach_intel"
        }
    
    breaches = hibp_result.get("breaches", [])
    kvkk_report = create_kvkk_report(req.email, breaches)
    
    return {
        "status": "success",
        "report": kvkk_report,
        "download_ready": True,
        "submit_to": kvkk_report["where_to_apply"],
        "module": "03_breach_intel",
        "action_items": [
            "Raporu PDF olarak indir",
            "kvkk.gov.tr üzerinden başvuruyu gönder",
            "Başvuru takip numarasını kaydet",
        ]
    }


# =========================================================
# ENDPOINT 4b: KVKK PDF RAPORU (YENİ)
# =========================================================

class KVKKPDFRequest(BaseModel):
    email: str
    applicant_name: Optional[str] = None


@router.post("/generate-kvkk-pdf")
def generate_kvkk_pdf_report(req: KVKKPDFRequest):
    """
    KVKK 6698 uyumlu veri ihlali başvuru belgesini PDF olarak üretir.

    - reportlab yüklüyse gerçek PDF çıktısı (Base64)
    - Değilse metin tabanlı özet döner
    """
    hibp_result = lookup_breaches(req.email)

    if not hibp_result.get("breached"):
        return {
            "status": "info",
            "message": "Bu e-posta için bilinen bir sızıntı yok. KVKK başvurusuna gerek yok.",
            "module": "03_breach_intel",
        }

    breaches = hibp_result.get("breaches", [])
    result = generate_kvkk_pdf(req.email, breaches, req.applicant_name)

    return {
        "status": "success",
        "email": req.email,
        "filename": result["filename"],
        "method": result["method"],
        "breach_count": result["breach_count"],
        "pdf_base64": result["pdf_base64"],
        "download_hint": (
            "pdf_base64 alanını Base64 decode ederek PDF olarak kaydedin."
            if result["method"] == "reportlab"
            else "text_fallback: reportlab yüklü değil, metin olarak kaydedildi."
        ),
        "submit_to": "kvkk.gov.tr — Başvuru Formu",
        "module": "03_breach_intel",
    }


@router.post("/download-kvkk-pdf")
def download_kvkk_pdf_file(req: KVKKPDFRequest):
    """
    KVKK PDF dosyasını doğrudan HTTP response olarak indirir.
    Content-Type: application/pdf
    """
    hibp_result = lookup_breaches(req.email)

    if not hibp_result.get("breached"):
        raise HTTPException(
            status_code=404,
            detail="Bu e-posta için bilinen bir sızıntı yok.",
        )

    breaches = hibp_result.get("breaches", [])
    result = generate_kvkk_pdf(req.email, breaches, req.applicant_name)

    if result["method"] == "reportlab":
        return Response(
            content=result["pdf_bytes"],
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{result["filename"]}"'
            },
        )
    else:
        return Response(
            content=result["pdf_bytes"],
            media_type="text/plain; charset=utf-8",
            headers={
                "Content-Disposition": f'attachment; filename="{result["filename"]}"'
            },
        )


# =========================================================
# ENDPOINT 5: GÜVENLİK SEVİYELERİ
# =========================================================

@router.get("/risk-levels")
def get_risk_level_definitions():
    """Veri sızıntısı risk seviyelerini açıkla"""
    return {
        "risk_levels": {
            "CRITICAL": {
                "score_range": "80-100",
                "indicators": ["Kredi kartı", "Banka hesabı", "Özel mesajlar", "Fotoğraflar"],
                "action": "DERHAL harekete geç - Şantaj/dolandırıcılık riski yüksek",
            },
            "HIGH": {
                "score_range": "60-79",
                "indicators": ["Şifreler (açık metin)", "TCKN", "Adres bilgileri"],
                "action": "Şifreleri değiştir, 2FA aktif et",
            },
            "MEDIUM": {
                "score_range": "30-59",
                "indicators": ["E-posta", "Telefon", "Doğum tarihi"],
                "action": "Önlem al, hesapları gözden geçir",
            },
            "LOW": {
                "score_range": "0-29",
                "indicators": ["Kullanıcı adı", "İsim"],
                "action": "Farkındalık için bilgi amaçlı",
            },
        },
        "module": "03_breach_intel",
    }


# =========================================================
# ENDPOINT 6: İSTATİSTİKLER
# =========================================================

@router.get("/stats")
def get_breach_statistics():
    """Sızıntı istihbaratı genel istatistikleri"""
    return {
        "monitored_emails": len(breach_engine.monitored_emails),
        "total_tracked_breaches": breach_engine.total_breaches_tracked,
        "risk_score_definitions": breach_engine.RISK_SCORES,
        "module": "03_breach_intel",
        "social_impact": {
            "message": "Her sızıntı uyarısı = Potansiyel bir şantaj vakasının önüne geçmek",
            "youth_protection": "Genç kullanıcılar öncelikli koruma grubu",
            "kvkk_compliance": "Otomatik raporlama ile vatandaş haklarını savun",
        }
    }


# =========================================================
# ENDPOINT 7: GENÇ KULLANICILAR
# =========================================================

@router.post("/youth-protection")
def get_youth_protection_support(req: YouthSupportRequest):
    """
    Genç kullanıcılar için siber zorbalık ve şantaj koruması.
    Psikolojik destek ve teknik önlemler.
    """
    resources = breach_engine.get_youth_protection_resources()
    
    # E-posta kontrolü (opsiyonel)
    hibp_result = lookup_breaches(req.email)
    breach_status = "safe" if not hibp_result.get("breached") else "at_risk"
    
    return {
        "status": "success",
        "age_group": req.age_group,
        "email_breach_status": breach_status,
        "immediate_actions": resources["teknik_onlemler"],
        "psychological_support": resources["psikolojik_destek"],
        "legal_support": resources["acil_destek"],
        "kvkk_guide": resources["kvkk_basvuru_rehberi"],
        "emergency_message": """
        Siber zorbalık veya şantaj mağduruysanız:
        1. Panik yapmayın - Çözüm var
        2. Yasal Destek: 156
        3. Aile ve Sosyal Hizmetler: aile.gov.tr
        4. Aegis Nexus teknik önlemleri uygulayın
        """,
        "module": "03_breach_intel",
        "social_impact": "Gençlerin verileri sızdığında şantaj mağduru olabilir. Erken uyarı = psikolojik yıkım önlenir."
    }


# =========================================================
# ENDPOINT 8: LLM-BASED RAPOR ÜRETİMİ (YENİ)
# =========================================================

@router.post("/llm-report")
@router.post("/legacy-llm-report")
def generate_llm_report(
    req: LLMReportRequest,
    _: None = Depends(require_admin_api_key),
):
    """
    LLM ile Türkçe detaylı breach raporu üret
    """
    try:
        # LLM rapor üretimi
        reporter = BreachReportGenerator()
        
        # Breach verileri oluştur
        breach_info = {
            "domain": req.domain,
            "email_count": req.email_count,
            "risk_score": req.risk_score,
            "company_name": req.company_name,
            "data_types": req.data_types
        }
        
        report = reporter.generate_breach_summary(req.domain, [breach_info])
        
        # Report string olarak döner
        report_text = report if isinstance(report, str) else str(report)
        
        return {
            "status": "success",
            "domain": req.domain,
            "report": report_text,
            "risk_level": "HIGH",
            "module": "03_breach_intel",
            "mode": "Groq LLM"
        }
    except Exception as e:
        logger.error(f"LLM rapor hatası: {e}")
        return {
            "status": "error",
            "message": str(e),
            "note": "Ollama service gerekli: http://localhost:11434",
            "module": "03_breach_intel"
        }


# =========================================================
# ENDPOINT 9: DARK WEB TARAMASI (YENİ)
# =========================================================

@router.post("/dark-web-scan")
def scan_dark_web_for_email(
    req: EmailCheckRequest
):
    """
    E-posta adresini Pastebin, GitHub Gist, Paste.org'da ara.
    Hacker forumlarında sızıntı verisini bulur.
    """
    try:
        scanner = DarkWebScanner()
        findings = scanner.scan_for_email(req.email)
        
        return {
            "status": "success",
            "email": req.email,
            "findings": findings,
            "module": "03_breach_intel",
            "action": "Bulunursa ek risk analizi ve KVKK başvurusu yapılabilir"
        }
    except Exception as e:
        logger.error(f"Dark web taraması hatası: {e}")
        return {
            "status": "error",
            "message": str(e),
            "module": "03_breach_intel"
        }


# =========================================================
# ENDPOINT 10: LLM-BASED HACKER PSYCHOLOJİ ANALİZİ (YENİ)
# =========================================================

@router.post("/psychology-analysis")
def analyze_hacker_psychology(
    req: dict  # {"forum_post": "...", "threat_type": "..."}
):
    """
    Forum gönderisinin hackerın psikolojisini LLM ile analiz et.
    Pattern-based + LLM = Detaylı profiling
    """
    try:
        forum_post = req.get("forum_post", "")
        if not forum_post:
            return {
                "status": "error",
                "message": "forum_post gerekli",
                "module": "03_breach_intel"
            }
        
        # Pattern-based analiz (mevcut sistem)
        pattern_result = analyze_breach_in_dark_web([forum_post])
        
        # LLM-based detaylı analiz
        analyzer_llm = PsychologyAnalyzerLLM()
        llm_result = analyzer_llm.analyze_with_llm(
            forum_post,
            pattern_result[0] if pattern_result else {}
        )
        
        return {
            "status": "success",
            "analysis": llm_result,
            "module": "03_breach_intel",
            "note": "Pattern-based ve LLM analizinin birleşimidir"
        }
    except Exception as e:
        logger.error(f"Psychology analiz hatası: {e}")
        return {
            "status": "error",
            "message": str(e),
            "module": "03_breach_intel"
        }


# =========================================================
# ENDPOINT 11: TELEGRAM CATCHER (YENİ)
# =========================================================

@router.get("/catcher-stats")
def get_catcher_statistics():
    """
    Telegram'dan toplanan breach istatistikleri (henüz aktif değil)
    """
    return {
        "status": "not_implemented",
        "message": "Telegram Breach Catcher modülü henüz bu sürümde aktif değil.",
        "module": "03_breach_intel_catcher",
    }


@router.get("/catcher-breaches")
def get_catcher_breaches(domain: str = None, limit: int = 50):
    """
    Telegram'dan toplanan breach'ler (henüz aktif değil)
    """
    return {
        "status": "not_implemented",
        "message": "Telegram Breach Catcher modülü henüz bu sürümde aktif değil.",
        "module": "03_breach_intel_catcher",
    }
