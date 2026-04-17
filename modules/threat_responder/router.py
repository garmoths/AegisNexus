"""
06 - Cyber Guardian Module Router (Siber Koruyucu)
Siber zorbalık, şantaj önleme ve mağdur destek endpointleri
"""
from fastapi import APIRouter
from pydantic import BaseModel
from typing import Optional

from .engine import cyber_guardian, VictimSupportCase

router = APIRouter(tags=["06-cyber-guardian"])


class ThreatAnalysisRequest(BaseModel):
    message: str
    context: Optional[str] = None  # sms, email, social_media, chat


class SupportCaseRequest(BaseModel):
    case_type: str  # blackmail, cyberbullying, identity_theft, harassament
    description: str
    severity: Optional[str] = None  # Otomatik tespit edilebilir
    evidence: Optional[str] = None


class CaseReportRequest(BaseModel):
    case_id: str


@router.post("/analyze-threat")
def analyze_threat_message(req: ThreatAnalysisRequest):
    """
    Şüpheli mesajı analiz et - Şantaj veya siber zorbalık tespiti.
    Yapay zeka destekli gösterge analizi.
    """
    analysis = cyber_guardian.analyze_threat_message(req.message)
    
    # Eğer tehdit tespit edildiyse otomatik destek planı öner
    auto_support = None
    if analysis["threat_detected"]:
        auto_support = {
            "immediate_actions": [
                "Panik yapmayın - Yardım mevcut",
                "Kanıtları (ekran görüntüsü) kaydedin",
                "Bu analiz sonucunu güvenilir yetişkinle paylaşın",
            ],
            "emergency_contacts": [
                {"hizmet": "Yasal Destek", "numara": "156"},
                {"hizmet": "Aile Bakanlığı", "numara": "183"} if analysis["threat_type"] == "cyberbullying" else {"hizmet": "Siber Suçlar", "iletisim": "siber@egm.gov.tr"},
            ],
        }
    
    return {
        "status": "success",
        "analysis": analysis,
        "context": req.context,
        "auto_support": auto_support,
        "module": "06_cyber_guardian",
        "next_steps": [
            "Destek vakası oluştur" if analysis["threat_detected"] else "İzlemeye devam et",
            "KVKK başvurusu hazırla" if analysis["threat_type"] == "blackmail" else None,
            "Psikolojik destek al" if analysis["severity"] in ["CRITICAL", "HIGH"] else None,
        ],
    }


@router.post("/create-case")
def create_support_case(req: SupportCaseRequest):
    """
    Yeni destek vakası oluştur.
    Siber zorbalık veya şantaj mağdurları için özel destek planı.
    """
    # Eğer severity belirtilmemişse otomatik analiz
    severity = req.severity
    if not severity and req.description:
        analysis = cyber_guardian.analyze_threat_message(req.description)
        severity = analysis.get("severity", "MEDIUM")
    
    case = cyber_guardian.create_support_case(
        case_type=req.case_type,
        description=req.description,
        severity=severity or "MEDIUM",
        evidence=req.evidence,
    )
    
    return {
        "status": "success",
        "case": case.to_dict(),
        "support_plan": case.support_plan,
        "resources": case.resources_provided,
        "module": "06_cyber_guardian",
        "message": "Destek vakası oluşturuldu. Bir yetişkinle paylaşın.",
        "immediate_help": "156 Yasal Destek (7/24)" if case.severity in ["CRITICAL", "HIGH"] else None,
    }


@router.get("/cases/{case_id}")
def get_case_details(case_id: str):
    """Vaka detaylarını getir"""
    case = cyber_guardian.active_cases.get(case_id)
    if not case:
        return {
            "status": "error",
            "message": "Vaka bulunamadı",
            "module": "06_cyber_guardian",
        }
    
    return {
        "status": "success",
        "case": {
            **case.to_dict(),
            "full_description": case.description,
            "support_plan": case.support_plan,
            "resources": case.resources_provided,
        },
        "module": "06_cyber_guardian",
    }


@router.post("/generate-report")
def generate_incident_report(req: CaseReportRequest):
    """
    Yasal başvuru için olay raporu oluştur.
    Savcılık/KVKK başvurularında kullanılabilir.
    """
    report = cyber_guardian.generate_incident_report(req.case_id)
    
    if not report:
        return {
            "status": "error",
            "message": "Vaka bulunamadı",
            "module": "06_cyber_guardian",
        }
    
    return {
        "status": "success",
        "report": report,
        "download_ready": True,
        "submit_to": report["recommended_authorities"],
        "module": "06_cyber_guardian",
        "usage_instructions": [
            "Bu raporu PDF olarak indirin",
            "Savcılığa suç duyurusu yapın (şantaj/sondaj varsa)",
            "KVKK'ya veri ihlali başvurusu yapın",
            "Rapor numarasını kaydedin",
        ],
    }


@router.get("/resources")
def get_support_resources():
    """Tüm destek kaynaklarını listele"""
    return {
        "status": "success",
        "emergency_contacts": {
            "yasal_destek": {
                "156": "Ücretsiz hukuki danışma (7/24)",
                "siber@egm.gov.tr": "Emniyet Siber Suçlar",
                "ihbarweb.org.tr": "Online şikayet",
            },
            "psikolojik_destek": {
                "183": "Aile ve Sosyal Hizmetler Bakanlığı",
                "116": "Umut İmseselim - İntiharı önleme hattı",
                "0850 222 0 123": "Gençlik ve Aile Destek Hattı",
            },
            "kvkk_basvuru": {
                "kvkk.gov.tr": "Kişisel Verileri Koruma Kurumu",
                "kvkk@kvkk.gov.tr": "E-posta başvurusu",
            },
        },
        "module": "06_cyber_guardian",
        "message": "Bu kaynaklar ücretsiz ve gizlidir. Çekinmeden arayın.",
    }


@router.get("/education")
def get_prevention_education():
    """Önleyici eğitim materyalleri"""
    education = cyber_guardian.get_prevention_education()
    
    return {
        "status": "success",
        "education_materials": education,
        "module": "06_cyber_guardian",
        "target_audience": "Gençler, veliler, öğretmenler",
        "usage": "Bu materyaller okul seminerleri ve aile bilgilendirmelerinde kullanılabilir",
    }


@router.get("/stats")
def get_guardian_stats():
    """Cyber Guardian toplumsal etki istatistikleri"""
    stats = cyber_guardian.get_social_impact_stats()
    
    return {
        "status": "success",
        "statistics": stats,
        "module": "06_cyber_guardian",
        "social_impact_message": "Her destek vakası = Potansiyel bir intiharın, ciddi travmanın veya şantaj mağduriyetinin önüne geçmek",
        "success_stories_template": [
            "[Vaka 1] 17 yaşındaki genç şantaj mesajı sonrası destek aldı, hukuki süreç başlatıldı",
            "[Vaka 2] Siber zorbalık mağduru öğrenci psikolojik destekle okula döndü",
            "[Vaka 3] Veri ihlali fark edilip şifreler değiştirildi, şantaj önlendi",
        ],
    }


@router.get("/indicators")
def get_threat_indicators():
    """Şantaj ve zorbalık göstergeleri listesi"""
    return {
        "status": "success",
        "blackmail_indicators": cyber_guardian.BLACKMAIL_INDICATORS,
        "cyberbullying_indicators": cyber_guardian.CYBERBULLYING_INDICATORS,
        "module": "06_cyber_guardian",
        "note": "Bu göstergeler yapay zeka analizinde kullanılır. Kesin teşhis değildir, profesyonel değerlendirme gerekir.",
    }
