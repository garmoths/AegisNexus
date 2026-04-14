"""
Cyber Guardian Engine - Siber Koruyucu Motor
Siber zorbalık, şantaj önleme ve mağdur destek sistemi
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field


@dataclass
class VictimSupportCase:
    """Siber zorbalık/şantaj mağduru vakası"""
    case_id: str
    created_at: datetime
    case_type: str  # "blackmail", "cyberbullying", "identity_theft", "harassment"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str
    evidence_hash: Optional[str] = None
    support_plan: List[str] = field(default_factory=list)
    resources_provided: List[dict] = field(default_factory=list)
    status: str = "active"  # active, resolved, escalated
    
    def to_dict(self) -> dict:
        return {
            "case_id": self.case_id,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "case_type": self.case_type,
            "severity": self.severity,
            "description": self.description[:100] + "..." if len(self.description) > 100 else self.description,
            "status": self.status,
            "support_plan_steps": len(self.support_plan),
        }


class CyberGuardian:
    """
    Siber Koruyucu - Gençleri ve mağdurları koruyan sistem
    
    Temel görevler:
    1. Şantaj tespiti ve risk analizi
    2. Otomatik destek planı oluşturma
    3. Yasal/teknik kaynak yönlendirme
    4. Psikolojik destek erişimi
    5. KVKK başvurusu otomasyonu
    """
    
    # Şantaj göstergeleri (blackmail indicators)
    BLACKMAIL_INDICATORS = [
        r"para.*transfer", r"bitcoin", r"kripto",
        r"fotoğraflarını.*paylaşacağım", r"videonu.*yayacağım",
        r"hesabını.*sileceğim", r"işini.*kaybedeceksin",
        r"ailene.*göstereceğim", r"arkadaşlarına.*yollayacağım",
        r"ifşa", r"şantaj", r"tehdit",
    ]
    
    # Siber zorbalık göstergeleri
    CYBERBULLYING_INDICATORS = [
        r"aptal", r"gerizekalı", r"ölsün", r"intihar",
        r"kimse.*sevmiyor", r"değersiz", r"başarısız",
        r"dışla", r"yalnız", r"yok et",
    ]
    
    # Destek kaynakları
    SUPPORT_RESOURCES = {
        "acil_yasal": {
            "yasal_destek_hatti": {"number": "156", "description": "Ücretsiz hukuki danışma"},
            "siber_suclar": {"email": "siber@egm.gov.tr", "description": "Emniyet Genel Müdürlüğü Siber Suçlar"},
            "ihbar_web": {"url": "https://ihbarweb.org.tr", "description": "İhbarWeb şikayet hattı"},
        },
        "psikolojik_destek": {
            "aile_bakanligi": {"number": "183", "description": "Aile ve Sosyal Hizmetler Bakanlığı"},
            "umut_imseselim": {"number": "116", "description": "İntiharı önleme ve destek hattı"},
            "genclik_destek": {"number": "0850 222 0 123", "description": "Gençlik ve Aile Destek Hattı"},
        },
        "kvkk_basvuru": {
            "kvkk_website": {"url": "https://www.kvkk.gov.tr", "description": "Kişisel Verileri Koruma Kurumu"},
            "kvkk_email": {"email": "kvkk@kvkk.gov.tr", "description": "Başvuru ve şikayet"},
        },
    }
    
    def __init__(self):
        self.active_cases: Dict[str, VictimSupportCase] = {}
        self.total_cases_handled: int = 0
        self.critical_interventions: int = 0
    
    def analyze_threat_message(self, message: str) -> Dict:
        """
        Gelen mesajı analiz et - Şantaj veya siber zorbalık mı?
        """
        message_lower = message.lower()
        
        # Şantaj göstergeleri
        blackmail_hits = []
        for pattern in self.BLACKMAIL_INDICATORS:
            if re.search(pattern, message_lower):
                blackmail_hits.append(pattern)
        
        # Zorbalık göstergeleri
        bullying_hits = []
        for pattern in self.CYBERBULLYING_INDICATORS:
            if re.search(pattern, message_lower):
                bullying_hits.append(pattern)
        
        # Risk seviyesi belirleme
        risk_score = len(blackmail_hits) * 20 + len(bullying_hits) * 10
        
        if risk_score >= 60 or len(blackmail_hits) >= 3:
            severity = "CRITICAL"
        elif risk_score >= 40 or len(blackmail_hits) >= 2:
            severity = "HIGH"
        elif risk_score >= 20:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        # Tür belirleme
        if len(blackmail_hits) > len(bullying_hits):
            threat_type = "blackmail"
        elif len(bullying_hits) > 0:
            threat_type = "cyberbullying"
        else:
            threat_type = "suspicious"
        
        return {
            "threat_detected": risk_score > 0,
            "threat_type": threat_type,
            "severity": severity,
            "risk_score": risk_score,
            "blackmail_indicators_found": blackmail_hits,
            "bullying_indicators_found": bullying_hits,
            "recommended_action": self._get_recommended_action(severity, threat_type),
        }
    
    def _get_recommended_action(self, severity: str, threat_type: str) -> str:
        """Risk seviyesine göre önerilen aksiyon"""
        if severity == "CRITICAL":
            return "DERHAL 156 Yasal Destek Hattı'nı arayın. Ekran görüntülerini kaydedin. Aile/hukuki destek alın."
        elif severity == "HIGH":
            return "KVKK başvurusu yapın. 183 Aile Bakanlığı hattını arayın. Teknik önlemleri uygulayın."
        elif severity == "MEDIUM":
            return "Şüpheli hesapları engelleyin. Gizlilik ayarlarını sıkılaştırın."
        else:
            return "Durumu izleyin. Gerekirse destek alın."
    
    def create_support_case(
        self,
        case_type: str,
        description: str,
        severity: str,
        evidence: Optional[str] = None
    ) -> VictimSupportCase:
        """Yeni destek vakası oluştur"""
        case_id = f"CG-{datetime.utcnow().strftime('%Y%m%d')}-{hash(description) % 10000:04d}"
        
        # Destek planı oluştur
        support_plan = self._generate_support_plan(case_type, severity)
        
        case = VictimSupportCase(
            case_id=case_id,
            created_at=datetime.utcnow(),
            case_type=case_type,
            severity=severity,
            description=description,
            evidence_hash=hashlib.sha256(evidence.encode()).hexdigest()[:16] if evidence else None,
            support_plan=support_plan,
            resources_provided=self._get_relevant_resources(case_type, severity),
        )
        
        self.active_cases[case_id] = case
        self.total_cases_handled += 1
        
        if severity in ["CRITICAL", "HIGH"]:
            self.critical_interventions += 1
        
        return case
    
    def _generate_support_plan(self, case_type: str, severity: str) -> List[str]:
        """Vaka tipine göre destek planı oluştur"""
        base_steps = [
            "1. Panik yapmayın - Çözüm var ve destek alabilirsiniz",
            "2. Tüm kanıtları (mesajlar, ekran görüntüleri) güvenli yerde saklayın",
            "3. Olayı güvendiğiniz bir yetişkine (aile/hoca) bildirin",
        ]
        
        if case_type == "blackmail":
            specific_steps = [
                "4. KESİNLİKLE para ödemeyin - Bu sizi daha çok hedef yapar",
                "5. 156 Yasal Destek Hattı'nı arayın",
                "6. KVKK'ya kişisel veri ihlali başvurusu yapın",
                "7. Şüpheli hesapları tüm platformlarda engelleyin",
            ]
        elif case_type == "cyberbullying":
            specific_steps = [
                "4. Zorbalığı beslemeyin - Cevap vermeyin",
                "5. 183 Aile ve Sosyal Hizmetler Bakanlığı'nı arayın",
                "6. Okul/psikolojik destek alın",
                "7. Sosyal medya platformuna şikayet edin",
            ]
        else:
            specific_steps = [
                "4. Şüpheli durumları raporlayın",
                "5. Güvenlik ayarlarınızı gözden geçirin",
            ]
        
        if severity == "CRITICAL":
            specific_steps.insert(0, "🚨 KRİTİK: Hemen yetkili mercilere başvurun")
        
        return base_steps + specific_steps
    
    def _get_relevant_resources(self, case_type: str, severity: str) -> List[dict]:
        """Vaka tipine göre ilgili kaynakları getir"""
        resources = []
        
        if severity in ["CRITICAL", "HIGH"]:
            resources.append({
                "type": "acil_yasal",
                "hizmet": "156 Yasal Destek",
                "iletisim": "156",
                "aciklama": "7/24 ücretsiz hukuki danışma",
            })
        
        if case_type in ["blackmail", "identity_theft"]:
            resources.append({
                "type": "kvkk",
                "hizmet": "KVKK Başvuru",
                "iletisim": "kvkk.gov.tr",
                "aciklama": "Kişisel veri ihlali şikayeti",
            })
        
        if case_type in ["cyberbullying", "harassment"]:
            resources.append({
                "type": "psikolojik",
                "hizmet": "183 Aile Bakanlığı",
                "iletisim": "183",
                "aciklama": "Psikososyal destek ve danışmanlık",
            })
            resources.append({
                "type": "psikolojik",
                "hizmet": "116 Umut İmseselim",
                "iletisim": "116",
                "aciklama": "İntiharı önleme ve yaşam hattı",
            })
        
        return resources
    
    def get_social_impact_stats(self) -> Dict:
        """Toplumsal etki istatistikleri"""
        active_critical = sum(1 for c in self.active_cases.values() if c.severity in ["CRITICAL", "HIGH"])
        
        return {
            "total_cases_supported": self.total_cases_handled,
            "currently_active_cases": len(self.active_cases),
            "critical_interventions": self.critical_interventions,
            "active_critical_high": active_critical,
            "lives_potentially_saved": self.critical_interventions,  # Her müdahale = potansiyel kurtuluş
            "message": "Her destek vakası = Potansiyel bir intiharın veya ciddi travmanın önüne geçmek",
            "youth_protection": "18-25 yaş grubu öncelikli destek",
        }
    
    def generate_incident_report(self, case_id: str) -> Optional[Dict]:
        """Olay raporu oluştur (yasal başvuru için)"""
        case = self.active_cases.get(case_id)
        if not case:
            return None
        
        return {
            "report_id": f"RAPOR-{case_id}",
            "generated_at": datetime.utcnow().isoformat(),
            "case_type_tr": {
                "blackmail": "Şantaj / Karapara",
                "cyberbullying": "Siber Zorbalık",
                "identity_theft": "Kimlik Hırsızlığı",
                "harassment": "Taciz",
            }.get(case.case_type, case.case_type),
            "severity": case.severity,
            "incident_summary": case.description,
            "timeline": [
                {"step": 1, "action": "Olay tespiti", "status": "completed"},
                {"step": 2, "action": "Risk analizi", "status": "completed"},
                {"step": 3, "action": "Destek planı", "status": "active"},
                {"step": 4, "action": "Yasal başvuru", "status": "pending"},
            ],
            "evidence_hash": case.evidence_hash,
            "recommended_authorities": [
                {"kurum": "Cumhuriyet Savcılığı", "konu": "Şantaj/Tehdit suçu"},
                {"kurum": "KVKK", "konu": "Kişisel veri ihlali"},
                {"kurum": "Aile Mahkemesi", "konu": "Koruma kararı (gerekirse)"},
            ],
            "support_resources_used": case.resources_provided,
        }
    
    def get_prevention_education(self) -> Dict:
        """Önleyici eğitim materyalleri"""
        return {
            "before_incident": {
                "sosyal_medya_guvenligi": [
                    "Profil gizli yapın",
                    "Kimlik bilgilerini paylaşmayın",
                    "Şüpheli linklere tıklamayın",
                    "Zorlayıcı mesajları engelleyin",
                ],
                "dijital_farkindalik": [
                    "Göndermeden önce iki kez düşünün",
                    "Paylaştığınız içerik kalıcıdır",
                    "Özel mesajlar bile sızdırılabilir",
                ],
            },
            "during_incident": {
                "dont": [
                    "Panik yapmayın",
                    "Para ödemeyin",
                    "Suçlayıcı mesajlar atmayın",
                    "Tek başına mücadele etmeyin",
                ],
                "do": [
                    "Kanıtları saklayın",
                    "Güvenilir yetişkine bildirin",
                    "Profesyonel destek alın",
                    "Yasal yollara başvurun",
                ],
            },
            "after_incident": {
                "iyilesme": [
                    "Psikolojik destek alın",
                    "Dijital ayara çekin",
                    "Güvenli hesaplar oluşturun",
                    "Deneyiminizi paylaşarak başkalarına yardım edin",
                ],
            },
        }


# Global instance
cyber_guardian = CyberGuardian()
