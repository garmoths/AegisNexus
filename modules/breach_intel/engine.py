"""
Breach Intelligence Engine - Sızıntı İstihbaratı Motoru
"""
from __future__ import annotations

import re
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass


@dataclass
class BreachRecord:
    """Sızıntı kaydını temsil eder"""
    email: str
    breach_name: str
    breach_date: str
    data_types: List[str]
    severity_score: int  # 0-100
    first_seen: datetime
    
    def to_dict(self) -> dict:
        return {
            "email": self.email,
            "breach_name": self.breach_name,
            "breach_date": self.breach_date,
            "data_types": self.data_types,
            "severity_score": self.severity_score,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
        }


class BreachIntelligenceEngine:
    """
    Sızıntı istihbarat motoru
    - E-posta sızıntı takibi
    - Şifre açığa çıkma uyarısı
    - Şantaj riski analizi
    """
    
    # Riskli veri türleri ve puanları
    RISK_SCORES = {
        "Passwords": 50,
        "Password": 50,
        "HashedPasswords": 40,
        "Email addresses": 20,
        "Phone numbers": 30,
        "Names": 10,
        "Usernames": 15,
        "Dates of birth": 25,
        "Physical addresses": 20,
        "Credit cards": 80,
        "Bank account numbers": 90,
        "Social media profiles": 35,
        "Photos": 30,
        "Private messages": 60,
    }
    
    def __init__(self):
        self.monitored_emails: Set[str] = set()
        self.breach_cache: Dict[str, List[BreachRecord]] = {}
        self.total_breaches_tracked: int = 0
    
    def calculate_breach_severity(self, data_classes: List[str]) -> int:
        """Sızıntı şiddetini hesapla (0-100)"""
        total_score = 0
        for data_type in data_classes:
            total_score += self.RISK_SCORES.get(data_type, 10)
        return min(100, total_score)
    
    def analyze_shantaj_risk(self, email: str, breaches: List[dict]) -> dict:
        """
        Şantaj riski analizi
        Gençlerin sızdırılan verileri şantaj malzemesi olarak kullanılabilir
        """
        risk_factors = []
        risk_score = 0
        
        for breach in breaches:
            data_types = breach.get("data_classes", [])
            
            # Yüksek riskli veri türleri kontrolü
            if "Photos" in data_types or "Social media profiles" in data_types:
                risk_factors.append("Fotoğraf/sosyal medya profili sızdı - Şantaj riski YÜKSEK")
                risk_score += 30
            
            if "Private messages" in data_types:
                risk_factors.append("Özel mesajlar sızdı - KVKK ihlali + şantaj riski")
                risk_score += 40
            
            if "Passwords" in data_types or "Password" in data_types:
                risk_factors.append("Şifreler açık metin sızdı - Diğer hesaplar tehlikede")
                risk_score += 50
            
            if "Credit cards" in data_types or "Bank account numbers" in data_types:
                risk_factors.append("Finansal bilgiler sızdı - Dolandırıcılık riski")
                risk_score += 60
        
        # Yaş grubu tahmini (e-posta domaininden)
        email_domain = email.split("@")[-1] if "@" in email else ""
        young_domains = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com"]
        if email_domain in young_domains:
            risk_factors.append("Genç kullanıcı profili - Psikolojik destek önerilir")
        
        return {
            "shantaj_risk_score": min(100, risk_score),
            "risk_level": "YÜKSEK" if risk_score >= 60 else "ORTA" if risk_score >= 30 else "DÜŞÜK",
            "risk_factors": risk_factors,
            "recommendations": self._get_recommendations(risk_score, breaches),
        }
    
    def _get_recommendations(self, risk_score: int, breaches: List[dict]) -> List[str]:
        """Risk seviyesine göre öneriler"""
        recommendations = []
        
        if risk_score >= 60:
            recommendations.extend([
                "DERHAL tüm şifrelerinizi değiştirin - Kriptografik Kalkan modülünü kullanın",
                "Çok faktörlü doğrulama (2FA) aktif edin",
                "Banka ve finansal hesaplarınızı kontrol edin",
                "Şantaj durumunda: 156 YASAL DESTEK HATTI",
                "KVKK'ya şikayet başvurusu yapın (kvkk.gov.tr)",
            ])
        elif risk_score >= 30:
            recommendations.extend([
                "Şüpheli hesaplarda şifre değiştirin",
                "E-posta hesabınızda 2FA aktif edin",
                "Sosyal medya hesaplarınızı gözden geçirin",
            ])
        else:
            recommendations.append("Önlem olarak şifrelerinizi güncelleyin")
        
        return recommendations
    
    def generate_kvkk_report(self, email: str, breaches: List[dict]) -> dict:
        """KVKK başvurusu için otomatik rapor oluştur"""
        report_id = hashlib.sha256(f"{email}{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
        
        affected_services = [b.get("Title", b.get("Name", "Bilinmeyen")) for b in breaches]
        
        return {
            "report_id": report_id,
            "report_type": "KVKK_Kisisel_Veri_Ihlali_Basvurusu",
            "applicant_email": email,
            "generated_at": datetime.utcnow().isoformat(),
            "affected_services": affected_services,
            "violated_data_types": list(set(
                dt for b in breaches for dt in b.get("data_classes", [])
            )),
            "application_text": self._generate_kvkk_text(email, breaches),
            "supporting_documents": [
                "E-posta sahipliği kanıtı",
                "Sızıntı kayıtları (ekte)",
                "Risk analiz raporu",
            ],
            "where_to_apply": {
                "online": "https://www.kvkk.gov.tr",
                "email": "kvkk@kvkk.gov.tr",
                "address": "KVKK Merkez Ofis, Ankara",
            }
        }
    
    def _generate_kvkk_text(self, email: str, breaches: List[dict]) -> str:
        """KVKK başvuru metni oluştur"""
        breach_list = ", ".join([b.get("Title", "Bilinmeyen") for b in breaches[:5]])
        return f"""
Sayın Kurul,

{email} e-posta adresime ait kişisel verilerimin aşağıdaki veri ihlallerinde 
açığa çıktığını tespit ettim:

{breach_list}

Bu ihlallerde; şifrelerim, kişisel bilgilerim ve potansiyel olarak 
finansal verilerim sızdırılmıştır. 

6698 sayılı Kişisel Verilerin Korunması Kanunu kapsamında:
1) Veri ihlalinin detaylarının tarafıma bildirilmesini,
2) Sorumlular hakkında gerekli incelemenin yapılmasını,
3) Kişisel verilerimin güvenliğinin sağlanması için tedbirlerin alınmasını
   talep ediyorum.

Saygılarımla,
[Ad Soyad]
{email}
""".strip()
    
    def get_youth_protection_resources(self) -> dict:
        """Genç kullanıcılar için koruma kaynakları"""
        return {
            "acil_destek": {
                "yasal_destek": "156",
                "siber_zorbalik": "183",
                "emniyet_siber": "siber@egm.gov.tr",
            },
            "psikolojik_destek": {
                "genclik_ve_aile": "183",
                "umut_imseselim": "116",
                "aile_ve_sosyal": "aile.gov.tr",
            },
            "teknik_onlemler": [
                "Hemen şifre değiştir (Kriptografik Kalkan)",
                "2FA aktif et",
                "Şüpheli hesapları kontrol et",
                "Sosyal medya gizlilik ayarlarını sıkılaştır",
            ],
            "kvkk_basvuru_rehberi": {
                "adim_1": "kvkk.gov.tr adresine git",
                "adim_2": "Başvuru formunu doldur",
                "adim_3": "Sızıntı kanıtlarını ekle",
                "adim_4": "Takip numarası ile süreci izle",
            }
        }


# Global engine instance
breach_engine = BreachIntelligenceEngine()
