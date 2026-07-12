"""
Breach Intel Utility Functions
"""
import logging
from typing import Dict, List
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class BreachRiskCalculator:
    """Sızıntı riski hesaplayan utility"""
    
    # Veri türüne göre risk puanları
    DATA_TYPE_SCORES = {
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
        "TCKN": 85,
        "Passport": 75,
        "Driver license": 70,
    }
    
    @staticmethod
    def calculate_breach_severity(data_classes: List[str]) -> int:
        """Veri sınıflarından sızıntı şiddetini hesapla"""
        total_score = 0
        
        for data_class in data_classes:
            score = BreachRiskCalculator.DATA_TYPE_SCORES.get(data_class, 15)
            total_score += score
        
        return min(100, total_score)
    
    @staticmethod
    def is_zombie_account_risky(last_activity_date: str) -> bool:
        """Hesap ne kadar eski ise o kadar riskli"""
        try:
            activity_date = datetime.fromisoformat(last_activity_date)
            days_inactive = (datetime.now() - activity_date).days
            
            # 2+ yıl hiç aktivite yok ise çok riskli
            return days_inactive > 730
        except:
            return True
    
    @staticmethod
    def calculate_total_exposure(breaches: List[Dict]) -> int:
        """Tüm sızıntılardaki toplam kayıt sayısını hesapla"""
        total = 0
        
        for breach in breaches:
            # Bu info genelde HIBP'den geliyor
            total += breach.get("total_records", 0)
        
        return total


class BreachRecommendationEngine:
    """Sızıntı sonrası eylem önerileri"""
    
    @staticmethod
    def get_recommendations(
        email: str,
        breaches: List[Dict],
        zombie_accounts: List[Dict],
        threat_profile: Dict
    ) -> List[str]:
        """Kullanıcıya öneriler ver"""
        recommendations = []
        
        # Sızıntı tipine göre
        if breaches:
            critical_breaches = [b for b in breaches if BreachRiskCalculator.calculate_breach_severity(b.get("data_classes", [])) > 70]
            
            if critical_breaches:
                recommendations.append("🚨 KRİTİK: Şifreni DERHAL değiştir")
                recommendations.append("2FA (İki Faktörlü Doğrulama) aktif et")
            
            # Finansal bilgi sızıyor mu?
            financial_breaches = [b for b in breaches if any(dc in b.get("data_classes", []) for dc in ["Credit cards", "Bank account numbers"])]
            if financial_breaches:
                recommendations.append("Banka hesaplarını kontrol et ve kartları bloke et")
                recommendations.append("Kredi raporunu (Equifax, Experian) talep et")
        
        # Zombi hesaplar
        if zombie_accounts:
            recommendations.append(f"❌ {len(zombie_accounts)} adet eski hesabı kapatmayı düşün")
            recommendations.append("Unutulmuş hesaplarının şifrelerini değiştir")
        
        # Threat profili
        if threat_profile:
            threat_type = threat_profile.get("threat_type", {}).get("type", "")
            
            if threat_type == "IDENTITY_THEFT":
                recommendations.append("Kimlik hırsızlığı paketi pazarlanıyor - Kredi takibi yap")
            elif threat_type == "RANSOMWARE":
                recommendations.append("Sistem güvenliğini maksimum seviyeye çık")
            elif threat_type == "MALWARE_DISTRIBUTION":
                recommendations.append("Sistem taraması yap ve güvenlik yazılımını güncelle")
        
        # Genel
        if not recommendations:
            recommendations.append("Düzenli olarak şifrelerini değiştirmeye devam et")
        
        recommendations.append("Aegis Nexus ile düzenli kontroller yap")
        
        return recommendations


def format_breach_summary(email: str, breaches: List[Dict]) -> str:
    """Sızıntı özeti Türkçe formatla"""
    if not breaches:
        return f"{email} hesabı bilinen sızıntılarda görünmüyor. Güvenli kalmanız devam edin."
    
    count = len(breaches)
    breach_names = ", ".join([b.get("name", "Unknown") for b in breaches[:3]])
    
    if count > 3:
        breach_names += f" ve {count - 3} kayıt daha"
    
    data_types = set()
    for breach in breaches:
        for dt in breach.get("data_classes", []):
            data_types.add(dt)
    
    data_summary = ", ".join(list(data_types)[:5])
    
    return f"""
{count} ayrı sızıntıda görüldü: {breach_names}

Sızan veri türleri: {data_summary}

Tavsiye: Şifreni değiştir ve 2FA aktif et.
KVKK başvurusu yapman gerekebilir.
    """


def create_kvkk_report(email: str, breaches: List[Dict]) -> Dict:
    """KVKK kişisel veri ihlali başvurusu raporu oluştur"""
    return {
        "report_type": "KVKK Kişisel Veri İhlali Bildirim Formu",
        "personal_info": {
            "email": email,
            "notification_date": datetime.now().isoformat()
        },
        "data_breach_details": {
            "total_breaches": len(breaches),
            "breaches": [
                {
                    "name": b.get("name"),
                    "date": b.get("breach_date"),
                    "affected_data": b.get("data_classes", [])
                }
                for b in breaches
            ]
        },
        "legal_basis": "KVKK Madde 4 - Kişisel Veri İhlali",
        "required_actions": [
            "Bu raporu kvkk.gov.tr üzerinden ilgili kuruluşa gönder",
            "Başvuru takip numarasını kaydet",
            "Kuruluştan cevap zamanlaması maksimum 30 gün"
        ],
        "where_to_apply": "kvkk.gov.tr - İVB (İletişim Ve Bilgi Sistemi)",
        "template_prepared_by": "Aegis Nexus Platform",
        "timestamp": datetime.now().isoformat()
    }
