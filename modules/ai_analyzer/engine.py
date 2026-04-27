"""
AI Security Analysis Engine - Ana analiz motoru
"""
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from datetime import datetime
import json

from app.models import URLAnalizHistory
from .llm_client import llm_client
from .url_checker import URLSecurityChecker

class AIAnalyzerEngine:
    """AI güvenlik analiz motoru"""
    
    def __init__(self, db: Session = None):
        self.db = db
        self.url_checker = URLSecurityChecker(db)
    
    def analyze_message(self, message: str, context: str = "email", 
                       sender: str = None, subject: str = None) -> Dict:
        """
        Mesajı analiz et - Tam güvenlik raporu
        
        Args:
            message: Mesaj içeriği
            context: email, sms, whatsapp, social_media
            sender: Gönderen bilgisi
            subject: Konu (email için)
        
        Returns:
            Tam analiz raporu
        """
        # Başlangıç zamanı
        start_time = datetime.utcnow()
        
        # 1. LLM analizi
        llm_result = llm_client.analyze_text(message, context)
        
        # 2. URL çıkar ve kontrol et
        urls = self.url_checker.extract_urls(message)
        url_results = []
        
        for url in urls:
            check_result = self.url_checker.check_url(url)
            url_results.append(check_result)
            
            # LLM URL analizini güncelle (eğer varsa)
            if "url_analysis" in llm_result:
                for ua in llm_result["url_analysis"]:
                    if ua["url"] == url:
                        ua["database_check"] = check_result["in_database"]
                        ua["risk_score"] = check_result["risk_score"]
        
        # 3. Rapor oluştur
        report = self._generate_report(
            message=message,
            context=context,
            sender=sender,
            subject=subject,
            llm_analysis=llm_result,
            url_results=url_results,
            start_time=start_time
        )
        
        return report
    
    def quick_scan(self, message: str) -> Dict:
        """Hızlı tarama - Sadece kritik bilgiler"""
        urls = self.url_checker.extract_urls(message)
        
        # URL'leri kontrol et
        malicious_urls = []
        for url in urls:
            result = self.url_checker.check_url(url)
            if not result["is_safe"]:
                malicious_urls.append({
                    "url": url,
                    "risk_score": result["risk_score"],
                    "reason": result["checks"]
                })
        
        # LLM hızlı analiz
        llm_result = llm_client.analyze_text(message, "unknown")
        
        return {
            "is_safe": len(malicious_urls) == 0 and llm_result["threat_level"] in ["low", "medium"],
            "threat_level": llm_result["threat_level"],
            "malicious_urls": malicious_urls,
            "is_phishing": llm_result["is_phishing"],
            "confidence": llm_result["confidence_score"]
        }
    
    def _generate_report(self, message: str, context: str, sender: str,
                        subject: str, llm_analysis: Dict, 
                        url_results: List[Dict], start_time: datetime) -> Dict:
        """Detaylı rapor oluştur"""
        
        # Güvenlik skoru hesapla (0-100, düşük = güvenli)
        base_score = llm_analysis.get("confidence_score", 0)

        # URL'lerden gelen risk
        url_risk = sum(r.get("risk_score", 0) for r in url_results) / max(len(url_results), 1)

        # Toplam risk skoru (100 = çok tehlikeli)
        total_risk = min((base_score + url_risk) / 2, 100)

        # Eğer skor 0 ise, threat_level'den hesapla
        if total_risk == 0:
            threat_level = llm_analysis.get("threat_level", "low")
            if threat_level == "critical":
                total_risk = 85
            elif threat_level == "high":
                total_risk = 70
            elif threat_level == "medium":
                total_risk = 45
            else:
                total_risk = 15

        # Güvenlik durumu - eğer LLM phishing/scam dediyse direkt TEHLİKELİ
        is_phishing_flag = llm_analysis.get("is_phishing", False)
        is_scam_flag = llm_analysis.get("is_scam", False)
        threat_level_str = llm_analysis.get("threat_level", "low")
        
        if is_phishing_flag or is_scam_flag or threat_level_str in ("critical", "high"):
            safety_status = "TEHLİKELİ"
            action_required = "ACİL"
            # Use calculated total_risk without override
        elif total_risk >= 50:
            safety_status = "TEHLİKELİ"
            action_required = "DİKKAT"
        elif total_risk >= 25:
            safety_status = "ŞÜPHELİ"
            action_required = "DİKKAT"
        else:
            safety_status = "GÜVENLİ"
            action_required = "YOK"
        
        # Öneriler oluştur
        recommendations = self._generate_recommendations(
            llm_analysis, url_results, total_risk
        )
        
        # Rapor
        report = {
            "analysis_id": f"ai-{start_time.strftime('%Y%m%d%H%M%S')}-{hash(message) % 10000}",
            "timestamp": start_time.isoformat(),
            "context": context,
            "message_info": {
                "sender": sender,
                "subject": subject,
                "length": len(message),
                "urls_found": len(url_results)
            },
            "security_assessment": {
                "risk_level": "critical" if is_phishing_flag or is_scam_flag or threat_level_str == "critical" else ("high" if total_risk >= 60 else ("medium" if total_risk >= 25 else "low")),
                "score": round(total_risk, 2),
                "safety_status": safety_status,
                "action_required": action_required,
                "is_phishing": llm_analysis.get("is_phishing", False),
                "is_scam": llm_analysis.get("is_scam", False),
                "threat_level": llm_analysis.get("threat_level", "unknown")
            },
            "detailed_analysis": {
                "ai_analysis": llm_analysis,
                "url_analysis": url_results,
                "identified_threats": llm_analysis.get("identified_threats", []),
                "psychological_triggers": llm_analysis.get("psychological_triggers", []),
                "suspicious_elements": llm_analysis.get("suspicious_elements", [])
            },
            "recommendations": recommendations,
            "summary": self._generate_summary(llm_analysis, url_results, total_risk, message)
        }
        
        return report
    
    def _generate_recommendations(self, llm_analysis: Dict, 
                                 url_results: List[Dict], total_risk: float) -> List[Dict]:
        """Kişiselleştirilmiş öneriler"""
        recommendations = []
        
        # Tehlike seviyesine gore
        ml_conf = llm_analysis.get("confidence_score", 0)
        is_phishing_flag = llm_analysis.get("is_phishing", False)

        if is_phishing_flag or ml_conf >= 50:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "MESAJI SİLİN",
                "description": "Bu mesaj yüksek riskli. Hemen silin ve göndereni engelleyin."
            })
            recommendations.append({
                "priority": "HIGH",
                "action": "HİÇBİR LİNKE TIKLAMAYIN",
                "description": "Mesajdaki tüm linkler tehlikeli olabilir."
            })
        elif ml_conf >= 20:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "DİKKATLİ OLUN",
                "description": "Mesaj şüpheli. Göndereni doğrulamadan işlem yapmayın."
            })
        
        # URL önerileri
        for url_result in url_results:
            if not url_result["is_safe"]:
                recommendations.append({
                    "priority": "HIGH",
                    "action": f"ŞÜPHELİ URL: {url_result['url'][:50]}...",
                    "description": f"Risk skoru: {url_result['risk_score']}/100. "
                                f"Nedenler: {', '.join(url_result['checks'][:2])}"
                })
        
        # Genel öneriler
        if is_phishing_flag or llm_analysis.get("is_scam", False) or ml_conf >= 50:
            recommendations.append({
                "priority": "CRITICAL",
                "action": "🚨 KİMLİK AVI TESPİT EDİLDİ",
                "description": "Bu mesaj %100 phishing/scam özellikleri taşıyor! KESİNLİKLE linke tıklamayın, bilgi girmeyin, yanıt vermeyin."
            })
        
        # Psikolojik tetikleyiciler
        triggers = llm_analysis.get("psychological_triggers", [])
        if "urgency" in triggers:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "ACİLİYET TUZAĞI",
                "description": "Mesaj acele etmenizi istiyor. Gerçek acil durumlarda bile "
                            "önce doğrulama yapın. 'Şimdi' diyorsa durun ve düşünün."
            })
        
        if "fear" in triggers:
            recommendations.append({
                "priority": "MEDIUM",
                "action": "KORKU TEMASI",
                "description": "Hesabınızın kapatılacağı gibi tehditler var. "
                            "Bankanızı/resmi kurumu doğrudan arayın, mesajdaki linkleri kullanmayın."
            })
        
        # Güvenli ise
        if ml_conf < 12 and not recommendations:
            recommendations.append({
                "priority": "LOW",
                "action": "GÜVENLİ",
                "description": "Mesaj güvenli görünüyor. Yine de dikkatli olun."
            })
        
        return recommendations
    
    def _generate_summary(self, llm_analysis: Dict, url_results: List[Dict],
                         total_risk: float, message: str = "") -> str:
        """Kısa ve öz güvenlik özeti oluştur"""

        # Tehdit durumu
        is_phishing_flag = llm_analysis.get("is_phishing", False)
        is_scam_flag = llm_analysis.get("is_scam", False)
        threat_level_str = llm_analysis.get("threat_level", "low")
        
        if is_phishing_flag or is_scam_flag or threat_level_str in ("critical", "high") or total_risk >= 50:
            status = "⚠️ TEHLİKELİ"
            action = "Hemen silin ve göndereni engelleyin"
        elif total_risk >= 25:
            status = "⚡ ŞÜPHELİ"
            action = "Göndereni doğrulamadan işlem yapmayın"
        else:
            status = "✅ GÜVENLİ"
            action = "Yine de dikkatli olun"

        # Tehditler
        threats = llm_analysis.get("identified_threats", [])
        threat_text = ", ".join(threats[:3]) if threats and len(threats) > 0 else "Tehdit tespit edilmedi"

        # URL durumu
        url_count = len(url_results)
        if url_count > 0:
            url_text = f"{url_count} URL tespit edildi"
        else:
            url_text = "URL bulunamadı"

        # Kısa özet
        summary = f"""{status} - Risk Skoru: {round(total_risk, 1)}/100

Tehditler: {threat_text}
{url_text}

Aksiyon: {action}

ML Analizi: {llm_analysis.get("explanation", "Analiz yok")[:200]}..."""

        return summary

# Singleton
analyzer_engine = AIAnalyzerEngine()
