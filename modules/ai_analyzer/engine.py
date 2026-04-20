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

        # Güvenlik durumu
        if total_risk >= 70:
            safety_status = "TEHLİKELİ"
            action_required = "ACİL"
        elif total_risk >= 40:
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
                "risk_level": "high" if total_risk >= 70 else ("medium" if total_risk >= 40 else "low"),
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
        
        # Tehlike seviyesine göre
        if total_risk >= 70:
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
        elif total_risk >= 40:
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
        if llm_analysis.get("is_phishing"):
            recommendations.append({
                "priority": "HIGH",
                "action": "KİMLİK AVI TESPİTİ",
                "description": "Bu mesaj kimlik avı (phishing) özellikleri taşıyor. "
                            "Kullanıcı adı, şifre veya kredi kartı bilgisi istiyorsa ASLA paylaşmayın."
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
        if total_risk < 20 and not recommendations:
            recommendations.append({
                "priority": "LOW",
                "action": "GÜVENLİ",
                "description": "Mesaj güvenli görünüyor. Yine de dikkatli olun."
            })
        
        return recommendations
    
    def _generate_summary(self, llm_analysis: Dict, url_results: List[Dict], 
                         total_risk: float, message: str = "") -> str:
        """Profesyonel Türkçe güvenlik raporu oluştur"""
        
        # Rapor başlığı ve meta bilgiler
        report_lines = [
            "=" * 60,
            "           AEGIS NEXUS - AI GÜVENLİK ANALİZ RAPORU",
            "=" * 60,
            "",
        ]
        
        # 1. GENEL DEĞERLENDİRME (Executive Summary)
        report_lines.append("📊 GENEL DEĞERLENDİRME")
        report_lines.append("-" * 40)
        
        if total_risk >= 70:
            report_lines.append("🔴 SONUÇ: BU BİR DOLANDIRICILIK / KİMLİK AVI MESAJIDIR!")
            report_lines.append("   • Mesaj yüksek riskli içerik barındırıyor")
            report_lines.append("   • Acil önlem alınması gerekiyor")
        elif total_risk >= 40:
            report_lines.append("🟡 SONUÇ: ŞÜPHELİ MESAJ")
            report_lines.append("   • Dikkatli olun ve doğrulama yapın")
            report_lines.append("   • Hassas bilgi paylaşmayın")
        else:
            report_lines.append("🟢 SONUÇ: GÜVENLİ GÖRÜNÜYOR")
            report_lines.append("   • Belirgin tehdit tespit edilmedi")
            report_lines.append("   • Yine de temkinli olun")
        
        report_lines.append("")
        
        # 2. METİN ANALİZİ
        report_lines.append("📝 METİN İÇERİK ANALİZİ")
        report_lines.append("-" * 40)
        
        is_phishing = llm_analysis.get("is_phishing", False)
        is_scam = llm_analysis.get("is_scam", False)
        
        if is_phishing:
            report_lines.append("⚠️  Bu mesaj KİMLİK AVI (PHISHING) özellikleri taşıyor!")
            report_lines.append("   → Sahte banka/kurum kimliği kullanılarak bilgi çalmaya çalışılıyor")
        
        if is_scam:
            report_lines.append("⚠️  Bu mesaj DOLANDIRICILIK amaçlı!")
            report_lines.append("   → Para/kripto talep eden sahte senaryolar var")
        
        if not is_phishing and not is_scam:
            report_lines.append("✓ Metin içeriği dolandırıcılık patternlerine uymuyor")
        
        # Metin uzunluğu ve yapı
        words = len(message.split())
        chars = len(message)
        report_lines.append(f"   • Kelime sayısı: {words}")
        report_lines.append(f"   • Karakter sayısı: {chars}")
        report_lines.append("")
        
        # 3. URL / LİNK ANALİZİ
        report_lines.append("🔗 URL GÜVENLİK ANALİZİ")
        report_lines.append("-" * 40)
        
        if url_results:
            high_risk_urls = [r for r in url_results if r["risk_score"] >= 70]
            medium_risk_urls = [r for r in url_results if 40 <= r["risk_score"] < 70]
            low_risk_urls = [r for r in url_results if 0 < r["risk_score"] < 40]
            safe_urls = [r for r in url_results if r["risk_score"] == 0]
            
            if high_risk_urls:
                report_lines.append(f"🚨 YÜKSEK RİSKLİ LİNKLER ({len(high_risk_urls)} adet):")
                for url_data in high_risk_urls:
                    url = url_data["url"]
                    score = url_data.get("risk_score", 0)
                    report_lines.append(f"   • {url}")
                    report_lines.append(f"     🔴 Risk Skoru: {score}/100 - TEHLİKELİ!")
                    checks = url_data.get("checks", [])
                    if checks:
                        for check in checks[:3]:
                            report_lines.append(f"       ⚠️  {check}")
                report_lines.append("")
            
            if medium_risk_urls:
                report_lines.append(f"⚠️  ŞÜPHELİ LİNKLER ({len(medium_risk_urls)} adet):")
                for url_data in medium_risk_urls:
                    url = url_data["url"]
                    score = url_data.get("risk_score", 0)
                    report_lines.append(f"   • {url}")
                    report_lines.append(f"     🟡 Risk Skoru: {score}/100 - DİKKAT!")
                    checks = url_data.get("checks", [])
                    if checks:
                        for check in checks[:2]:
                            report_lines.append(f"       ⚡ {check}")
                report_lines.append("")
            
            if low_risk_urls:
                report_lines.append(f"ℹ️  DÜŞÜK RİSKLİ LİNKLER ({len(low_risk_urls)} adet):")
                for url_data in low_risk_urls:
                    url = url_data["url"]
                    score = url_data.get("risk_score", 0)
                    report_lines.append(f"   • {url} (Skor: {score}/100)")
                report_lines.append("")
            
            if safe_urls:
                report_lines.append(f"✓ GÜVENLİ LİNKLER ({len(safe_urls)} adet)")
                for url_data in safe_urls:
                    report_lines.append(f"   • {url_data['url']}")
                report_lines.append("")
            
            report_lines.append("📌 URL ANALİZİ SONUCU:")
            if high_risk_urls:
                report_lines.append("   🔴 TESPİT EDİLEN URL'LER YÜKSEK RİSKLİ!")
                report_lines.append("   → Bu linkler PHISHING sitesi olabilir")
                report_lines.append("   → ASLA TIKLAMAYIN!")
            elif medium_risk_urls:
                report_lines.append("   ⚠️  URL'ler ŞÜPHELİ özellikler taşıyor")
                report_lines.append("   → Dikkatli olun ve doğrulama yapın")
            elif low_risk_urls:
                report_lines.append("   ℹ️  URL'lerde düşük risk tespit edildi")
                report_lines.append("   → Yine de dikkatli olun")
            else:
                report_lines.append("   ✓ URL'ler güvenli görünüyor")
        else:
            report_lines.append("ℹ️  Mesajda link bulunmuyor")
        
        report_lines.append("")
        
        # 4. TEKNİK TEHDİT ANALİZİ
        threats = llm_analysis.get("identified_threats", [])
        if threats:
            report_lines.append("🎯 TESPİT EDİLEN TEKNİK TEHDİTLER")
            report_lines.append("-" * 40)
            for i, threat in enumerate(threats, 1):
                report_lines.append(f"{i}. {threat}")
            report_lines.append("")
        
        # 5. PSİKOLOJİK MANİPÜLASYON
        triggers = llm_analysis.get("psychological_triggers", [])
        if triggers:
            report_lines.append("🧠 PSİKOLOJİK MANİPÜLASYON TESPİTİ")
            report_lines.append("-" * 40)
            
            trigger_descriptions = {
                "urgency": "⏰ Acelilik / Acele ettirme - 'Hemen', 'Şimdi', '24 saat'",
                "fear": "😰 Korku / Panik - 'Hesabınız kapanacak', 'Sızdırıldı'",
                "greed": "💰 Açgözlülük - 'Kazandınız', 'Büyük ödül', 'Yatırım'",
                "authority": "👔 Sahte Otorite - 'Banka', 'Devlet', 'Polis'",
                "curiosity": "🔍 Merak - 'Bakın ne buldum', 'Gizli bilgi'",
                "scarcity": "⚡ Kıtlık - 'Son 5 adet', 'Sınırlı süre'"
            }
            
            for trigger in triggers:
                desc = trigger_descriptions.get(trigger, trigger)
                report_lines.append(f"   • {desc}")
            
            report_lines.append("")
            report_lines.append("💡 NEDEN TEHLİKELİ?")
            report_lines.append("   Bu mesaj sizi acele karar vermeye zorluyor.")
            report_lines.append("   Gerçek kurumlar asla böyle acil dil kullanmaz.")
            report_lines.append("")
        
        # 6. GÜVENLİK PUANI VE RİSK METRİĞİ
        report_lines.append("📈 GÜVENLİK METRİKLERİ")
        report_lines.append("-" * 40)
        confidence = llm_analysis.get("confidence_score", 50)
        report_lines.append(f"   • AI Güven Skoru: %{confidence}")
        report_lines.append(f"   • Toplam Risk Puanı: {total_risk:.0f}/100")
        
        if total_risk >= 70:
            report_lines.append("   • Risk Seviyesi: 🔴 YÜKSEK (Hemen önlem alın)")
        elif total_risk >= 40:
            report_lines.append("   • Risk Seviyesi: 🟡 ORTA (Dikkatli olun)")
        else:
            report_lines.append("   • Risk Seviyesi: 🟢 DÜŞÜK (Güvenli görünüyor)")
        
        report_lines.append("")
        
        # 7. AI AÇIKLAMASI
        explanation = llm_analysis.get("explanation", "")
        if explanation:
            report_lines.append("🤖 AI DEĞERLENDİRMESİ")
            report_lines.append("-" * 40)
            report_lines.append(f"   {explanation}")
            report_lines.append("")
        
        # 8. ÖNERİLER
        report_lines.append("📋 GÜVENLİK ÖNERİLERİMİZ")
        report_lines.append("-" * 40)
        
        if total_risk >= 70:
            report_lines.append("🚨 ACİL ÖNLEMLER:")
            report_lines.append("   1. Bu mesajı HEMEN silin")
            report_lines.append("   2. Göndereni engelleyin")
            report_lines.append("   3. HİÇBİR linke tıklamayın")
            report_lines.append("   4. E-postayı spam olarak işaretleyin")
            report_lines.append("   5. Gerçek kurumu arayıp bilgilendirin")
            report_lines.append("")
            report_lines.append("⚠️  UNUTMAYIN:")
            report_lines.append("   • Bankalar asla e-postayla şifre istemez")
            report_lines.append("   • Resmi kurumlar 'acil' diye tehdit etmez")
            report_lines.append("   • Linklere tıklamadan önce adresi kontrol edin")
        elif total_risk >= 40:
            report_lines.append("⚡ DİKKAT EDİLMESİ GEREKENLER:")
            report_lines.append("   • Göndereni doğrulamadan işlem yapmayın")
            report_lines.append("   • Şüpheli linkleri kontrol edin")
            report_lines.append("   • Hassas bilgi isteniyorsa durun ve arayın")
        else:
            report_lines.append("✓ TEMEL GÜVENLİK:")
            report_lines.append("   • Normal güvenlik önlemlerini uygulayın")
            report_lines.append("   • Gerekirse göndereni doğrulayın")
        
        report_lines.append("")
        
        # 9. SONUÇ VE KAPANIŞ
        report_lines.append("=" * 60)
        report_lines.append("                    RAPOR SONU")
        report_lines.append("=" * 60)
        report_lines.append("")
        report_lines.append("Bu rapor AegisNexus AI Güvenlik Asistanı tarafından")
        report_lines.append(f"oluşturulmuştur. | Tarih: {datetime.utcnow().strftime('%d.%m.%Y %H:%M')}")
        report_lines.append("")
        
        if total_risk >= 70:
            report_lines.append("⚠️  BU MESAJ BİR GÜVENLİK TEHDİDİ İÇERİYOR!")
            report_lines.append("   Lütfen önerilen önlemleri hemen uygulayın.")
        
        return "\n".join(report_lines)


# Singleton
analyzer_engine = AIAnalyzerEngine()
