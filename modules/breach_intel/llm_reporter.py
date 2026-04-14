"""
LLM-based breach report generator using Ollama.
Generates detailed Turkish breach summaries and recommendations.
"""

import requests
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama2"

class BreachReportGenerator:
    """Generates detailed Turkish reports for breached data."""
    
    def __init__(self, ollama_url: str = OLLAMA_ENDPOINT):
        self.ollama_url = ollama_url
        self.model = OLLAMA_MODEL
        self._check_ollama_available()
    
    def _check_ollama_available(self) -> bool:
        """Check if Ollama service is running."""
        try:
            response = requests.get(
                self.ollama_url.replace("/api/generate", "/api/tags"),
                timeout=2
            )
            return response.status_code == 200
        except Exception as e:
            logger.warning(f"Ollama not available: {e}. Using demo mode.")
            return False
    
    def generate_breach_summary(
        self, 
        email: str, 
        breaches: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate Turkish summary for breaches.
        
        Args:
            email: Email address
            breaches: List of breach objects from HIBP
            
        Returns:
            Summary with Türkçe rapor metni
        """
        if not breaches:
            return {
                "email": email,
                "summary": "İyi haber! E-posta adresiniz bilinen veri sızıntılarında bulunmamıştır.",
                "risk_level": "LOW",
                "actions": []
            }
        
        breach_details = self._format_breaches_for_prompt(breaches)
        prompt = self._build_report_prompt(email, breaches, breach_details)
        
        report_text = self._call_llm(prompt)
        
        return {
            "email": email,
            "breach_count": len(breaches),
            "breaches": breaches,
            "summary": report_text,
            "risk_level": self._calculate_risk_level(breaches),
            "actions": self._generate_actions(breaches),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _format_breaches_for_prompt(self, breaches: List[Dict]) -> str:
        """Format breach data for LLM prompt."""
        formatted = []
        for b in breaches:
            formatted.append(
                f"- {b.get('Name', 'Unknown')}: "
                f"{b.get('BreachDate', 'Tarih bilinmiyor')} tarihinde, "
                f"{b.get('PwnCount', 0):,} kayıt sızdırıldı. "
                f"Sızan veri: {', '.join(b.get('DataClasses', []))}"
            )
        return "\n".join(formatted)
    
    def _build_report_prompt(
        self, 
        email: str, 
        breaches: List[Dict],
        breach_details: str
    ) -> str:
        """Build LLM prompt for report generation."""
        return f"""
Aşağıda bir e-posta adresinin maruz kaldığı veri sızıntılarının listesi verilmiştir.
Buna dayanarak, Türkçe olarak detaylı bir güvenlik raporu oluştur.

E-posta: {email}
Sızıntı Sayısı: {len(breaches)}

SIRTILIK TARİHÇESİ:
{breach_details}

LÜTFEN:
1. En eski ve en yeni sızıntıları vurgula
2. Hangi türde verilerin sızdığını analiz et (şifre, kredi kartı, kimlik vb)
3. Türkçe olarak 3-4 cümlelik bir risk özeti yaz
4. En iyi 3 hareketi öner (örn: şifre değişikliği, iki faktörlü kimlik doğrulama, kredi kartı izleme)
5. Acil işaretleme gerekirse "⚠️ ACİL" başlığı ekle

Türkçe cevap ver, profesyonel ton kullan:
"""
    
    def _call_llm(self, prompt: str) -> str:
        """Call Ollama LLM and get response."""
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.3,  # Lower temperature for consistent output
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                logger.error(f"LLM API error: {response.status_code}")
                return self._demo_report_fallback()
        
        except requests.exceptions.ConnectionError:
            logger.warning("Ollama not reachable. Using demo mode.")
            return self._demo_report_fallback()
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return self._demo_report_fallback()
    
    def _demo_report_fallback(self) -> str:
        """Fallback when Ollama unavailable."""
        return (
            "🔴 Şu anda LLM analizi sunulamıyor. "
            "Lütfen Ollama'yı yükleyin ve http://localhost:11434'te çalıştırın.\n\n"
            "Temel analiz: Veri sızıntısına maruz kaldınız. "
            "Acilen şifre değişikliği ve iki faktörlü kimlik doğrulamayı etkinleştirin."
        )
    
    def _calculate_risk_level(self, breaches: List[Dict]) -> str:
        """Calculate overall risk level."""
        if len(breaches) == 0:
            return "LOW"
        elif len(breaches) <= 2:
            total_records = sum(b.get("PwnCount", 0) for b in breaches)
            return "MEDIUM" if total_records < 1000000 else "HIGH"
        else:
            return "CRITICAL"
    
    def _generate_actions(self, breaches: List[Dict]) -> List[str]:
        """Generate recommended actions based on breaches."""
        actions = []
        
        # Check for sensitive data types
        all_data_classes = set()
        for b in breaches:
            all_data_classes.update(b.get("DataClasses", []))
        
        if any(dc in all_data_classes for dc in ["Passwords", "Email", "Username"]):
            actions.append("🔐 Şifre değişikliği (tüm hesaplarda)")
        
        if any(dc in all_data_classes for dc in ["Credit card", "Payment"]):
            actions.append("💳 Kredi kartınızı bloke edin ve banka ile iletişime geçin")
        
        if "Phone Number" in all_data_classes:
            actions.append("📱 2FA ayarlarını kontrol edin")
        
        if "SSN" in all_data_classes or "Identity" in all_data_classes:
            actions.append("⚠️ Kredi notu dondurmayı (credit freeze) düşünün")
        
        if not actions:
            actions.append("✓ Genel hesap güvenliği taraması yapın")
        
        return actions
    
    def generate_forum_analysis_report(
        self,
        forum_post: str,
        threat_classification: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate detailed analysis of forum post threat level.
        
        Args:
            forum_post: Raw forum post text
            threat_classification: Result from psychology analyzer
            
        Returns:
            Detailed analysis with Türkçe açıklama
        """
        prompt = self._build_forum_analysis_prompt(forum_post, threat_classification)
        analysis = self._call_llm(prompt)
        
        return {
            "original_post_preview": forum_post[:200] + "..." if len(forum_post) > 200 else forum_post,
            "threat_type": threat_classification.get("threat_type", "Unknown"),
            "confidence": threat_classification.get("confidence", 0),
            "detailed_analysis": analysis,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def _build_forum_analysis_prompt(
        self, 
        forum_post: str, 
        threat_class: Dict
    ) -> str:
        """Build prompt for forum threat analysis."""
        return f"""
Aşağıdaki hacker forumu gönderisini analiz et ve ne kadar tehlikeli olduğunu Türkçe olarak açıkla.

FORUM GÖNDERİSİ:
{forum_post[:500]}

YAPAY ZEKA ÖN ANALİZİ:
- Tehdit Türü: {threat_class.get('threat_type')}
- Güven Seviyesi: {threat_class.get('confidence')}%
- Temel Dilbilgisi: {threat_class.get('language_pattern')}

LÜTFEN:
1. Bu gönderinin ne kadar profesyonel olduğunu değerlendir
2. Hedef kitlesi kimler olabilir (bireyler, şirketler, vb)
3. Tehlikenin şiddeti (1-10 ölçeğinde)
4. Olası motivasyonu (para, intikam, ideoloji, vb)
5. Tavsiye edilen savunma önlemleri

Türkçe, profesyonel ve yapılandırılmış cevap ver.
"""


def get_report_generator() -> BreachReportGenerator:
    """Factory function to get report generator instance."""
    return BreachReportGenerator()
