"""
Groq-based breach report generator using Cloud LLM.
Generates detailed Turkish breach summaries using llama2-70b model.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

try:
    from groq import Groq
except ImportError:
    Groq = None

logger = logging.getLogger(__name__)

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

class BreachReportGenerator:
    """Generates detailed Turkish reports for breached data using Groq."""
    
    def __init__(self, api_key: str = None):
        self.api_key = api_key or GROQ_API_KEY
        if not self.api_key:
            logger.warning("GROQ_API_KEY not found. Fallback mode will be used.")
        
        if Groq and self.api_key:
            self.client = Groq(api_key=self.api_key)
        else:
            self.client = None
    
    def generate_breach_summary(
        self, 
        domain: str, 
        breaches: List[Dict[str, Any]]
    ) -> str:
        """
        Generate Turkish summary for breaches.
        
        Args:
            domain: Domain/company name
            breaches: List of breach objects
            
        Returns:
            Türkçe rapor metni
        """
        if not breaches:
            return "İyi haber! Bu domain bilinen veri sızıntılarında bulunmamıştır."
        
        breach_details = self._format_breaches_for_prompt(breaches)
        prompt = self._build_report_prompt(domain, breaches, breach_details)
        
        if self.client:
            report_text = self._call_groq(prompt)
        else:
            report_text = self._demo_report_fallback()
        
        return report_text
    
    def _format_breaches_for_prompt(self, breaches: List[Dict]) -> str:
        """Format breach data for LLM prompt."""
        formatted = []
        for b in breaches:
            company = b.get('company_name', b.get('domain', 'Unknown'))
            records = b.get('email_count', 'N/A')
            data_types = ', '.join(b.get('data_types', []))
            
            formatted.append(
                f"- {company}: {records} kayıt sızdırıldı ({data_types})"
            )
        
        return "\n".join(formatted)
    
    def _build_report_prompt(self, domain: str, breaches: List[Dict], breach_details: str) -> str:
        """Build the prompt for LLM."""
        return f"""
Aşağıdaki veri sızıntısı hakkında kısa, profesyonel bir Türkçe güvenlik raporu yazın:

DOMAIN/ŞİRKET: {domain}
SAYSTILAR: {len(breaches)} sızıntı bulundu

SIZZINTILARIN DETAYLARı:
{breach_details}

LÜTFEN:
1. Tehlikenin türünü ve ciddiyetini açıkla (1-2 cümle)
2. Etkilenen veri türlerini listele
3. Acil yapılması gerekenler (3-4 madde)
4. İçinde "⚠️ ACİL:" başlığı varsa kırmızı bayrak koy
5. Cevabı kısa, profesyonel ve Türkçe yaz

Yanıt ver:
"""
    
    def _call_groq(self, prompt: str) -> str:
        """Call Groq API and get response."""
        try:
            message = self.client.chat.completions.create(
                messages=[
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.3,
                max_tokens=1000,
            )
            
            response_text = message.choices[0].message.content.strip()
            return response_text
        
        except Exception as e:
            logger.error(f"Groq API error: {e}")
            return self._demo_report_fallback()
    
    def _demo_report_fallback(self) -> str:
        """Fallback when Groq unavailable."""
        return (
            "⚠️ Şu anda LLM analizi sunulamıyor. "
            "Temel analiz: Veri sızıntısına maruz kaldınız. "
            "Acilen şifre değişikliği ve iki faktörlü kimlik doğrulamayı etkinleştirin."
        )
