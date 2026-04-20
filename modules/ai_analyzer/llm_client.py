"""
LLM Client - OpenAI/Claude/Gemini API Entegrasyonu
"""
import os
import json
import requests
from typing import Dict, List, Optional
from datetime import datetime

try:
    from google import genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False

class LLMClient:
    """LLM API client for security analysis - OpenAI, Claude, Gemini"""
    
    def __init__(self):
        self.openai_key = os.getenv("OPENAI_API_KEY", "")
        self.claude_key = os.getenv("CLAUDE_API_KEY", "")
        self.gemini_key = os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_GEMINI_KEY", "")
        self.groq_key = os.getenv("GROQ_API_KEY", "")
        self.use_local = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"
        
    def analyze_text(self, text: str, context: str = "email") -> Dict:
        """
        Metin analizi - Phishing/dolandırıcılık tespiti
        
        Args:
            text: Analiz edilecek metin
            context: email, sms, whatsapp, vs.
        """
        prompt = self._build_security_prompt(text, context)
        
        # Önce Groq dene (Llama 3.1 - hızlı ve ucuz)
        if self.groq_key:
            return self._call_groq(prompt)
        # Sonra Gemini
        elif self.gemini_key:
            return self._call_gemini(prompt)
        # Sonra Claude
        elif self.claude_key:
            return self._call_claude(prompt)
        # Sonra OpenAI
        elif self.openai_key:
            return self._call_openai(prompt)
        # Fallback: Local pattern matching
        else:
            return self._local_analysis(text)
    
    def _build_security_prompt(self, text: str, context: str) -> str:
        """Güvenlik analizi prompt'u oluştur"""
        return f"""You are a cybersecurity expert analyzing {context} messages for phishing, scams, and social engineering attempts.

Analyze the following message and provide a detailed security assessment:

MESSAGE:
{text}

Provide your analysis in this exact JSON format:
{{
    "threat_level": "low|medium|high|critical",
    "is_phishing": true|false,
    "is_scam": true|false,
    "confidence_score": 0-100,
    "identified_threats": ["list", "of", "threats"],
    "suspicious_elements": ["suspicious", "elements", "found"],
    "url_analysis": [
        {{
            "url": "extracted_url",
            "is_suspicious": true|false,
            "reason": "why suspicious"
        }}
    ],
    "psychological_triggers": ["urgency", "fear", "greed", "authority", "etc"],
    "recommendations": ["action", "items"],
    "explanation": "Detailed explanation in Turkish"
}}

Be thorough but concise. Focus on actionable insights."""

    def _call_claude(self, prompt: str) -> Dict:
        """Claude API çağrısı"""
        try:
            headers = {
                "x-api-key": self.claude_key,
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "claude-3-haiku-20240307",
                "max_tokens": 2000,
                "messages": [{"role": "user", "content": prompt}]
            }
            
            response = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result["content"][0]["text"]
                # JSON çıkarma
                return self._extract_json(content)
            else:
                return self._local_analysis(prompt)
                
        except Exception as e:
            print(f"Claude API error: {e}")
            return self._local_analysis(prompt)
    
    def _call_groq(self, prompt: str) -> Dict:
        """Groq API çağrısı (Llama 3.1 - hızlı!)"""
        try:
            headers = {
                "Authorization": f"Bearer {self.groq_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "llama-3.1-8b-instant",  # Hızlı ve ucuz
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            }
            
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=10  # Groq çok hızlı!
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                return self._extract_json(content)
            else:
                print(f"Groq API error: {response.status_code}")
                return self._local_analysis(prompt)
                
        except Exception as e:
            print(f"Groq API error: {e}")
            return self._local_analysis(prompt)
    
    def _call_openai(self, prompt: str) -> Dict:
        """OpenAI API çağrısı"""
        try:
            headers = {
                "Authorization": f"Bearer {self.openai_key}",
                "Content-Type": "application/json"
            }
            
            data = {
                "model": "gpt-3.5-turbo",
                "messages": [
                    {"role": "system", "content": "You are a cybersecurity expert."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 2000
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result["choices"][0]["message"]["content"]
                return self._extract_json(content)
            else:
                return self._local_analysis(prompt)
                
        except Exception as e:
            print(f"OpenAI API error: {e}")
            return self._local_analysis(prompt)
    
    def _call_gemini(self, prompt: str) -> Dict:
        """Gemini API çağrısı (Google GenAI SDK)"""
        try:
            if not GENAI_AVAILABLE:
                print("Google GenAI SDK not installed")
                return self._local_analysis(prompt)
            
            # Yeni SDK ile client oluştur
            client = genai.Client(api_key=self.gemini_key)
            
            # Gemini Pro model ile generate (stabil sürüm)
            response = client.models.generate_content(
                model="gemini-pro",
                contents=prompt
            )
            
            # Yanıtı parse et
            content = response.text
            return self._extract_json(content)
                
        except Exception as e:
            print(f"Gemini API error: {e}")
            return self._local_analysis(prompt)
    
    def _extract_json(self, text: str) -> Dict:
        """Metinden JSON çıkar"""
        try:
            # JSON bloğu bul
            start = text.find("{")
            end = text.rfind("}") + 1
            if start >= 0 and end > start:
                json_str = text[start:end]
                return json.loads(json_str)
            else:
                return self._local_analysis(text)
        except:
            return self._local_analysis(text)
    
    def _local_analysis(self, text: str) -> Dict:
        """Yerel pattern matching (API yoksa)"""
        text_lower = text.lower()
        
        # Tehlike anahtar kelimeleri
        phishing_keywords = [
            "hesabınız", "şifreniz", "parolanız", "kredi kartı", "banka",
            "account", "password", "verify", "confirm", "suspended", "limited",
            "tıklayın", "click here", "linke tıkla", "acil", "hemen", "şimdi",
            "ücretsiz", "free", "kazandınız", "won", "ödül", "prize",
            "http://", "https://", ".tk", ".ml", "bit.ly", "tinyurl"
        ]
        
        urgent_keywords = ["acil", "hemen", "şimdi", "24 saat", "süre doluyor", "limited time"]
        fear_keywords = ["hesabınız kapatılacak", "engellenecek", "suspended", "terminate"]
        authority_keywords = ["banka", "devlet", "polis", "jandarma", "güvenlik", "security"]
        
        # Skor hesapla
        score = 0
        found_threats = []
        suspicious_elements = []
        
        for kw in phishing_keywords:
            if kw in text_lower:
                score += 10
                suspicious_elements.append(f"Anahtar kelime: '{kw}'")
        
        # Psikolojik tetikleyiciler
        psychological = []
        if any(k in text_lower for k in urgent_keywords):
            score += 15
            psychological.append("urgency")
            found_threats.append("Aciliyet yaratarak acele karar aldırma")
        
        if any(k in text_lower for k in fear_keywords):
            score += 20
            psychological.append("fear")
            found_threats.append("Korku teması (hesap kapatma tehdidi)")
        
        if any(k in text_lower for k in authority_keywords):
            score += 10
            psychological.append("authority")
        
        # URL kontrolü
        import re
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        url_analysis = []
        for url in urls:
            is_suspicious = any(x in url.lower() for x in ['.tk', '.ml', '.ga', '.cf', 'bit.ly', 'tinyurl', 'short'])
            url_analysis.append({
                "url": url,
                "is_suspicious": is_suspicious,
                "reason": "Kısa URL servisi veya şüpheli TLD" if is_suspicious else "Standart URL"
            })
            if is_suspicious:
                score += 25
                found_threats.append("Şüpheli URL yapısı")
        
        # Sonuç
        if score >= 70:
            threat_level = "critical"
        elif score >= 50:
            threat_level = "high"
        elif score >= 30:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return {
            "threat_level": threat_level,
            "is_phishing": score >= 50,
            "is_scam": score >= 40,
            "confidence_score": min(score, 100),
            "identified_threats": found_threats if found_threats else ["Belirgin tehdit tespit edilmedi"],
            "suspicious_elements": suspicious_elements if suspicious_elements else ["Şüpheli öğe bulunamadı"],
            "url_analysis": url_analysis if url_analysis else [],
            "psychological_triggers": psychological,
            "recommendations": [
                "Linke tıklamayın" if urls else "",
                "Göndereni doğrulayın",
                "Bankanızı arayın" if "banka" in text_lower else "",
                "Şüpheli ise silin"
            ],
            "explanation": f"Metin {score}/100 risk skoru ile analiz edildi. {len(found_threats)} tehdit tespit edildi." if found_threats else "Metin güvenli görünüyor.",
            "analysis_method": "local_pattern_matching"
        }


# Singleton instance
llm_client = LLMClient()
