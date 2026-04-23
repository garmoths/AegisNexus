"""
LLM Client - DeepSeek API + Groq (Llama) Çift Motorlu Yapı
Eski OpenAI/Claude/Gemini bağlantıları KALDIRILDI.
DeepSeek birincil, Groq (Llama) ikincil motor.
"""
import os
import json
import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# DeepSeek SDK (OpenAI-compatible)
try:
    from openai import OpenAI as DeepSeekClient
    DEEPSEEK_AVAILABLE = True
except ImportError:
    DeepSeekClient = None
    DEEPSEEK_AVAILABLE = False

# Groq SDK
try:
    from groq import Groq
    GROQ_AVAILABLE = True
except ImportError:
    Groq = None
    GROQ_AVAILABLE = False


class LLMClient:
    """
    LLM API client for security analysis.

    Motor stratejisi (fallback zinciri):
    1. DeepSeek (birincil - en güncel/doğru)
    2. Groq/Llama (ikincil - en hızlı, düşük maliyetli)
    3. Local pattern matching (son çare)
    """

    def __init__(self):
        # DeepSeek (birincil)
        self.deepseek_api_key = os.getenv("DEEPSEEK_API_KEY", "")
        self.deepseek_base_url = os.getenv(
            "DEEPSEEK_BASE_URL",
            "https://api.deepseek.com"
        )
        self.deepseek_model = os.getenv(
            "DEEPSEEK_MODEL",
            "deepseek-chat"
        )

        # Groq (ikincil - hızlı yedek)
        self.groq_key = os.getenv("GROQ_API_KEY", "")
        self.groq_model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")

        # Local LLM (opsiyonel - ollama vb.)
        self.use_local = os.getenv("USE_LOCAL_LLM", "false").lower() == "true"
        self.local_base_url = os.getenv("LOCAL_LLM_URL", "http://localhost:11434/v1")
        self.local_model = os.getenv("LOCAL_LLM_MODEL", "llama3.2")

        # İstemci bağlantıları
        self._deepseek_client = None
        self._groq_client = None
        self._local_client = None

        self._init_clients()

    def _init_clients(self):
        """API istemcilerini başlat"""
        if self.deepseek_api_key and DeepSeekClient is not None:
            self._deepseek_client = DeepSeekClient(
                api_key=self.deepseek_api_key,
                base_url=self.deepseek_base_url
            )
            logger.info("DeepSeek istemcisi başlatıldı")

        if self.groq_key and Groq is not None:
            self._groq_client = Groq(api_key=self.groq_key)
            logger.info("Groq istemcisi başlatıldı")

        if self.use_local and DeepSeekClient is not None:
            self._local_client = DeepSeekClient(
                api_key="ollama",
                base_url=self.local_base_url
            )
            logger.info(f"Local LLM istemcisi başlatıldı: {self.local_base_url}")

    def analyze_text(self, text: str, context: str = "email") -> Dict:
        """
        Metin analizi - Phishing/dolandırıcılık tespiti
        
        Args:
            text: Analiz edilecek metin
            context: email, sms, whatsapp, social_media, unknown

        Returns:
            Güvenlik analizi sonucu (Dict)
        """
        prompt = self._build_security_prompt(text, context)

        # 1. DeepSeek (birincil)
        if self._deepseek_client:
            result = self._call_deepseek(prompt)
            if result:
                result["analysis_provider"] = "deepseek"
                return result

        # 2. Groq (ikincil)
        if self._groq_client:
            result = self._call_groq(prompt)
            if result:
                result["analysis_provider"] = "groq"
                return result

        # 3. Local LLM (opsiyonel)
        if self._local_client:
            result = self._call_local(prompt)
            if result:
                result["analysis_provider"] = "local_llm"
                return result

        # 4. Fallback: Local pattern matching
        result = self._local_analysis(text)
        result["analysis_provider"] = "local_pattern_matching"
        return result

    # ──────────────────────────────────────────
    # DeepSeek
    # ──────────────────────────────────────────

    def _call_deepseek(self, prompt: str) -> Optional[Dict]:
        """DeepSeek API çağrısı (birincil motor)"""
        try:
            response = self._deepseek_client.chat.completions.create(
                model=self.deepseek_model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert specializing in phishing detection, "
                            "social engineering analysis, and threat intelligence. "
                            "Analyze messages and return structured JSON only."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2048,
                response_format={"type": "json_object"}
            )
                
            content = response.choices[0].message.content
            if content:
                return self._parse_json_response(content)

            logger.warning("DeepSeek boş yanıt döndü")
            return None

        except Exception as e:
            logger.error(f"DeepSeek API hatası: {e}")
            return None

    # ──────────────────────────────────────────
    # Groq (Llama)
    # ──────────────────────────────────────────

    def _call_groq(self, prompt: str) -> Optional[Dict]:
        """Groq API çağrısı (Llama - hızlı yedek)"""
        try:
            response = self._groq_client.chat.completions.create(
                model=self.groq_model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a cybersecurity expert. Analyze messages for phishing, "
                            "scams, and social engineering. Return ONLY valid JSON."
                        )
                    },
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2048
            )
                
            content = response.choices[0].message.content
            if content:
                return self._parse_json_response(content)

            logger.warning("Groq boş yanıt döndü")
            return None

        except Exception as e:
            logger.error(f"Groq API hatası: {e}")
            return None

    # ──────────────────────────────────────────
    # Local LLM (Ollama vb.)
    # ──────────────────────────────────────────

    def _call_local(self, prompt: str) -> Optional[Dict]:
        """Local LLM çağrısı (opsiyonel)"""
        try:
            response = self._local_client.chat.completions.create(
                model=self.local_model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert. Return JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=2048
            )
                
            content = response.choices[0].message.content
            if content:
                return self._parse_json_response(content)

            return None

        except Exception as e:
            logger.error(f"Local LLM hatası: {e}")
            return None

    # ──────────────────────────────────────────
    # Prompt Builder
    # ──────────────────────────────────────────

    def _build_security_prompt(self, text: str, context: str) -> str:
        """Güvenlik analizi prompt'u oluştur"""
        return json.dumps({
            "task": "cybersecurity_message_analysis",
            "context": context,
            "message": text,
            "analysis_fields": [
                "threat_level",
                "is_phishing",
                "is_scam",
                "confidence_score",
                "identified_threats",
                "suspicious_elements",
                "url_analysis",
                "psychological_triggers",
                "recommendations",
                "explanation"
            ],
            "instructions": (
                f"Analyze this {context} message for phishing, scams, "
                "and social engineering. Return ONLY valid JSON with the above fields. "
                "Be thorough but concise. Focus on actionable insights. "
                "Provide explanation in Turkish."
            )
        })

    def _parse_json_response(self, content: str) -> Optional[Dict]:
        """LLM yanıtından JSON çıkar"""
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            pass

        try:
            json_match = re.search(
                r'```(?:json)?\s*\n?({.*?})\n?\s*```',
                content, re.DOTALL
            )
            if json_match:
                return json.loads(json_match.group(1))
        except (json.JSONDecodeError, AttributeError):
            pass

        try:
            start = content.find('{')
            end = content.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(content[start:end])
        except (json.JSONDecodeError, IndexError):
            pass

        logger.warning("LLM yanıtından JSON çıkarılamadı")
        return None

    # ──────────────────────────────────────────
    # Yerel Analiz (Fallback)
    # ──────────────────────────────────────────

    def _local_analysis(self, text: str) -> Dict:
        """Yerel pattern matching (hiçbir API yoksa)"""
        text_lower = text.lower()

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

        score = 0
        found_threats = []
        suspicious_elements = []
        
        for kw in phishing_keywords:
            if kw in text_lower:
                score += 10
                suspicious_elements.append(f"Anahtar kelime: '{kw}'")

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

        urls = re.findall(
            r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
            text
        )
        url_analysis = []
        for url in urls:
            is_suspicious = any(
                x in url.lower()
                for x in ['.tk', '.ml', '.ga', '.cf', 'bit.ly', 'tinyurl', 'short']
            )
            url_analysis.append({
                "url": url,
                "is_suspicious": is_suspicious,
                "reason": "Kısa URL servisi veya şüpheli TLD" if is_suspicious else "Standart URL"
            })
            if is_suspicious:
                score += 25
                found_threats.append("Şüpheli URL yapısı")

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
            "identified_threats": found_threats or ["Belirgin tehdit tespit edilmedi"],
            "suspicious_elements": suspicious_elements or ["Şüpheli öğe bulunamadı"],
            "url_analysis": url_analysis or [],
            "psychological_triggers": psychological,
            "recommendations": [
                item for item in [
                    "Linke tıklamayın" if urls else "",
                    "Göndereni doğrulayın",
                    "Bankanızı arayın" if "banka" in text_lower else "",
                    "Şüpheli ise silin"
                ] if item
            ],
            "explanation": (
                f"Metin {score}/100 risk skoru ile analiz edildi. "
                f"{len(found_threats)} tehdit tespit edildi."
                if found_threats
                else "Metin güvenli görünüyor."
            ),
            "analysis_method": "local_pattern_matching"
        }


# Singleton instance
llm_client = LLMClient()
