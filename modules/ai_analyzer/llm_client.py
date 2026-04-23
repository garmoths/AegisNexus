
"""
LLM Client - Local Pattern Matching Only
"""
import os, json, re, logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class LLMClient:
    """Local pattern matching ile phishing tespiti"""
    def __init__(self):
        pass
    
    def analyze_text(self, text: str, context: str = "email") -> Dict:
        result = self._local_analysis(text)
        result["analysis_provider"] = "local_pattern_matching"
        return result
    
    def _local_analysis(self, text: str) -> Dict:
        text_lower = text.lower()
        score = 0
        found_threats = []
        suspicious_elements = []
        psychological = []
        
        # Keywords
        keywords = [
            "hesabiniz", "sifreniz", "parolaniz", "kredi karti", "banka",
            "account", "password", "verify", "confirm", "suspended", "limited",
            "tiklayin", "tikla", "click here", "linke",
            "ucretsiz", "free", "kazandiniz", "won", "odul", "prize",
            "askiya", "kapatilacak", "engellenecek", "dogrulama",
            "guvenlik", "oturum", "guncelle", "onay",
            "hesap", "sure", "doluyor", "tehdit", "bloke", "kisitli",
            "login", "sign in", "security", "alert", "warning",
            "acil", "hemen", "simdi", "tehlike", "uyari",
            "bit.ly", "tinyurl", "shorturl",
        ]
        for kw in keywords:
            if kw in text_lower:
                score += 8
                suspicious_elements.append(f"Keyword: '{kw}'")
        
        # Urgency
        urgent = ["acil", "hemen", "simdi", "24 saat", "sure doluyor", "limited time", "tehlike", "uyari"]
        if any(k in text_lower for k in urgent):
            score += 15
            psychological.append("urgency")
            found_threats.append("Aciliyet yaratarak acele karar aldirma")
        
        # Fear
        fear = ["kapatilacak", "engellenecek", "askiya", "bloke", "kisitli", "tehdit", "suspended", "terminate", "silinecek"]
        if any(k in text_lower for k in fear):
            score += 20
            psychological.append("fear")
            found_threats.append("Korku/tehdit temasi (psikolojik baski)")
        
        # Authority
        auth = ["banka", "devlet", "polis", "jandarma", "guvenlik", "security", "yetkili", "resmi", "makam"]
        if any(k in text_lower for k in auth):
            score += 10
            psychological.append("authority")
        
        # URL analysis
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        url_analysis = []
        has_suspicious_url = False
        for url in urls:
            domain = url.split("//")[-1].split("/")[0].lower() if "//" in url else url.lower()
            is_suspicious = any(x in url.lower() for x in [".tk", ".ml", ".ga", ".cf", "bit.ly", "tinyurl"])
            for dk in ["guvenlik", "hesap", "dogrulama", "onay", "secure", "verify", "login", "confirm", "update", "account", "bank", "security", "sifre"]:
                if dk in domain:
                    is_suspicious = True
            url_analysis.append({"url": url, "is_suspicious": is_suspicious, "reason": "Supheli domain" if is_suspicious else "Normal"})
            if is_suspicious:
                score += 25
                has_suspicious_url = True
                found_threats.append(f"Supheli URL: {url[:40]}")
        
        # Fake bank detection
        bank_names = ["bank", "garanti", "akbank", "isbank", "halkbank", "vakifbank", "ziraat", "yapikredi", "finans", "denizbank", "hsbc", "paypal", "apple", "google", "microsoft", "amazon"]
        for url in urls:
            domain = url.split("//")[-1].split("/")[0].lower() if "//" in url else url.lower()
            for bank in bank_names:
                if bank in domain and not any(official in domain for official in [".com.tr", ".gov.tr", ".org.tr"]):
                    score += 35
                    found_threats.append(f"SAHTE KURUM: '{bank}' adi kullaniliyor!")
                    break
        
        # Extra
        if text.count("!") >= 2:
            score += 5
        upper_ratio = sum(1 for c in text if c.isupper()) / max(len(text), 1)
        if upper_ratio > 0.3 and len(text) > 50:
            score += 10
            suspicious_elements.append("Asiri buyuk harf")
        
        # Decision
        if score >= 50:
            threat_level = "critical"
        elif score >= 25:
            threat_level = "high"
        elif score >= 10:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        # Build explanation
        if found_threats:
            threat_str = ", ".join(found_threats[:3])
            explanation = f"Risk Skoru: {score}/100. {len(found_threats)} tehdit: {threat_str}."
        else:
            explanation = f"Risk Skoru: {score}/100. Belirgin tehdit yok."
        
        # Build recommendations
        recs = []
        if has_suspicious_url or urls:
            recs.append("Linke tiklamayin - guvenilirligini dogrulayin")
        recs.append("Gondericiyi dogrulamadan islem yapmayin")
        if "banka" in text_lower or "hesap" in text_lower:
            recs.append("Bankanizi/resmi kurumu direkt arayin")
        if any(k in text_lower for k in ["sifre", "password", "kredi kart"]):
            recs.append("Sifre/bilgi paylasmayin")
        recs.append("Supheli mesaji silin ve engelleyin")
        
        return {
            "threat_level": threat_level,
            "is_phishing": score >= 20,
            "is_scam": score >= 15,
            "confidence_score": min(score, 100),
            "identified_threats": found_threats,
            "suspicious_elements": suspicious_elements,
            "url_analysis": url_analysis,
            "psychological_triggers": psychological,
            "recommendations": recs,
            "explanation": explanation,
            "analysis_method": "local_pattern_matching"
        }

llm_client = LLMClient()
