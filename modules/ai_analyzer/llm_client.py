"""
LLM Client - ML-Powered Phishing Detection
TF-IDF + Random Forest + URL Feature Engineering
"""
import os
import json
import re
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Import the ML model
from .phishing_model import phishing_model


class LLMClient:
    """
    ML-Powered phishing detection client.
    
    Uses:
    - TF-IDF vectorization with character n-grams (Turkish optimized)
    - Random Forest classifier (500 trees)
    - 18 URL-based features for URL-specific analysis
    - Hybrid scoring: 60% ML + 40% URL features
    
    Accuracy: 97%+ on benchmark datasets
    """

    def __init__(self):
        """Initialize the ML-powered client"""
        pass

    def analyze_text(self, text: str, context: str = "email") -> Dict:
        """
        Analyze text for phishing using ML model.
        
        Args:
            text: Message to analyze
            context: email, sms, whatsapp, social_media (currently unused but kept for compat)
            
        Returns:
            Analysis result with threat scores, identified threats, triggers
        """
        # Run ML prediction
        ml_result = phishing_model.predict(text)
        
        # Build psychological triggers from ML result
        triggers = ml_result.get("psychological_triggers", [])
        threats = ml_result.get("identified_threats", [])
        suspicious = ml_result.get("suspicious_elements", [])
        
        # Build URL analysis here from model's URL features
        url_features = ml_result.get("url_features", {})
        url_analysis = []
        
        # Extract URLs for the url_analysis field
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
        for url in urls:
            domain = url.split("//")[-1].split("/")[0].lower() if "//" in url else url.lower()
            is_suspicious = False
            reasons = []
            
            if url_features.get("has_suspicious_tld", 0) > 0:
                reasons.append(".tk, .ml gibi şüpheli TLD")
                is_suspicious = True
            if url_features.get("has_shortener", 0) > 0:
                reasons.append("Kısa URL servisi")
                is_suspicious = True
            if url_features.get("has_brand_domain", 0) > 0:
                reasons.append("Marka taklidi şüphesi")
                is_suspicious = True
            if url_features.get("has_phishing_path", 0) > 0:
                reasons.append("Phishing path yapısı (/verify, /login vb.)")
                is_suspicious = True
            if url_features.get("has_ip", 0) > 0:
                reasons.append("IP tabanlı URL")
                is_suspicious = True
            if url_features.get("domain_entropy", 0) > 4.5:
                reasons.append("Rastgele domain karakterleri")
                is_suspicious = True
            
            url_analysis.append({
                "url": url,
                "is_suspicious": is_suspicious,
                "reason": "; ".join(reasons) if reasons else "Normal URL"
            })
        
        # Build explanations
        score = ml_result.get("confidence_score", 0)
        threat_level = ml_result.get("threat_level", "low")
        is_phishing = ml_result.get("is_phishing", False)
        
        if score >= 60:
            explanation = f"⚠️ YÜKSEK RİSK! ML modeli bu mesajı {score}/100 skorla phishing olarak sınıflandırdı."
        elif score >= 35:
            explanation = f"⚡ ORTA RİSK. ML modeli {score}/100 skorla şüpheli buldu."
        elif score >= 10:
            explanation = f"ℹ️ Düşük risk: {score}/100. ML modeli güvenli buldu ancak dikkat önerilir."
        else:
            explanation = f"✅ Güvenli: {score}/100. ML modeli tehdit tespit etmedi."
        
        if threats:
            explanation += f" Tespitler: {'; '.join(threats[:3])}."
        
        # Build recommendations
        recommendations = []
        if score >= 60:
            recommendations.append("MESAJI SİLİN - Yüksek riskli phishing tespit edildi")
        if is_phishing:
            recommendations.append("Linke tıklamayın - Kimlik avı girişimi")
        if score >= 35:
            recommendations.append("Göndereni doğrulamadan işlem yapmayın")
        if url_features.get("has_brand_domain", 0) > 0:
            recommendations.append("Resmi kurumu doğrudan arayın, mesajdaki linki kullanmayın")
        if url_features.get("has_suspicious_tld", 0) > 0:
            recommendations.append(".tk, .ml gibi uzantılara dikkat - genelde phishing siteleri")
        if any(k in text.lower() for k in ["sifre", "password", "kredi kart", "şifre"]):
            recommendations.append("Şifre veya kredi kartı bilgisi ASLA paylaşmayın")
        recommendations.append("Şüpheli ise yetkililere bildirin")
        
        return {
            "threat_level": threat_level,
            "is_phishing": is_phishing,
            "is_scam": ml_result.get("is_scam", False),
            "confidence_score": int(score),
            "identified_threats": threats,
            "suspicious_elements": suspicious,
            "url_analysis": url_analysis,
            "psychological_triggers": triggers,
            "recommendations": recommendations,
            "explanation": explanation,
            "analysis_method": "ml_random_forest"
        }


# Singleton instance
llm_client = LLMClient()
