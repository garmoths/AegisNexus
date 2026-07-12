"""
Hacker Psychology Profiler - NLP + LLM-based
Forum postlarından dil analizi ile tehdidin türünü ve ciddiyetini belirle
LLM destekli detaylı analiz için Ollama entegrasyonu
"""
import re
import logging
import requests
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

# Ollama LLM endpoint
OLLAMA_ENDPOINT = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "llama2"

# =========================================================
# NLP SÖZLÜĞÜ VE PATTERN'LER
# =========================================================

HACKER_LANGUAGE_PATTERNS = {
    # Agresif/Tehditkar dil
    "aggressive": {
        "keywords": [
            r"ransomware", r"exploit", r"vulnerability", r"zero-day",
            r"malware", r"trojan", r"backdoor", r"rootkit",
            r"deaththreat", r"blackmail", r"extortion", r"threat"
        ],
        "weight": 40
    },
    
    # Ticari/Para amaçlı
    "commercial": {
        "keywords": [
            r"for sale", r"$\d+", r"price", r"payment", r"crypto",
            r"bitcoin", r"satış", r"fiyat", r"para", r"para kazanç",
            r"komiser", r"satıcı", r"pazarlama"
        ],
        "weight": 30
    },
    
    # Teknik bilgi paylaşımı (hacktivism)
    "technical_sharing": {
        "keywords": [
            r"tutorial", r"howto", r"github", r"code", r"script",
            r"exploit\s*(kit|code)", r"payload", r"source\s*code"
        ],
        "weight": 20
    },
    
    # Spam/Bot
    "spam": {
        "keywords": [
            r"email\s*list", r"spam", r"bot", r"automation",
            r"lead\s*generation", r"marketing", r"database"
        ],
        "weight": 10
    },
    
    # Kimlik hırsızlığı
    "identity_theft": {
        "keywords": [
            r"ssn", r"social\s*security", r"credit\s*card",
            r"bank\s*account", r"passport", r"ssn",
            r"kimlik", r"tc\s*no", r"banka", r"kredi\s*kart"
        ],
        "weight": 45
    },
    
    # Zararlı yazılım dağıtımı
    "malware_distribution": {
        "keywords": [
            r"botnet", r"c2\s*(server)?", r"command\s*and\s*control",
            r"dga", r"dll", r"exe\s*file"
        ],
        "weight": 50
    },
    
    # Uyuşturucu/Yasadışı ürün
    "illegal_goods": {
        "keywords": [
            r"drug", r"fake\s*doc", r"passport", r"license",
            r"ilaç", r"sahte\s*belge", r"pasaport"
        ],
        "weight": 60
    }
}

THREAT_CLASSIFICATION = {
    "MASS_FRAUD": {
        "indicators": ["commercial", "spam", "email_list"],
        "severity": 70,
        "description": "Kütlesel dolandırıcılık - Spam veya kitle fraud"
    },
    "IDENTITY_THEFT": {
        "indicators": ["identity_theft", "commercial"],
        "severity": 85,
        "description": "Kimlik hırsızlığı paketi - Kişisel bilgilerin satışı"
    },
    "MALWARE_DISTRIBUTION": {
        "indicators": ["malware_distribution", "aggressive"],
        "severity": 90,
        "description": "Zararlı yazılım dağıtımı - Siber saldırı hazırlığı"
    },
    "HACKTIVISM": {
        "indicators": ["technical_sharing"],
        "severity": 30,
        "description": "Hacktivist aktivitesi - Bilgi paylaşımı"
    },
    "RANSOMWARE": {
        "indicators": ["aggressive", "malware_distribution"],
        "severity": 95,
        "description": "Ransomware tehdidi - Kritik tehlike"
    },
    "EXTORTION": {
        "indicators": ["aggressive", "identity_theft"],
        "severity": 80,
        "description": "Şantaj/Extortion - Ödeme tehdidi"
    },
    "MARKET_LISTING": {
        "indicators": ["commercial", "spam"],
        "severity": 40,
        "description": "Veri pazarlaması - Açık forum satışı"
    }
}


class HackerPsychologyAnalyzer:
    """Hacker forum dilini analiz eder"""
    
    def __init__(self):
        self.language_patterns = HACKER_LANGUAGE_PATTERNS
        self.threat_types = THREAT_CLASSIFICATION
    
    def analyze_forum_post(self, text: str) -> Dict:
        """Forum postunu analiz et"""
        if not text:
            return {"error": "Boş metin"}
        
        text_lower = text.lower()
        
        # Dil pattern'lerini tara
        found_patterns = {}
        total_score = 0
        
        for pattern_type, config in self.language_patterns.items():
            matches = 0
            for keyword_pattern in config["keywords"]:
                if re.search(keyword_pattern, text_lower):
                    matches += 1
            
            if matches > 0:
                found_patterns[pattern_type] = {
                    "matches": matches,
                    "weight": config["weight"],
                    "score": min(100, matches * config["weight"])
                }
                total_score += found_patterns[pattern_type]["score"]
        
        # Tehdit tipini sınıflandır
        threat_classification = self._classify_threat(found_patterns)
        
        return {
            "detected_patterns": found_patterns,
            "total_language_score": min(100, total_score // 2),  # Normalize
            "threat_type": threat_classification,
            "confidence": self._calculate_confidence(found_patterns),
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def _classify_threat(self, patterns: Dict) -> Dict:
        """Bulunan pattern'lere göre tehdit tipini sınıflandır"""
        pattern_names = set(patterns.keys())
        
        best_match = None
        best_score = 0
        
        for threat_type, config in self.threat_types.items():
            # Kaç indicator match ettiğini say
            matching_indicators = len([ind for ind in config["indicators"] if ind in pattern_names])
            
            if matching_indicators > 0:
                match_score = (matching_indicators / len(config["indicators"])) * 100
                
                if match_score > best_score:
                    best_score = match_score
                    best_match = threat_type
        
        if best_match:
            return {
                "type": best_match,
                "severity": self.threat_types[best_match]["severity"],
                "description": self.threat_types[best_match]["description"],
                "confidence": best_score
            }
        
        return {
            "type": "UNKNOWN",
            "severity": 0,
            "description": "Bilinen tehdit pattern'i eşleşmedi",
            "confidence": 0
        }
    
    def _calculate_confidence(self, patterns: Dict) -> float:
        """Confidence skoru hesapla"""
        if not patterns:
            return 0.0
        
        total_matches = sum(p.get("matches", 0) for p in patterns.values())
        return min(100.0, total_matches * 10.0)


def analyze_breach_in_dark_web(email: str, breach_listings: List[str]) -> Dict:
    """
    Sızıntılı e-postanın dark web'deki pazarlanış şeklini analiz et
    
    Args:
        email: Sızıntı e-postası
        breach_listings: Forum postları (simülasyon için örnek metin)
    
    Returns:
        Analiz raporu
    """
    analyzer = HackerPsychologyAnalyzer()
    
    # Tüm postları analiz et
    post_analyses = []
    overall_threat_score = 0
    
    for listing in breach_listings:
        analysis = analyzer.analyze_forum_post(listing)
        post_analyses.append(analysis)
        
        threat_severity = analysis.get("threat_type", {}).get("severity", 0)
        overall_threat_score += threat_severity
    
    # Ortalama threat skoru
    avg_threat_score = overall_threat_score / len(breach_listings) if breach_listings else 0
    
    # En yaygın tehdit tipini bul
    threat_types_found = {}
    for analysis in post_analyses:
        threat_type = analysis.get("threat_type", {}).get("type", "UNKNOWN")
        threat_types_found[threat_type] = threat_types_found.get(threat_type, 0) + 1
    
    most_common_threat = max(threat_types_found.items(), key=lambda x: x[1])[0] if threat_types_found else "UNKNOWN"
    
    return {
        "email": email,
        "total_listings_analyzed": len(breach_listings),
        "post_analyses": post_analyses,
        "average_threat_severity": avg_threat_score,
        "most_common_threat_type": most_common_threat,
        "overall_risk_level": _get_risk_level(avg_threat_score),
        "recommendations": _get_psychology_recommendations(most_common_threat, avg_threat_score),
        "profile": {
            "hacker_sophistication": "High" if avg_threat_score > 70 else "Medium" if avg_threat_score > 40 else "Low",
            "organizational_level": "Organized group" if avg_threat_score > 80 else "Semi-organized" if avg_threat_score > 50 else "Individual",
            "target_market": "Professional" if avg_threat_score > 75 else "Opportunistic"
        }
    }


def _get_risk_level(score: float) -> str:
    """Score'a göre risk seviyesi döndür"""
    if score >= 85:
        return "CRITICAL"
    elif score >= 70:
        return "HIGH"
    elif score >= 50:
        return "MEDIUM"
    elif score >= 25:
        return "LOW"
    else:
        return "MINIMAL"


def _get_psychology_recommendations(threat_type: str, severity: float) -> List[str]:
    """Tehdit tipi ve şiddetine göre öneriler ver"""
    recommendations = []
    
    if threat_type == "IDENTITY_THEFT":
        recommendations = [
            "🚨 DERHAL kredi kartını kontrol et",
            "Banka hesabını güvenli kılma",
            "Kredi raporu (Equifax, Experian) kontrol et",
            "TCKN'nle kaydedilmiş tüm hesapları kontrol et"
        ]
    elif threat_type == "RANSOMWARE":
        recommendations = [
            "🔴 KRITIK: Sistem güvenlik yazılımını güncelle",
            "Tüm sistemi koruma altına al",
            "Network segmentasyonunu sağla",
            "Backup'ları offline saklı tut"
        ]
    elif threat_type == "MALWARE_DISTRIBUTION":
        recommendations = [
            "Antivirüs taraması yap",
            "Sistem güvenliğini gözden geçir",
            "Dosya indirmelerini kontrol et",
            "Firewall ayarlarını güçlendir"
        ]
    elif threat_type == "MARKET_LISTING":
        recommendations = [
            "Şifreni değiştir",
            "2FA aktif et",
            "İlgili platformlara bildir (KVKK şikayeti)"
        ]
    
    if severity > 70:
        recommendations.insert(0, "⚠️ YÜKSEK RİSK - Hemen harekete geç!")
    
    return recommendations


# =========================================================
# LLM-BASED ADVANCED ANALYSIS
# =========================================================

class PsychologyAnalyzerLLM:
    """LLM-based psychology analyzer for advanced hacker profiling."""
    
    def __init__(self, ollama_url: str = OLLAMA_ENDPOINT):
        self.ollama_url = ollama_url
        self.model = OLLAMA_MODEL
    
    def analyze_with_llm(
        self, 
        forum_post: str,
        pattern_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use LLM to provide detailed analysis of hacker psychology.
        
        Args:
            forum_post: Raw forum post text
            pattern_analysis: Results from pattern-based analysis
            
        Returns:
            Detailed LLM-based analysis
        """
        prompt = self._build_psychology_prompt(forum_post, pattern_analysis)
        llm_analysis = self._call_llm(prompt)
        
        return {
            "pattern_based": pattern_analysis,
            "llm_analysis": llm_analysis,
            "combined_risk_score": self._calculate_combined_score(
                pattern_analysis, 
                llm_analysis
            ),
            "profiler_notes": self._extract_profiler_insights(llm_analysis)
        }
    
    def _build_psychology_prompt(
        self, 
        forum_post: str, 
        pattern_analysis: Dict
    ) -> str:
        """Build LLM prompt for psychology analysis."""
        return f"""
Bir hacker forumu gönderisini analiz edin ve hackerın profilini çıkarın. Türkçe cevap verin.

FORUM GÖNDERİSİ (İlk 500 karakter):
{forum_post[:500]}

ÖN ANALİZ (Pattern Matching Sonuçları):
- Tespit Edilen Dilbilgisi: {pattern_analysis.get('language_patterns', [])}
- Başlangıç Tehdit Sınıflaması: {pattern_analysis.get('threat_type', 'Unknown')}
- Güven Seviyesi: {pattern_analysis.get('confidence', 0):.1%}

LÜTFEN ŞU SORULARI CEVAPLAYIN:

1. **Hackerın Teknisyen Seviyesi**: Bu kişi ne kadar deneyimli görünüyor? (Acemi/Orta/İleri/Uzman)

2. **Motivasyon**: Asıl amacı nedir? (Para/İntikam/Hacktivism/Merak/Örgüt Üyesi)

3. **Hedef Tipi**: Kimi hedefliyor? (Bireyler/SME/Kurumlar/Hükümet)

4. **Profesyonellik**: Organizasyon seviyesi nedir? (Sıradan bireysel/Semi-organize/Organize Grup/Devlet sponsorlu)

5. **Geçmiş Tecrübe**: Daha önce başarılı operasyonlar yaptığı belirtileri var mı?

6. **Tehlikenin Türü**: En yakın tehdit sınıflaması nedir? (Spam/Dolandırıcı/Kimlik Hırsızı/Rançomware/Devlet Aktörü)

7. **Tavsiye**: Bu hedef için savunma önerileri nelerdir?

Yapılandırılmış, profesyonel cevap ver. Önemli noktaları listeleme şeklinde sun.
"""
    
    def _call_llm(self, prompt: str) -> str:
        """Call Ollama for LLM analysis."""
        try:
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "temperature": 0.4,
                },
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                return result.get("response", "").strip()
            else:
                logger.error(f"LLM error: {response.status_code}")
                return self._fallback_analysis()
        
        except requests.exceptions.ConnectionError:
            logger.warning("Ollama not available. Using pattern-based analysis only.")
            return self._fallback_analysis()
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return self._fallback_analysis()
    
    def _fallback_analysis(self) -> str:
        """Fallback when LLM unavailable."""
        return (
            "LLM analizi şu anda sunulamıyor. "
            "Lütfen Ollama'yı (http://localhost:11434) başlatın. "
            "Pattern-based analiz devam ediyor."
        )
    
    def _calculate_combined_score(
        self, 
        pattern_analysis: Dict, 
        llm_analysis: str
    ) -> float:
        """Calculate combined risk score."""
        pattern_score = pattern_analysis.get("threat_score", 50)
        
        # Extract risk indicators from LLM analysis
        llm_multiplier = 1.0
        if "Devlet sponsorlu" in llm_analysis or "Organize Grup" in llm_analysis:
            llm_multiplier = 1.2
        elif "KRITIK" in llm_analysis or "ÇOK YÜKSEK" in llm_analysis:
            llm_multiplier = 1.15
        
        combined = min(100, pattern_score * llm_multiplier)
        return combined
    
    def _extract_profiler_insights(self, llm_analysis: str) -> str:
        """Extract key insights from LLM analysis."""
        # Simple extraction of first 200 chars of key insights
        lines = llm_analysis.split('\n')
        insights = [line.strip() for line in lines if line.strip()]
        return ' '.join(insights[:3])  # First 3 key points


def get_psychology_analyzer_llm() -> PsychologyAnalyzerLLM:
    """Factory for LLM psychology analyzer."""
    return PsychologyAnalyzerLLM()
