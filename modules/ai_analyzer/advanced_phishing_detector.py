"""
Advanced AI Phishing Detection Algorithm
3-Module Hybrid Scoring System with Mathematical Amplification

Modules:
- URL Module (w_url = 0.40): DB similarity + SSL check
- Text+Emotion Module (w_text = 0.35): Gemini LLM + urgency rules + VAD emotion
- Confidence Score C (w_conf = 0.25): Data quality assessment

Final Score Formula:
  S_raw = C * (0.40 * s_url + 0.35 * s_text) + (1 - C) * 0.5
  S* = S^β / (S^β + (1-S)^β), β = 1.5
"""

import os
import re
import ssl
import json
import math
import socket
import logging
import requests
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from datetime import datetime
from dataclasses import dataclass

# Third-party imports
from rapidfuzz import fuzz, distance
import google.generativeai as genai
from transformers import pipeline

# Database
from modules.phishing_detector.cache_db import get_db_connection

logger = logging.getLogger(__name__)

# Constants
W_URL = 0.40
W_TEXT = 0.35
W_CONF = 0.25  # Confidence weight (implicit in formula)
BETA = 1.5
PRIOR = 0.5

# API Keys from env
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")


@dataclass
class PhishingResult:
    verdict: str  # "PHİSHİNG", "ŞÜPHELİ", "DÜŞÜK RİSK", "TEMİZ"
    score: float  # S_star (0.0 - 1.0)
    confidence: float  # C (0.0 - 1.0)
    breakdown: Dict
    hard_override: bool
    reason: str


class AdvancedPhishingDetector:
    """3-Module Hybrid Phishing Detection System"""
    
    def __init__(self):
        self.phishing_urls = []
        self._load_phishing_db()
        self._init_gemini()
        self._init_emotion_model()
    
    def _load_phishing_db(self):
        """Load phishing URLs from database (1.5M records)"""
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Get all phishing URLs from cache
                cursor.execute("""
                    SELECT DISTINCT url FROM phishing_urls
                    WHERE risk_score > 40
                    ORDER BY checked_at DESC
                    LIMIT 100000
                """)
                self.phishing_urls = [row[0] for row in cursor.fetchall()]
                logger.info(f"Loaded {len(self.phishing_urls)} phishing URLs from DB")
        except Exception as e:
            logger.warning(f"Could not load phishing DB: {e}")
            self.phishing_urls = []
    
    def _init_gemini(self):
        """Initialize Gemini API"""
        if GEMINI_API_KEY:
            genai.configure(api_key=GEMINI_API_KEY)
            self.gemini_model = genai.GenerativeModel('gemini-2.0-flash')
        else:
            logger.warning("GEMINI_API_KEY not found")
            self.gemini_model = None
    
    def _init_emotion_model(self):
        """Initialize emotion analysis model"""
        try:
            self.emotion_analyzer = pipeline(
                "text-classification",
                model="j-hartmann/emotion-english-distilroberta-base",
                return_all_scores=True,
                device=-1  # CPU
            )
        except Exception as e:
            logger.warning(f"Could not load emotion model: {e}")
            self.emotion_analyzer = None
    
    def detect(self, message: str, url: Optional[str] = None) -> PhishingResult:
        """
        Main detection function
        
        Args:
            message: Message text to analyze
            url: Optional URL to check
        
        Returns:
            PhishingResult with verdict and scores
        """
        # === MODULE 1: URL ANALYSIS ===
        s_url, url_breakdown, hard_override = self._analyze_url(url)
        
        if hard_override:
            return PhishingResult(
                verdict="PHİSHİNG",
                score=1.0,
                confidence=1.0,
                breakdown={"s_url": 1.0, **url_breakdown},
                hard_override=True,
                reason="DB'de benzerlik >= 0.90 - kesin eşleşme"
            )
        
        # === MODULE 2: TEXT + EMOTION ANALYSIS ===
        s_text, text_breakdown = self._analyze_text(message)
        
        # === MODULE 3: CONFIDENCE SCORE ===
        confidence, conf_breakdown = self._calculate_confidence(url, message, text_breakdown)
        
        # === FINAL SCORE CALCULATION ===
        S_raw = confidence * (W_URL * s_url + W_TEXT * s_text) + (1 - confidence) * PRIOR
        
        # Amplification
        S_star = self._amplify_score(S_raw)
        
        # Verdict
        verdict = self._get_verdict(S_star)
        
        # Reason from LLM
        reason = text_breakdown.get("llm_reason", "Analiz tamamlandı")
        
        return PhishingResult(
            verdict=verdict,
            score=round(S_star, 4),
            confidence=round(confidence, 4),
            breakdown={
                "s_url": round(s_url, 4),
                "s_text": round(s_text, 4),
                "s_llm": round(text_breakdown.get("s_llm", 0), 4),
                "s_urgency": round(text_breakdown.get("s_urgency", 0), 4),
                "s_emotion": round(text_breakdown.get("s_emotion", 0), 4),
                "ssl_score": round(url_breakdown.get("ssl_score", 0), 4),
                "db_similarity": round(url_breakdown.get("db_similarity", 0), 4),
            },
            hard_override=False,
            reason=reason
        )
    
    def _analyze_url(self, url: Optional[str]) -> Tuple[float, Dict, bool]:
        """
        URL Module Analysis
        Returns: (s_url, breakdown, hard_override)
        """
        if not url:
            return 0.0, {"ssl_score": 0.0, "db_similarity": 0.0}, False
        
        # A) Database Similarity Score (70% weight)
        s_sim, max_similarity = self._calculate_db_similarity(url)
        
        # Hard Override Check
        if max_similarity >= 0.90:
            return 1.0, {"ssl_score": 0.0, "db_similarity": max_similarity}, True
        
        # B) SSL Score (30% weight)
        ssl_score = self._check_ssl(url)
        
        # C) Suspicious Domain Pattern Detection (override if high risk)
        domain_risk = self._check_suspicious_domain(url)
        if domain_risk > 0.8:
            return domain_risk, {"ssl_score": ssl_score, "db_similarity": s_sim, "domain_risk": domain_risk}, False
        
        # D) Combine
        s_url = 0.70 * s_sim + 0.30 * ssl_score
        
        breakdown = {
            "ssl_score": ssl_score,
            "db_similarity": s_sim,
            "max_similarity": max_similarity,
            "domain_risk": domain_risk
        }
        
        return s_url, breakdown, False
    
    def _check_suspicious_domain(self, url: str) -> float:
        """
        Check for suspicious domain patterns
        Returns: 0.0 - 1.0
        """
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            # Suspicious TLDs and subdomains
            suspicious_patterns = [
                # Fake support domains
                "help-center", "support-center", "helpdesk", "customer-service",
                # Fake verification domains  
                "verify-account", "verify", "confirm-account", "auth-verify",
                # Fake copyright/legal domains
                "copyright", "legal-notice", "compliance", "appeals",
                # Suspicious TLDs
                ".support", ".help", ".center", ".top", ".xyz", ".tk"
            ]
            
            # Check for suspicious patterns in domain
            risk_score = 0.0
            for pattern in suspicious_patterns:
                if pattern in domain:
                    risk_score += 0.25
            
            # Check if domain pretends to be a real service but isn't
            brand_impersonation = [
                "instagram", "facebook", "google", "apple", "amazon",
                "microsoft", "netflix", "paypal", "spotify", "twitter"
            ]
            
            for brand in brand_impersonation:
                if brand in domain:
                    # If brand name is in domain but not the official domain
                    official_domains = [
                        "instagram.com", "facebook.com", "google.com",
                        "apple.com", "amazon.com", "microsoft.com",
                        "netflix.com", "paypal.com", "spotify.com", "twitter.com"
                    ]
                    if not any(official in domain for official in official_domains):
                        risk_score += 0.4
            
            return min(risk_score, 1.0)
            
        except Exception as e:
            logger.debug(f"Domain check error: {e}")
            return 0.0
    
    def _calculate_db_similarity(self, url: str) -> Tuple[float, float]:
        """
        Calculate DB similarity using Levenshtein + Jaro-Winkler
        Returns: (normalized_sim, max_raw_sim)
        """
        if not self.phishing_urls:
            return 0.0, 0.0
        
        max_sim = 0.0
        url_lower = url.lower()
        url_len = len(url)
        
        for db_url in self.phishing_urls:
            db_url_lower = db_url.lower()
            db_len = len(db_url)
            
            # Levenshtein distance (normalized)
            lev_dist = distance.Levenshtein.distance(url_lower, db_url_lower)
            max_len = max(url_len, db_len)
            lev_sim = 1 - (lev_dist / max_len) if max_len > 0 else 0
            
            # Jaro-Winkler similarity
            jaro_sim = fuzz.WRatio(url_lower, db_url_lower) / 100.0
            
            # Average
            combined_sim = (lev_sim + jaro_sim) / 2.0
            
            if combined_sim > max_sim:
                max_sim = combined_sim
                
            # Early exit if perfect match found
            if max_sim >= 0.95:
                break
        
        return max_sim, max_sim
    
    def _check_ssl(self, url: str) -> float:
        """
        Check SSL certificate
        Returns: 0.0 (valid), 0.6 (no SSL), 0.8 (expired), 0.5 (error)
        """
        try:
            parsed = urlparse(url)
            hostname = parsed.netloc
            
            if not hostname:
                return 0.5
            
            # HTTP (no SSL)
            if url.startswith("http://"):
                return 0.6
            
            # HTTPS - check certificate
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return 0.8
                    
                    # Check expiration
                    not_after = cert.get("notAfter")
                    if not_after:
                        expire_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        if expire_date < datetime.now():
                            return 0.8
                    
                    return 0.0  # Valid
                    
        except ssl.SSLCertVerificationError:
            return 0.8  # Invalid/expired
        except socket.error:
            return 0.5  # Connection error
        except Exception as e:
            logger.debug(f"SSL check error: {e}")
            return 0.5
    
    def _analyze_text(self, message: str) -> Tuple[float, Dict]:
        """
        Text + Emotion Module Analysis
        Returns: (s_text, breakdown)
        """
        if not message or len(message.strip()) < 10:
            return 0.0, {"s_llm": 0.0, "s_urgency": 0.0, "s_emotion": 0.3}
        
        # A) LLM Semantic Score (50%)
        s_llm, llm_reason, llm_quality = self._llm_score(message)
        
        # B) Rule-based Urgency Score (30%)
        s_urgency = self._urgency_score(message)
        
        # C) VAD Emotion Score (20%)
        s_emotion = self._emotion_score(message)
        
        # Combine
        s_text = 0.50 * s_llm + 0.30 * s_urgency + 0.20 * s_emotion
        
        breakdown = {
            "s_llm": s_llm,
            "s_urgency": s_urgency,
            "s_emotion": s_emotion,
            "llm_reason": llm_reason,
            "llm_quality": llm_quality
        }
        
        return s_text, breakdown
    
    def _llm_score(self, message: str) -> Tuple[float, str, float]:
        """
        Get phishing score from Gemini LLM
        Returns: (score, reason, quality)
        """
        if not self.gemini_model:
            return 0.5, "LLM not available", 0.0
        
        prompt = """Sen bir siber güvenlik analistinin phishing tespit asistanısın.
Verilen metni değerlendir. Şu kriterlere bak:
- Kimlik bilgisi toplama girişimi var mı?
- Sahte otorite veya marka taklidi var mı?
- Manipülatif veya aldatıcı dil var mı?
- Kullanıcıyı bir aksiyona zorlamaya çalışıyor mu?

SADECE şu JSON formatında yanıt ver, başka hiçbir şey yazma:
{"score": <0.0 ile 1.0 arası float>, "reason": "<max 10 kelime>"}

0.0 = kesinlikle temiz, 1.0 = kesinlikle phishing/sosyal mühendislik

Metin: """ + message[:2000]
        
        try:
            response = self.gemini_model.generate_content(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=100
                )
            )
            
            text = response.text.strip()
            
            # Extract JSON
            json_match = re.search(r'\{[^}]+\}', text)
            if json_match:
                data = json.loads(json_match.group())
                score = float(data.get("score", 0.5))
                reason = data.get("reason", "Değerlendirildi")
                return min(max(score, 0.0), 1.0), reason, 1.0
            
            return 0.5, "JSON parse error", 0.4
            
        except Exception as e:
            logger.debug(f"Gemini error: {e}")
            return 0.5, "LLM timeout/error", 0.0
    
    def _urgency_score(self, message: str) -> float:
        """
        Rule-based urgency scoring
        Returns: 0.0 - 1.0
        """
        text_lower = message.lower()
        
        categories = {
            "urgency": [
                "hemen", "acil", "son gün", "bugün sona eriyor",
                "urgent", "immediately", "expires today", "act now",
                "şimdi", "acele", "son tarih", "süre doluyor",
                "24 saat", "48 saat", "saat içinde", "gün içinde",
                "24 hours", "48 hours", "hours", "immediate"
            ],
            "threat": [
                "hesabınız askıya alındı", "yasal işlem", "bloke",
                "suspended", "legal action", "blocked", "engellendi",
                "kapatılacak", "silinecek", "askıya alındı",
                "kalıcı olarak kapatılması", "geri döndürülemez",
                "permanently closed", "irreversible", "permanently suspended",
                "telif hakkı", "copyright", "ihlal", "infringement"
            ],
            "identity": [
                "şifrenizi girin", "doğrulayın", "kimliğinizi onayla",
                "verify your identity", "confirm password", "enter credentials",
                "şifre", "parola", "kart numarası", "cvv",
                "itiraz formu", "appeal form", "doğrulamanız gerekmektedir"
            ]
        }
        
        hits = 0
        for category, keywords in categories.items():
            if any(kw in text_lower for kw in keywords):
                hits += 1
        
        # If multiple hits from same category, weight more heavily
        total_matches = sum(1 for category in categories.values() for kw in category if kw in text_lower)
        
        # Base score from category hits
        score = min(hits / 3.0, 1.0)
        
        # Boost if multiple keyword matches
        if total_matches >= 3:
            score = min(score + 0.2, 1.0)
        if total_matches >= 5:
            score = min(score + 0.2, 1.0)
        
        return score
    
    def _emotion_score(self, message: str) -> float:
        """
        VAD emotion analysis
        Returns: 0.0 - 1.0 (phishing pattern: low valence + high arousal)
        """
        if not self.emotion_analyzer:
            return 0.3  # Neutral default
        
        try:
            # Truncate if too long
            text = message[:512]
            result = self.emotion_analyzer(text)
            
            if result and len(result) > 0:
                scores = result[0]
                
                # Map emotions to VAD
                # anger, disgust, fear = negative valence + high arousal
                # joy = positive valence + high arousal
                # sadness, neutral = low arousal
                
                emotion_map = {
                    "anger": (-0.8, 0.8),
                    "disgust": (-0.7, 0.6),
                    "fear": (-0.9, 0.9),  # Phishing indicator
                    "joy": (0.7, 0.7),
                    "neutral": (0.0, 0.1),
                    "sadness": (-0.6, 0.3),
                    "surprise": (0.0, 0.8)
                }
                
                # Calculate weighted VAD
                total_valence = 0
                total_arousal = 0
                total_weight = 0
                
                for emotion_score in scores:
                    label = emotion_score.get("label", "").lower()
                    score = emotion_score.get("score", 0)
                    
                    if label in emotion_map:
                        valence, arousal = emotion_map[label]
                        total_valence += valence * score
                        total_arousal += arousal * score
                        total_weight += score
                
                if total_weight > 0:
                    avg_valence = total_valence / total_weight
                    avg_arousal = total_arousal / total_weight
                    
                    # Phishing pattern: negative valence + high arousal
                    # Normalize to [0, 1]
                    s_emotion = (-avg_valence + avg_arousal + 2) / 4
                    return min(max(s_emotion, 0.0), 1.0)
            
            return 0.3
            
        except Exception as e:
            logger.debug(f"Emotion analysis error: {e}")
            return 0.3
    
    def _calculate_confidence(
        self, 
        url: Optional[str], 
        message: str, 
        text_breakdown: Dict
    ) -> Tuple[float, Dict]:
        """
        Calculate confidence score C
        Returns: (C, breakdown)
        """
        # A) Source Score (40%)
        if url and message and len(message.strip()) > 10:
            source_score = 1.0
        elif message and len(message.strip()) > 10:
            source_score = 0.6
        elif url:
            source_score = 0.7
        else:
            source_score = 0.0
        
        # B) URL Accessibility Score (30%)
        if url:
            try:
                parsed = urlparse(url)
                if parsed.scheme and parsed.netloc:
                    url_access = 1.0
                else:
                    url_access = 0.5
            except:
                url_access = 0.0
        else:
            url_access = 0.0
        
        # C) LLM Quality Score (30%)
        llm_quality = text_breakdown.get("llm_quality", 0.0)
        
        # Combine
        C = 0.40 * source_score + 0.30 * url_access + 0.30 * llm_quality
        
        breakdown = {
            "source_score": source_score,
            "url_access": url_access,
            "llm_quality": llm_quality
        }
        
        return C, breakdown
    
    def _amplify_score(self, S_raw: float) -> float:
        """
        Amplify score using sigmoid-like function
        S* = S^β / (S^β + (1-S)^β)
        """
        if S_raw <= 0:
            return 0.0
        if S_raw >= 1:
            return 1.0
        
        S_beta = math.pow(S_raw, BETA)
        one_minus_S_beta = math.pow(1 - S_raw, BETA)
        
        return S_beta / (S_beta + one_minus_S_beta)
    
    def _get_verdict(self, S_star: float) -> str:
        """Get verdict based on amplified score"""
        if S_star >= 0.60:
            return "PHİSHİNG"
        elif S_star >= 0.35:
            return "ŞÜPHELİ"
        elif S_star >= 0.20:
            return "DÜŞÜK RİSK"
        else:
            return "TEMİZ"


# Singleton instance
detector = AdvancedPhishingDetector()


def detect_phishing(message: str, url: Optional[str] = None) -> Dict:
    """Public API function"""
    result = detector.detect(message, url)
    return {
        "verdict": result.verdict,
        "score": result.score,
        "confidence": result.confidence,
        "breakdown": result.breakdown,
        "hard_override": result.hard_override,
        "reason": result.reason
    }
