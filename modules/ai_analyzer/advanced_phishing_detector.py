"""
Advanced AI Phishing Detection Algorithm
3-Module Hybrid Scoring System with Mathematical Amplification

Modules:
- URL Module (w_url = 0.40): DB similarity + SSL check
- Text+Emotion Module (w_text = 0.35): Groq LLM + urgency rules + VAD emotion
- Confidence Score C (w_conf = 0.25): Data quality assessment

Final Score Formula:
  S_raw = C * (0.40 * s_url + 0.35 * s_text) + (1 - C) * 0.5
  S* = S^β / (S^β + (1-S)^β), β = 1.5

Short-message safety rule:
  very short phishing texts should not be dampened back toward prior 0.5.
"""

import os
import re
import ssl
import json
import math
import socket
import logging
from typing import Dict, List, Tuple, Optional
from urllib.parse import urlparse
from datetime import datetime
from dataclasses import dataclass

# Load .env file
from dotenv import load_dotenv
load_dotenv()

# Third-party imports
from rapidfuzz import fuzz, distance
from openai import OpenAI

# transformers opsiyonel — kaldırıldıysa emotion pipeline None kalır (no-op).
try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from transformers import pipeline
except ImportError:
    pipeline = None

# Database
from modules.phishing_detector.cache_db import get_db_connection

logger = logging.getLogger(__name__)

# Constants
W_URL = 0.40
W_TEXT = 0.35
W_CONF = 0.25  # Confidence weight (implicit in formula)
BETA = 1.5
PRIOR = 0.5

# API Keys from env - Groq (OpenAI uyumlu)
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "") or ""
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
if not GROQ_API_KEY:
    logger.warning("GROQ_API_KEY not set - LLM scoring will be limited")


@dataclass
class PhishingResult:
    verdict: str  # "PHİSHİNG", "ŞÜPHELİ", "DÜŞÜK RİSK", "TEMİZ"
    score: float  # S_star (0.0 - 1.0)
    confidence: float  # C (0.0 - 1.0)
    breakdown: Dict
    hard_override: bool
    reason: str
    matched_categories: Optional[List[str]] = None
    evidence: Optional[List[str]] = None


class AdvancedPhishingDetector:
    """3-Module Hybrid Phishing Detection System with Lazy Loading"""
    
    def __init__(self):
        self.phishing_urls = []
        self.llm_client = None
        self.emotion_analyzer = None
        self._db_loaded = False
        self._llm_loaded = False
        self._emotion_loaded = False
    
    def _load_phishing_db(self):
        """Load phishing URLs from database (lazy loading - 10K for memory optimization)"""
        if self._db_loaded:
            return
        
        try:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                # Get recent phishing URLs from cache (reduced from 100K to 10K)
                cursor.execute("""
                    SELECT DISTINCT url FROM phishing_urls
                    WHERE risk_score > 50
                    ORDER BY checked_at DESC
                    LIMIT 10000
                """)
                self.phishing_urls = [row[0] for row in cursor.fetchall()]
                self._db_loaded = True
                logger.info(f"Lazy loaded {len(self.phishing_urls)} phishing URLs from DB")
        except Exception as e:
            logger.warning(f"Could not load phishing DB: {e}")
            self.phishing_urls = []
            self._db_loaded = True
    
    def _init_llm(self):
        """Initialize Groq LLM API (lazy loading)"""
        if self._llm_loaded:
            return
        
        if GROQ_API_KEY:
            try:
                self.llm_client = OpenAI(
                    base_url=GROQ_BASE_URL,
                    api_key=GROQ_API_KEY,
                )
                self._llm_loaded = True
                logger.info(f"Lazy loaded Groq LLM ({GROQ_MODEL})")
            except Exception as e:
                logger.warning(f"Could not load Groq LLM: {e}")
                self.llm_client = None
                self._llm_loaded = True
        else:
            logger.warning("GROQ_API_KEY not found")
            self.llm_client = None
            self._llm_loaded = True
    
    def _init_emotion_model(self):
        """Initialize emotion analysis model (lazy loading)"""
        if self._emotion_loaded:
            return

        if pipeline is None:
            logger.warning("transformers kurul değil — emotion pipeline pasif (no-op)")
            self.emotion_analyzer = None
            self._emotion_loaded = True
            return

        try:
            self.emotion_analyzer = pipeline(
                "text-classification",
                model="j-hartmann/emotion-english-distilroberta-base",
                return_all_scores=True,
                device=-1  # CPU
            )
            self._emotion_loaded = True
            logger.info("Lazy loaded emotion model")
        except Exception as e:
            logger.warning(f"Could not load emotion model: {e}")
            self.emotion_analyzer = None
            self._emotion_loaded = True
    
    def detect(
        self,
        message: str,
        url: Optional[str] = None,
        email_signals: Optional[Dict[str, float]] = None,
    ) -> PhishingResult:
        """
        Main detection function with lazy loading
        
        Args:
            message: Message text to analyze
            url: Optional URL to check
        
        Returns:
            PhishingResult with verdict and scores
        """
        # Lazy load models on first use
        self._load_phishing_db()

        signal_score, matched_categories, evidence = self._signal_scan(message)

        if signal_score >= 0.85:
            return PhishingResult(
                verdict="PHİSHİNG",
                score=round(signal_score, 4),
                confidence=0.95,
                breakdown={
                    "signal_score": round(signal_score, 4),
                    "matched_categories": matched_categories,
                    "signal_evidence": evidence,
                    "score_mode": "signal_override",
                },
                hard_override=True,
                reason=evidence[0] if evidence else "Yüksek güven sinyali",
                matched_categories=matched_categories,
                evidence=evidence,
            )
        
        # === MODULE 1: URL ANALYSIS ===
        s_url, url_breakdown, hard_override = self._analyze_url(url)
        
        if hard_override:
            domain_risk_val = url_breakdown.get("domain_risk", 0)
            db_sim_val = url_breakdown.get("db_similarity", url_breakdown.get("max_similarity", 0))
            if domain_risk_val >= 0.8:
                override_reason = f"Yüksek riskli domain tespit edildi (skor: {domain_risk_val:.2f}) — şüpheli TLD + kurum adı kombinasyonu"
                override_score = round(domain_risk_val, 4)
            else:
                override_reason = f"DB'de benzerlik >= 0.90 - kesin eşleşme (benzerlik: {db_sim_val:.2f})"
                override_score = 1.0
            return PhishingResult(
                verdict="PHİSHİNG",
                score=override_score,
                confidence=0.95,
                breakdown={"s_url": override_score, **url_breakdown},
                hard_override=True,
                reason=override_reason
            )
        
        # Lazy load ML models for text/emotion analysis
        self._init_llm()
        self._init_emotion_model()
        
        # === MODULE 2: TEXT + EMOTION ANALYSIS ===
        s_text, text_breakdown = self._analyze_text(message)
        
        # === MODULE 3: CONFIDENCE SCORE ===
        confidence, conf_breakdown = self._calculate_confidence(url, message, text_breakdown)
        
        email_signal = 0.0
        if email_signals:
            email_signal = float(email_signals.get("total", 0.0) or 0.0)

        message_length = len(message.strip()) if message else 0

        # === FINAL SCORE CALCULATION ===
        if email_signal > 0.0:
            S_raw = (0.40 * s_url) + (0.35 * s_text) + (0.25 * email_signal)
            S_raw = max(S_raw, signal_score * 0.85)
            score_mode = "email"
        elif message_length < 120 and not url:
            # Kısa phishing mesajları için prior'a geri çekmeyi azalt.
            S_raw = max((0.60 * s_text) + (0.40 * signal_score), signal_score * 0.92)
            score_mode = "short_text"
        elif url:
            S_raw = confidence * (0.50 * s_url + 0.50 * s_text)
            S_raw = max(S_raw, signal_score * 0.9)
            score_mode = "url"
        else:
            S_raw = 0.55 * s_text + 0.45 * signal_score
            score_mode = "text"
        
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
                "signal_score": round(signal_score, 4),
                "score_mode": score_mode,
                "s_llm": round(text_breakdown.get("s_llm", 0), 4),
                "s_urgency": round(text_breakdown.get("s_urgency", 0), 4),
                "s_emotion": round(text_breakdown.get("s_emotion", 0), 4),
                "ssl_score": round(url_breakdown.get("ssl_score", 0), 4),
                "db_similarity": round(url_breakdown.get("db_similarity", 0), 4),
                "matched_categories": matched_categories,
                "signal_evidence": evidence,
                "email_signal": round(email_signal, 4),
                "message_length": message_length,
                "llm_provider": "groq",
            },
            hard_override=False,
            reason=evidence[0] if evidence else reason,
            matched_categories=matched_categories,
            evidence=evidence,
        )

    def _signal_scan(self, message: str) -> Tuple[float, List[str], List[str]]:
        """Scan for rule-based phishing signals with composite Turkish patterns."""
        if not message:
            return 0.0, [], []

        text = message.lower()
        evidence: List[str] = []
        matched_categories: List[str] = []
        score = 0.0

        categories = {
            "prize_scam": {
                "weight": 0.85,
                "patterns": ["kazandınız", "ödülünüz", "seçildiniz", "talihli", "çekiliş", "iphone", "para kazandınız", "hediye kartı"],
            },
            "bank_scam": {
                "weight": 0.80,
                "patterns": ["hesabınız bloke", "hesabınız askıya", "kart işlem", "güvenlik doğrulama", "bankacılık güvenlik", "şüpheli işlem", "hesabınızı doğrulayın", "limitiniz aşıldı"],
            },
            "delivery_scam": {
                "weight": 0.70,
                "patterns": ["kargonuz bekleniyor", "teslimat ücreti", "paketiniz", "ptt", "kurye", "adres doğrulama", "gümrük ücreti", "kargo bekleniyor"],
            },
            "authority_scam": {
                "weight": 0.80,
                "patterns": ["sgk", "e-devlet", "vergi cezası", "icra", "mahkeme", "yasal işlem", "resmi tebligat", "kimlik doğrulama"],
            },
            "investment_scam": {
                "weight": 0.75,
                "patterns": ["yatırım", "kripto", "günlük kazanç", "garantili getiri", "teminatlı kazanç", "borsa sinyali", "pasif gelir"],
            },
            "romance_scam": {
                "weight": 0.65,
                "patterns": ["tanışmak istiyorum", "güzel fotoğraflarınızı", "yalnız hissediyorum", "seni özledim", "gizli sohbet", "buluşalım"],
            },
            "credential_harvest": {
                "weight": 0.90,
                "patterns": ["şifrenizi girin", "tc kimlik", "kart numaranız", "cvv", "iban", "otp", "doğrulama kodu", "giriş yapın", "parolanız"],
            },
            "urgency_compound": {
                "weight": 0.85,
                "patterns": ["hemen", "acil", "şimdi", "tıkla", "ara", "yaz", "linke tıkla", "son tarih", "bugün"],
            },
        }

        action_words = ("tıkla", "ara", "yaz", "giriş yap", "doğrula", "gönder", "onayla", "indir")
        risk_words = ("hemen", "acil", "şimdi", "son tarih", "bugün", "24 saat", "48 saat")

        for category, config in categories.items():
            matches = [pattern for pattern in config["patterns"] if pattern in text]
            if not matches:
                continue

            matched_categories.append(category)
            evidence.extend([f"{category}: '{pattern}'" for pattern in matches[:3]])

            base = config["weight"]
            category_score = base * 0.65 + min(0.12 * len(matches), 0.25)
            if category == "urgency_compound":
                has_action = any(word in text for word in action_words)
                has_risk = any(word in text for word in risk_words)
                if has_action and has_risk:
                    category_score = max(category_score, 0.85)
                    evidence.append("Kompozit aciliyet + eylem + risk örüntüsü")

            score = max(score, min(category_score, 1.0))

        if len(matched_categories) >= 2:
            score = min(score + 0.10 * (len(matched_categories) - 1), 1.0)

        return round(score, 4), matched_categories, evidence
    
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
            return domain_risk, {"ssl_score": ssl_score, "db_similarity": s_sim, "domain_risk": domain_risk}, True
        
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
            path = parsed.path.lower()

            # Suspicious TLDs
            suspicious_tlds = [
                ".tk", ".ml", ".ga", ".cf", ".xyz", ".top",
                ".click", ".link", ".work", ".gq", ".cc", ".pw",
                ".support", ".help", ".center",
            ]
            has_suspicious_tld = any(domain.endswith(tld) for tld in suspicious_tlds)

            # Suspicious path patterns
            suspicious_paths = [
                "/verify", "/confirm", "/secure", "/login", "/auth",
                "/validate", "/account", "/billing", "/payment", "/pay",
                "/dogrula", "/dogrulama", "/giris", "/hesap", "/odeme",
                "/islem", "/cek", "/guncelle", "/sifre", "/onay",
                "/aktivasyon", "help-center", "verify-account", "auth-verify",
            ]
            has_phishing_path = any(p in path for p in suspicious_paths)

            risk_score = 0.0
            if has_suspicious_tld:
                risk_score += 0.30
            if has_phishing_path:
                risk_score += 0.20

            # Brand impersonation — global brands
            global_brands = [
                ("instagram", "instagram.com"),
                ("facebook", "facebook.com"),
                ("google", "google.com"),
                ("apple", "apple.com"),
                ("amazon", "amazon.com"),
                ("microsoft", "microsoft.com"),
                ("netflix", "netflix.com"),
                ("paypal", "paypal.com"),
                ("spotify", "spotify.com"),
                ("twitter", "twitter.com"),
                ("whatsapp", "whatsapp.com"),
            ]
            # Turkish banks & institutions
            tr_brands = [
                # Bankalar
                ("garanti", "garantibbva.com.tr"),
                ("akbank", "akbank.com"),
                ("isbank", "isbank.com.tr"),
                ("ziraat", "ziraatbank.com.tr"),
                ("vakifbank", "vakifbank.com.tr"),
                ("halkbank", "halkbank.com.tr"),
                ("yapikredi", "yapikredi.com.tr"),
                ("denizbank", "denizbank.com"),
                ("enpara", "enpara.com"),
                ("papara", "papara.com"),
                # Devlet kurumları
                ("ptt", "ptt.gov.tr"),
                ("kargo", "ptt.gov.tr"),
                ("sgk", "sgk.gov.tr"),
                ("edevlet", "turkiye.gov.tr"),
                ("turkiye", "turkiye.gov.tr"),
                ("e-devlet", "turkiye.gov.tr"),
                ("meb", "meb.gov.tr"),
                ("gib", "gib.gov.tr"),
                ("emniyet", "emniyet.gov.tr"),
                ("jandarma", "jandarma.gov.tr"),
                ("saglik", "saglik.gov.tr"),
                ("hazine", "hazine.gov.tr"),
                ("adalet", "adalet.gov.tr"),
                ("icisleri", "icisleri.gov.tr"),
                ("nvi", "nvi.gov.tr"),
                ("osym", "osym.gov.tr"),
                ("yok", "yok.gov.tr"),
                ("bddk", "bddk.gov.tr"),
                ("spk", "spk.gov.tr"),
                ("btk", "btk.gov.tr"),
                ("rtuk", "rtuk.gov.tr"),
                ("kyk", "kyk.gov.tr"),
                ("diyanet", "diyanet.gov.tr"),
                # Telekom / e-ticaret
                ("turkcell", "turkcell.com.tr"),
                ("vodafone", "vodafone.com.tr"),
                ("turktelekom", "turktelekom.com.tr"),
                ("trendyol", "trendyol.com"),
                ("hepsiburada", "hepsiburada.com"),
                ("n11", "n11.com"),
                ("gittigidiyor", "gittigidiyor.com"),
            ]

            # Sahte .gov.tr pattern tespiti (en güçlü sinyal)
            fake_gov_patterns = [
                "gov-tr", "govtr", "gov.com", "gov.net", "gov.org",
                "gov.xyz", "gov.top", ".gov.tr.",  # subdomain spoof
                "gov-portal", "e-gov", "egovtr",
            ]
            if any(p in domain for p in fake_gov_patterns):
                return 0.96  # Direkt kritik

            has_brand = False
            brand_count = 0
            for brand, official in (global_brands + tr_brands):
                if brand in domain and official not in domain:
                    risk_score += 0.40
                    has_brand = True
                    brand_count += 1
                    if brand_count >= 2:
                        break

            # Birden fazla kurum adı aynı domain'de → çok güçlü phishing sinyali
            if brand_count >= 2:
                return 0.94

            # Kritik kombinasyon: şüpheli TLD + kurum adı → neredeyse kesin phishing
            if has_suspicious_tld and has_brand:
                return 0.92

            # .net / .org + kurum adı → resmi olmayan, phishing tuzagı
            if has_brand and any(domain.endswith(tld) for tld in [".net", ".org", ".info", ".biz"]):
                risk_score = max(risk_score, 0.86)

            # .com.tr benzeri ama sahte: *-guvenlik.com.tr, *-dogrulama.com.tr
            if has_brand and domain.endswith(".com.tr"):
                suspicious_com_tr = ["guvenlik", "dogrula", "giris", "hesap", "odeme", "verify"]
                if any(p in domain for p in suspicious_com_tr):
                    risk_score = max(risk_score, 0.88)

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
        Get phishing score from Groq LLM
        Returns: (score, reason, quality)
        """
        if not self.llm_client:
            return 0.5, "LLM not available", 0.0
        
        try:
            response = self.llm_client.chat.completions.create(
                model=GROQ_MODEL,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "Sen bir siber güvenlik analistinin phishing tespit asistanısın.\n"
                            "Verilen metni değerlendir. Şu kriterlere bak:\n"
                            "- Kimlik bilgisi toplama girişimi var mı?\n"
                            "- Sahte otorite veya marka taklidi var mı?\n"
                            "- Manipülatif veya aldatıcı dil var mı?\n"
                            "- Kullanıcıyı bir aksiyona zorlamaya çalışıyor mu?\n\n"
                            "SADECE şu JSON formatında yanıt ver, başka hiçbir şey yazma:\n"
                            '{"score": <0.0 ile 1.0 arasi float>, "reason": "<max 10 kelime>"}\n\n'
                            "0.0 = kesinlikle temiz, 1.0 = kesinlikle phishing/sosyal mühendislik"
                        ),
                    },
                    {
                        "role": "user",
                        "content": f"Metin: {message[:2000]}",
                    }
                ],
                temperature=0.1,
                max_tokens=100,
            )
            
            text = response.choices[0].message.content.strip()
            
            # Extract JSON
            json_match = re.search(r'\{[^}]+\}', text)
            if json_match:
                data = json.loads(json_match.group())
                score = float(data.get("score", 0.5))
                reason = data.get("reason", "Değerlendirildi")
                return min(max(score, 0.0), 1.0), reason, 1.0
            
            return 0.5, "JSON parse error", 0.4
            
        except Exception as e:
            logger.debug(f"Groq LLM error: {e}")
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
        if S_star >= 0.62:
            return "PHİSHİNG"
        elif S_star >= 0.40:
            return "ŞÜPHELİ"
        elif S_star >= 0.22:
            return "DÜŞÜK RİSK"
        else:
            return "TEMİZ"


# Singleton instance
detector = AdvancedPhishingDetector()


def detect_phishing(message: str, url: Optional[str] = None, email_signals: Optional[Dict[str, float]] = None) -> Dict:
    """Public API function"""
    result = detector.detect(message, url, email_signals=email_signals)
    return {
        "verdict": result.verdict,
        "score": result.score,
        "confidence": result.confidence,
        "breakdown": result.breakdown,
        "hard_override": result.hard_override,
        "reason": result.reason,
        "matched_categories": result.matched_categories or [],
        "evidence": result.evidence or [],
    }


# ─────────────────────────────────────────────────────────
# Event Bus entegrasyonu: Victim Atlas → extra sinyal hint
# ─────────────────────────────────────────────────────────

_EXTRA_HINTS: List[str] = []


def update_extra_hints(attack_methods: List[str]) -> None:
    """
    Victim Atlas ingest tamamlandığında çağrılır.
    Yeni saldırı yöntemlerini in-memory hint listesine ekler.
    """
    global _EXTRA_HINTS
    new_hints = [str(m).lower() for m in (attack_methods or []) if m]
    added = [h for h in new_hints if h not in _EXTRA_HINTS]
    _EXTRA_HINTS.extend(added)
    if len(_EXTRA_HINTS) > 200:
        _EXTRA_HINTS = _EXTRA_HINTS[-200:]


def get_extra_hints() -> List[str]:
    """Mevcut extra hint listesini döner (debug/test)."""
    return list(_EXTRA_HINTS)
