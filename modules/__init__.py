"""
Aegis Nexus - 5 Katmanlı Güvenlik Kalkanı Modülleri

Her modül bağımsız çalışabilir ve ayrı bir sorumluluk alanına sahiptir.

Modüller:
---------
01. phishing_detector - Phishing ve zararlı URL tespiti (SSL/domain analizi ile)
02. honeypot - IP Avcısı (tersine mühendislik tuzakları)
03. breach_intel - Veri sızıntısı istihbaratı
04. password_shield - Kriptografik şifre üretimi
05. threat_responder - Tehdit göstergelerini operatörlere yanıt ver

Her modülün router'ı /api/v2/modular/ prefix'i altında erişilebilir.
Örnek: /api/v2/phishing/check-url
"""

# 01 - Phishing Detector
from .phishing_detector import router as phishing_detector_router

# 02 - Honeypot (IP Avcısı)
from .honeypot import router as honeypot_router

# 03 - Breach Intelligence (Veri Radarı)
from .breach_intel import router as breach_intel_router

# 04 - Password Shield (Kriptografik Kalkan)
from .password_shield import router as password_shield_router

# 05 - Threat Responder (Tehdit Yanıtlayıcı)
from .threat_responder import router as threat_responder_router

# 06 - AI Analyzer (AI Güvenlik Asistanı)
from .ai_analyzer import router as ai_analyzer_router

# 07 - Victim Atlas (Siber Magduriyet Atlasi)
from .victim_atlas import router as victim_atlas_router

router = None  # Placeholder for direct router access

__all__ = [
    "phishing_detector_router",
    "honeypot_router",
    "breach_intel_router",
    "password_shield_router",
    "threat_responder_router",
    "ai_analyzer_router",
    "victim_atlas_router",
]
