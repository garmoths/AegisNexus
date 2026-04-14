"""
Aegis Nexus - 6 Katmanlı Güvenlik Kalkanı Modülleri

Her modül bağımsız çalışabilir ve ayrı bir sorumluluk alanına sahiptir.

Modüller:
---------
01. phishing_detector - Phishing ve zararlı URL tespiti
02. honeypot - IP Avcısı (tersine mühendislik tuzakları)
03. breach_intel - Veri sızıntısı istihbaratı
04. password_shield - Kriptografik şifre üretimi
05. infra_guard - Altyapı ve SSL güvenlik analizi
06. cyber_guardian - Siber zorbalık ve şantaj önleme

Her modülün router'ı /api/modular/ prefix'i altında erişilebilir.
Örnek: /api/modular/phishing/check-url
"""

# 01 - Phishing Detector
from .phishing_detector import router as phishing_detector_router

# 02 - Honeypot (IP Avcısı)
from .honeypot import router as honeypot_router

# 03 - Breach Intelligence (Veri Radarı)
from .breach_intel import router as breach_intel_router

# 04 - Password Shield (Kriptografik Kalkan)
from .password_shield import router as password_shield_router

# 05 - Infrastructure Guard (Altyapı Kalkanı)
from .infra_guard import router as infra_guard_router

# 06 - Cyber Guardian (Siber Koruyucu)
from .cyber_guardian import router as cyber_guardian_router

router = None  # Placeholder for direct router access

__all__ = [
    "phishing_detector_router",
    "honeypot_router",
    "breach_intel_router",
    "password_shield_router",
    "infra_guard_router",
    "cyber_guardian_router",
]
