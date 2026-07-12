"""
Aegis Nexus - 5 Katmanlı Güvenlik Kalkanı Modülleri

Her modül bağımsız çalışabilir ve ayrı bir sorumluluk alanına sahiptir.

Modüller:
---------
01. phishing_detector - Phishing ve zararlı URL tespiti (SSL/domain analizi ile)
02. honeypot - IP Avcısı (tersine mühendislik tuzakları)
03. breach_intel - Veri sızıntısı istihbaratı
04. password_shield - Kriptografik şifre üretimi
05. ai_analyzer - AI Güvenlik Asistanı
06. victim_atlas - Siber Magduriyet Atlasi
07. sms_guard - SMS Guard
08. risk_dashboard - Birlesik Risk Paneli

Her modülün router'ı /api/v2/modular/ prefix'i altında erişilebilir.
Örnek: /api/v2/phishing/check-url
"""

from importlib import import_module

_ROUTER_MODULE_MAP = {
    "phishing_detector_router": "phishing_detector",
    "honeypot_router": "honeypot",
    "breach_intel_router": "breach_intel",
    "password_shield_router": "password_shield",
    "ai_analyzer_router": "ai_analyzer",
    "victim_atlas_router": "victim_atlas",
    "sms_guard_router": "sms_guard",
    "risk_dashboard_router": "risk_dashboard",
}


def __getattr__(name):
    module_name = _ROUTER_MODULE_MAP.get(name)
    if not module_name:
        raise AttributeError(f"module 'modules' has no attribute '{name}'")

    router = import_module(f".{module_name}", __name__).router
    globals()[name] = router
    return router


router = None  # Placeholder for direct router access

__all__ = [
    "phishing_detector_router",
    "honeypot_router",
    "breach_intel_router",
    "password_shield_router",
    "ai_analyzer_router",
    "victim_atlas_router",
    "sms_guard_router",
]
