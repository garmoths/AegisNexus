"""
Shared Models - Ortak Veritabanı Modelleri
"""
from .phishing import PhishingURL
from .honeypot import HoneypotEvent

__all__ = ["PhishingURL", "HoneypotEvent"]
