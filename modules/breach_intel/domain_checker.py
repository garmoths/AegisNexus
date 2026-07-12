"""
modules/breach_intel/domain_checker.py

Email domain'ini Phishing Detector'ın hızlı tarayıcısından geçirir.
'garanti-destek.com' gibi sahte domain'leri breach kontrolüne entegre eder.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Bilinen sahte banka/kurum domain kalıpları (hızlı pattern eşleşmesi)
_SUSPICIOUS_PATTERNS: List[tuple[re.Pattern, str]] = [
    (re.compile(r"(garanti|isbankasi|akbank|yapikredi|ziraat|vakif|halk|denizbank|qnb|ing|hsbc)"
                r".*(destek|bilgi|guvenlik|dogrulama|verify|secure|hesap|account|update|info|online|bank|limit|sms)",
                re.I), "Sahte banka domain kalıbı"),
    (re.compile(r"(ptt|mhrs|e-devlet|turkiye|t\.c|saglik|emekli)"
                r".*(destek|bilgi|dogrulama|verify|secure|hesap|update|gov|hizmet)",
                re.I), "Sahte resmi kurum domain kalıbı"),
    (re.compile(r"(paypal|apple|google|microsoft|amazon|netflix|instagram|facebook|twitter|whatsapp)"
                r".*(destek|bilgi|guvenlik|verify|secure|account|update|login|support)",
                re.I), "Sahte uluslararası marka domain kalıbı"),
    (re.compile(r"(hızlıkredi|anindakartı|ucuzkargo|indirimfırsatı|hediye|kazan|odul|para)",
                re.I), "Türkçe sahte kazanç domain kalıbı"),
]

_SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".click",
                    ".link", ".live", ".online", ".site", ".info", ".biz.tr"}


def _extract_domain(email: str) -> str | None:
    email = (email or "").strip().lower()
    if "@" not in email:
        return None
    domain = email.split("@")[-1]
    # Basit domain doğrulama
    if not re.match(r"^[a-z0-9.\-]+\.[a-z]{2,}$", domain):
        return None
    return domain


def _pattern_check(domain: str) -> List[str]:
    signals: List[str] = []
    for pattern, label in _SUSPICIOUS_PATTERNS:
        if pattern.search(domain):
            signals.append(label)
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            signals.append(f"Şüpheli TLD: {tld}")
    return signals


def check_email_domain(email: str) -> Dict[str, Any]:
    """
    Email domain'ini hem pattern tabanlı hem de Phishing Detector scanner ile kontrol eder.

    Returns:
        {
            "domain": str,
            "is_suspicious": bool,
            "risk_score": int (0-100),
            "signals": List[str],
            "method": str
        }
    """
    domain = _extract_domain(email)

    if not domain:
        return {
            "domain": None,
            "is_suspicious": False,
            "risk_score": 0,
            "signals": ["Geçersiz email formatı"],
            "method": "validation_error",
        }

    signals: List[str] = []
    risk_score = 0

    # 1. Hızlı pattern eşleşmesi (ağ I/O yok)
    pattern_signals = _pattern_check(domain)
    signals.extend(pattern_signals)
    if pattern_signals:
        risk_score = max(risk_score, 65)

    # 2. Phishing Detector scanner (run_quick_checks — ağ I/O yok, ~200ms)
    scanner_method = "pattern_only"
    try:
        from modules.phishing_detector.scanner import run_quick_checks

        scan_result = run_quick_checks(f"https://{domain}")
        scanner_score = scan_result.get("safety_score", scan_result.get("score", 100))
        # safety_score: yüksek = güvenli → risk = 100 - safety
        phishing_risk = 100 - int(scanner_score)
        risk_score = max(risk_score, phishing_risk)

        details = scan_result.get("details", [])
        for d in details:
            d_str = str(d)
            if any(kw in d_str.lower() for kw in ("şüpheli", "suspicious", "risk", "tehdit",
                                                    "phishing", "blacklist", "typosquat")):
                signals.append(d_str[:120])

        scanner_method = "phishing_detector_quick"
    except Exception as exc:
        logger.warning(f"[DomainChecker] Scanner unavailable for {domain}: {exc}")

    # Skor sınırla
    risk_score = min(risk_score, 100)
    is_suspicious = risk_score >= 40 or bool(pattern_signals)

    return {
        "domain": domain,
        "is_suspicious": is_suspicious,
        "risk_score": risk_score,
        "signals": signals[:10],  # max 10 sinyal
        "method": scanner_method,
    }
