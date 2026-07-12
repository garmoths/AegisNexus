"""
modules/password_shield/pwned_check.py

HIBP Pwned Passwords k-Anonymity API entegrasyonu.
Şifrenin SHA-1 hash'ini 5-prefix ile sorgular; tam hash sunucuya gönderilmez.

Endpoint: https://api.pwnedpasswords.com/range/{5-char-prefix}
"""

from __future__ import annotations

import hashlib
import logging
import urllib.request
from typing import Any, Dict

logger = logging.getLogger(__name__)

PWNED_API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
REQUEST_TIMEOUT = 6  # saniye


def _sha1_hash(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def check_pwned(password: str) -> Dict[str, Any]:
    """
    Şifrenin daha önce sızdırılıp sızdırılmadığını kontrol eder.

    k-Anonymity modeli: İlk 5 karakter prefix olarak gönderilir,
    kalan hash hiçbir zaman dışarı çıkmaz.

    Returns:
        {
            "pwned": bool,
            "times_seen": int,         # kaç ihlalde görüldü
            "risk_level": str,         # "safe" | "low" | "medium" | "high" | "critical"
            "warning": str,            # Türkçe uyarı mesajı
            "sha1_prefix": str,        # gönderilen 5 karakter (debug)
            "method": str,
        }
    """
    if not password:
        return {
            "pwned": False,
            "times_seen": 0,
            "risk_level": "unknown",
            "warning": "Şifre boş.",
            "sha1_prefix": "",
            "method": "skipped",
        }

    sha1 = _sha1_hash(password)
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        url = PWNED_API_URL.format(prefix=prefix)
        req = urllib.request.Request(url, headers={"User-Agent": "AegisNexus-PwnedCheck/1.0"})
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            body = resp.read().decode("utf-8")
    except Exception as exc:
        logger.warning(f"[PwnedCheck] API unavailable: {exc}")
        return {
            "pwned": False,
            "times_seen": 0,
            "risk_level": "unknown",
            "warning": "HIBP API erişilemiyor, kontrol yapılamadı.",
            "sha1_prefix": prefix,
            "method": "api_error",
        }

    times_seen = 0
    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            try:
                times_seen = int(parts[1])
            except ValueError:
                pass
            break

    pwned = times_seen > 0
    risk_level = _risk_level(times_seen)
    warning = _warning_message(times_seen)

    return {
        "pwned": pwned,
        "times_seen": times_seen,
        "risk_level": risk_level,
        "warning": warning,
        "sha1_prefix": prefix,
        "method": "hibp_k_anonymity",
    }


def _risk_level(times_seen: int) -> str:
    if times_seen == 0:
        return "safe"
    if times_seen < 10:
        return "low"
    if times_seen < 100:
        return "medium"
    if times_seen < 10_000:
        return "high"
    return "critical"


def _warning_message(times_seen: int) -> str:
    if times_seen == 0:
        return "Bu şifre bilinen sızıntı veritabanlarında görülmemiş."
    if times_seen == 1:
        return "Bu şifre 1 kez sızıntı veritabanında görülmüş — değiştirmeniz önerilir."
    if times_seen < 100:
        return (
            f"Bu şifre {times_seen} kez farklı ihlallerde görülmüş. "
            "Hemen değiştirmenizi öneririz."
        )
    return (
        f"⚠️ Bu şifre {times_seen:,} kez sızıntı veritabanında görülmüş! "
        "Çok yaygın, derhal değiştirin ve Password Shield ile yeni şifre oluşturun."
    )
