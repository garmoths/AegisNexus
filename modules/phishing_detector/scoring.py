"""
Phishing Scoring Engine — Bayesian Probability Combiner (Faz A)
===============================================================
Mevcut ceza toplamı modeline paralel çalışan olasılık tabanlı risk hesabı.

Kullanım:
    from .scoring import combine_probabilities, to_probability
"""
from __future__ import annotations

SCORING_MODEL_VERSION = "bayesian-v1"

SOURCE_WEIGHTS: dict[str, float] = {
    "virustotal_malicious": 1.00,
    "virustotal_suspicious": 0.60,
    "google_safe_browsing": 0.95,
    "phishtank_verified": 0.90,
    "urlhaus": 0.75,
    "spamhaus_dbl": 0.70,
    "spamhaus_domain": 0.70,
    "threatfox": 0.65,
    "spamhaus_xbl": 0.60,
    "spamhaus_ip": 0.60,
    "abuseipdb": 0.45,
    "spamhaus_zrd": 0.30,
    "screenshot_high": 0.70,
    "screenshot_suspicious": 0.35,
    "screenshot_gemini_skip": 0.20,
    "screenshot_unavailable": 0.15,
    "ml_model": 0.40,
}

DEFAULT_SOURCE_WEIGHT: float = 0.35


def apply_source_weight(base_probability: float, source_key: str) -> float:
    """
    Kaynak güvenilirlik ağırlığını uygular: weighted = min(1.0, base * weight)

    >>> apply_source_weight(0.4, "virustotal_malicious")
    0.4
    >>> apply_source_weight(0.4, "abuseipdb")
    0.18
    >>> apply_source_weight(0.4, "unknown_source")
    0.14
    >>> apply_source_weight(0.0, "virustotal_malicious")
    0.0
    """
    weight = SOURCE_WEIGHTS.get(source_key, DEFAULT_SOURCE_WEIGHT)
    return round(min(1.0, float(base_probability) * weight), 6)


SUSPICIOUS_TLDS: frozenset = frozenset({
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click", "link",
    "work", "loan", "win", "stream", "download", "online", "site",
    "website", "tech", "space", "fun", "pw", "buzz", "icu", "fit",
})

_CREDENTIAL_KEYWORDS: frozenset = frozenset({
    "password", "passwd", "login", "signin", "sign-in", "credential",
    "bank", "verify", "verification", "account", "secure", "update",
    "confirm", "paypal", "credit", "debit", "ssn", "social security",
})


def detect_signals(
    *,
    domain: str = "",
    page_text: str = "",
    screenshot_analysis: dict | None = None,
    abuseipdb: dict | None = None,
    urlhaus: dict | None = None,
    pre_penalty: int = 0,
    domain_age_days: int | None = None,
) -> dict:
    """
    Korelasyon boost'ları için sinyal sözlüğü oluşturur.
    Tüm alanlar boolean veya sayısal; eksik veri False/0 olarak işlenir.
    """
    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    suspicious_tld = tld in SUSPICIOUS_TLDS

    text_lower = page_text.lower() if page_text else ""
    credential_form = any(kw in text_lower for kw in _CREDENTIAL_KEYWORDS)

    # Screenshot'tan marka impersonation ve credential ipuçları
    indicators: list = []
    if isinstance(screenshot_analysis, dict):
        indicators = screenshot_analysis.get("threat_indicators") or []
    indicators_text = " ".join(str(i) for i in indicators).lower()
    brand_mismatch = any(
        kw in indicators_text
        for kw in ("brand", "impersonat", "logo", "marka", "sahte", "fake")
    )
    if not credential_form:
        credential_form = any(
            kw in indicators_text
            for kw in ("credential", "login form", "password", "giriş", "şifre")
        )

    abuseipdb_high = (abuseipdb or {}).get("abuse_score", 0) >= 70
    urlhaus_listed = bool((urlhaus or {}).get("listed"))
    screenshot_failed = screenshot_analysis is None
    structural_penalty_high = pre_penalty >= 20

    # domain_age_days: None = bilinmiyor (Faz D dolduracak), int = gerçek yaş
    domain_new = (domain_age_days is not None and domain_age_days < 30)

    return {
        "suspicious_tld": suspicious_tld,
        "credential_form": credential_form,
        "brand_mismatch": brand_mismatch,
        "abuseipdb_high": abuseipdb_high,
        "urlhaus_listed": urlhaus_listed,
        "screenshot_failed": screenshot_failed,
        "structural_penalty_high": structural_penalty_high,
        "domain_new": domain_new,
    }


def apply_correlation_boost(
    combined: float, signals: dict
) -> tuple:
    """
    Bağlamsal korelasyon kurallarına göre birleşik olasılığı artırır.

    Kural tetikleme sırası: boost sonrası risk azalamaz, 1.0 aşamaz.

    Returns: (boosted_probability: float, boost_events: list[dict])

    >>> p, evs = apply_correlation_boost(0.0, {})
    >>> p
    0.0
    >>> evs
    []
    >>> p2, evs2 = apply_correlation_boost(0.5, {"suspicious_tld": True, "credential_form": True})
    >>> p2
    0.7
    >>> len(evs2)
    1
    """
    boosts: list = []
    p = float(combined)

    _RULES = [
        (
            "suspicious_tld+credential_form",
            lambda s: s.get("suspicious_tld") and s.get("credential_form"),
            1.4,
        ),
        (
            "brand_mismatch",
            lambda s: s.get("brand_mismatch"),
            1.3,
        ),
        (
            "domain_new+abuseipdb_high+urlhaus_listed",
            lambda s: s.get("domain_new") and s.get("abuseipdb_high") and s.get("urlhaus_listed"),
            1.35,
        ),
        (
            "screenshot_failed+structural_penalty_high",
            lambda s: s.get("screenshot_failed") and s.get("structural_penalty_high"),
            1.2,
        ),
    ]

    for rule_name, condition, factor in _RULES:
        if condition(signals):
            before = round(p, 6)
            p = min(1.0, p * factor)
            after = round(p, 6)
            boosts.append({
                "rule": rule_name,
                "factor": factor,
                "before": before,
                "after": after,
            })

    return round(p, 6), boosts


def combine_probabilities(probabilities: list) -> float:
    """
    Bağımsız olayların birleşik olasılığı:  P = 1 - Π(1 - p_i)

    >>> round(combine_probabilities([0.8, 0.7]), 4)
    0.94
    >>> round(combine_probabilities([0.3, 0.2]), 4)
    0.44
    >>> combine_probabilities([])
    0.0
    >>> combine_probabilities([0.0, 0.0])
    0.0
    >>> combine_probabilities([1.0, 0.5])
    1.0
    """
    if not probabilities:
        return 0.0
    complement = 1.0
    for p in probabilities:
        p = max(0.0, min(1.0, float(p)))
        complement *= 1.0 - p
    return round(1.0 - complement, 6)


def to_probability(raw_penalty: float) -> float:
    """
    Ham ceza değerini (0-100 aralığı) olasılığa (0-1) çevirir.

    >>> to_probability(0)
    0.0
    >>> to_probability(100)
    1.0
    >>> to_probability(50)
    0.5
    >>> to_probability(-10)
    0.0
    >>> to_probability(150)
    1.0
    """
    return round(max(0.0, min(1.0, float(raw_penalty) / 100.0)), 6)
