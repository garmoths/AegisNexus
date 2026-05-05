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
