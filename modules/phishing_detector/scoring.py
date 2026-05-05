"""
Phishing Scoring Engine — Bayesian Probability Combiner (Faz A)
===============================================================
Mevcut ceza toplamı modeline paralel çalışan olasılık tabanlı risk hesabı.

Kullanım:
    from .scoring import combine_probabilities, to_probability
"""
from __future__ import annotations

SCORING_MODEL_VERSION = "bayesian-v1"


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
