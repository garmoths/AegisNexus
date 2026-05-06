"""
Phishing Scoring Phases A, B, C Tests
======================================
Faz A (Bayesian), Faz B (Source Weights), Faz C (Correlation Boost)
"""


def test_combine_probabilities_basic():
    from modules.phishing_detector.threat_intel import combine_probabilities
    
    # Empty list
    assert combine_probabilities([]) == 0.0
    
    # Single signal
    result = combine_probabilities([0.5])
    assert abs(result - 0.5) < 0.01
    
    # Two equal signals
    result = combine_probabilities([0.5, 0.5])
    assert 0.7 < result < 0.8  # Should be ~0.75
    
    # High confidence signals
    result = combine_probabilities([0.8, 0.7])
    assert result > 0.9  # Should be ~0.94
    
    # Low confidence signals
    result = combine_probabilities([0.3, 0.2])
    assert result < 0.5  # Should be ~0.44


def test_combine_probabilities_bounded():
    from modules.phishing_detector.threat_intel import combine_probabilities
    
    # Out of bounds values should be clamped
    result = combine_probabilities([1.5, -0.5, 0.8])
    assert 0.0 <= result <= 1.0
    assert result > 0.8


def test_to_probability_conversion():
    from modules.phishing_detector.threat_intel import to_probability
    
    assert to_probability(0) == 0.0
    assert to_probability(50) == 0.5
    assert to_probability(100) == 1.0
    assert to_probability(200) == 1.0  # Should clamp to 1.0
    assert to_probability(-50) == 0.0  # Should clamp to 0.0


def test_source_weights_tier_structure():
    from modules.phishing_detector.threat_intel import SOURCE_WEIGHTS
    
    # Tier 1 (highest reliability)
    assert SOURCE_WEIGHTS["virustotal_malicious"] == 1.0
    assert SOURCE_WEIGHTS["google_safe_browsing"] == 0.95
    assert SOURCE_WEIGHTS["phishtank_verified"] == 0.90
    
    # Tier 2 (reliable but slower updates)
    assert SOURCE_WEIGHTS["urlhaus"] == 0.75
    assert SOURCE_WEIGHTS["spamhaus_dbl"] == 0.70
    
    # Tier 3 (supporting signals)
    assert SOURCE_WEIGHTS["abuseipdb"] == 0.45
    assert SOURCE_WEIGHTS["screenshot_suspicious"] == 0.35
    
    # Tier 4 (structural signals)
    assert SOURCE_WEIGHTS["suspicious_tld"] == 0.25
    assert SOURCE_WEIGHTS["typosquatting"] == 0.45


def test_get_weighted_penalty():
    from modules.phishing_detector.threat_intel import get_weighted_penalty
    
    # Heavy source (weight 1.0)
    penalty = get_weighted_penalty("virustotal_malicious", 80)
    assert abs(penalty - 0.8) < 0.01
    
    # Medium weight source
    penalty = get_weighted_penalty("urlhaus", 40)
    assert abs(penalty - 0.3) < 0.01  # 40 * 0.75 / 100 = 0.3
    
    # Light weight source
    penalty = get_weighted_penalty("abuseipdb", 100)
    assert abs(penalty - 0.45) < 0.01  # 100 * 0.45 / 100 = 0.45
    
    # Unknown source defaults to 0.5
    penalty = get_weighted_penalty("unknown_source", 50)
    assert abs(penalty - 0.25) < 0.01  # 50 * 0.5 / 100 = 0.25


def test_get_weighted_penalty_bounds():
    from modules.phishing_detector.threat_intel import get_weighted_penalty
    
    # Negative penalty should clamp to 0
    penalty = get_weighted_penalty("urlhaus", -50)
    assert penalty == 0.0
    
    # Penalty > 100 should clamp to 100
    penalty = get_weighted_penalty("urlhaus", 250)
    assert abs(penalty - 0.75) < 0.01  # 100 * 0.75 / 100


def test_apply_correlation_boost_phishing_trifecta():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    signals = {
        "typosquatting": True,
        "suspicious_tld": True,
        "credential_form": True,
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    boost_names = [b[0] for b in boosts]
    assert "phishing_trifecta" in boost_names


def test_apply_correlation_boost_brand_consensus():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    signals = {
        "ti_brand": "Amazon",
        "visual_brand": "Amazon",
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    boost_names = [b[0] for b in boosts]
    assert "brand_consensus" in boost_names


def test_apply_correlation_boost_fresh_malicious():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    signals = {
        "domain_age_days": 10,
        "abuseipdb_score": 75,
        "urlhaus_listed": True,
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    boost_names = [b[0] for b in boosts]
    assert "fresh_malicious" in boost_names


def test_apply_correlation_boost_hidden_suspicious():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    signals = {
        "screenshot_failed": True,
        "structural_risk": 0.5,
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    boost_names = [b[0] for b in boosts]
    assert "hidden_suspicious" in boost_names


def test_apply_correlation_boost_multi_engine():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    signals = {
        "vt_malicious_count": 5,
        "google_safe_browsing_threat": True,
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    boost_names = [b[0] for b in boosts]
    assert "multi_engine_consensus" in boost_names


def test_apply_correlation_boost_no_matches():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    signals = {
        "clean_signal": True,
        "another_clean": True,
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    assert len(boosts) == 0


def test_apply_correlation_boost_partial_signals():
    from modules.phishing_detector.threat_intel import apply_correlation_boost
    
    # Trifecta incomplete (missing credential_form)
    signals = {
        "typosquatting": True,
        "suspicious_tld": True,
    }
    
    boosts = apply_correlation_boost(signals, 0.5)
    boost_names = [b[0] for b in boosts]
    assert "phishing_trifecta" not in boost_names
