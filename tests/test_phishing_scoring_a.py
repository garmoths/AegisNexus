"""
Phishing Scoring — Faz A Unit Tests
======================================
combine_probabilities() ve to_probability() için birim testler.
Regresyon: whitelist URL yüksek güvenli, kritik URL düşük güvenli kalmalı.

pytest tests/test_phishing_scoring_a.py -v
"""
from __future__ import annotations
import pytest
from modules.phishing_detector.scoring import (
    combine_probabilities,
    to_probability,
    apply_source_weight,
    detect_signals,
    apply_correlation_boost,
    SOURCE_WEIGHTS,
    DEFAULT_SOURCE_WEIGHT,
    SCORING_MODEL_VERSION,
    SUSPICIOUS_TLDS,
)


# ── 1. combine_probabilities ─────────────────────────────────────────────────

class TestCombineProbabilities:
    def test_empty_list_returns_zero(self):
        assert combine_probabilities([]) == 0.0

    def test_all_zeros_returns_zero(self):
        assert combine_probabilities([0.0, 0.0, 0.0]) == 0.0

    def test_single_one_returns_one(self):
        assert combine_probabilities([1.0]) == 1.0

    def test_first_one_clamps_result(self):
        assert combine_probabilities([1.0, 0.5]) == 1.0

    def test_high_signals_approx(self):
        result = combine_probabilities([0.8, 0.7])
        assert abs(result - 0.94) < 0.01

    def test_low_signals_approx(self):
        result = combine_probabilities([0.3, 0.2])
        assert abs(result - 0.44) < 0.01

    def test_result_in_range(self):
        for probs in [[0.1, 0.2, 0.3], [0.5], [0.9, 0.9, 0.9]]:
            r = combine_probabilities(probs)
            assert 0.0 <= r <= 1.0

    def test_order_independent(self):
        assert combine_probabilities([0.3, 0.7]) == combine_probabilities([0.7, 0.3])

    def test_clamps_over_one(self):
        result = combine_probabilities([1.5, 0.5])
        assert result == 1.0

    def test_clamps_below_zero(self):
        result = combine_probabilities([-0.5, 0.5])
        assert 0.0 <= result <= 1.0

    def test_single_probability_identity(self):
        for p in [0.1, 0.5, 0.9]:
            assert abs(combine_probabilities([p]) - p) < 1e-5

    def test_three_independent_signals(self):
        result = combine_probabilities([0.4, 0.4, 0.4])
        expected = 1 - (0.6 ** 3)
        assert abs(result - expected) < 1e-4


# ── 2. to_probability ────────────────────────────────────────────────────────

class TestToProbability:
    def test_zero_returns_zero(self):
        assert to_probability(0) == 0.0

    def test_hundred_returns_one(self):
        assert to_probability(100) == 1.0

    def test_fifty_returns_half(self):
        assert to_probability(50) == 0.5

    def test_negative_clamped_to_zero(self):
        assert to_probability(-10) == 0.0

    def test_over_hundred_clamped_to_one(self):
        assert to_probability(150) == 1.0

    def test_penalty_40_maps_correctly(self):
        assert to_probability(40) == 0.4

    def test_penalty_25_maps_correctly(self):
        assert to_probability(25) == 0.25

    def test_result_always_in_range(self):
        for val in [-100, 0, 10, 50, 100, 200]:
            r = to_probability(val)
            assert 0.0 <= r <= 1.0


# ── 3. Scoring model version ─────────────────────────────────────────────────

class TestScoringModelVersion:
    def test_version_string_set(self):
        assert SCORING_MODEL_VERSION == "bayesian-v1"


# ── 4. SOURCE_WEIGHTS ────────────────────────────────────────────────────────

class TestSourceWeights:
    def test_all_required_keys_present(self):
        required = [
            "virustotal_malicious", "virustotal_suspicious", "google_safe_browsing",
            "urlhaus", "spamhaus_dbl", "spamhaus_domain", "threatfox",
            "spamhaus_xbl", "spamhaus_ip", "abuseipdb", "spamhaus_zrd",
            "screenshot_high", "screenshot_suspicious",
        ]
        for k in required:
            assert k in SOURCE_WEIGHTS, f"Eksik kaynak ağırlığı: {k}"

    def test_all_weights_in_range(self):
        for k, w in SOURCE_WEIGHTS.items():
            assert 0.0 <= w <= 1.0, f"{k} ağırlığı [0,1] dışında: {w}"

    def test_vt_has_highest_weight(self):
        assert SOURCE_WEIGHTS["virustotal_malicious"] == 1.0

    def test_gsb_has_very_high_weight(self):
        assert SOURCE_WEIGHTS["google_safe_browsing"] >= 0.9

    def test_abuseipdb_lower_than_vt(self):
        assert SOURCE_WEIGHTS["abuseipdb"] < SOURCE_WEIGHTS["virustotal_malicious"]

    def test_spamhaus_zrd_lowest_among_spamhaus(self):
        assert SOURCE_WEIGHTS["spamhaus_zrd"] < SOURCE_WEIGHTS["spamhaus_dbl"]
        assert SOURCE_WEIGHTS["spamhaus_zrd"] < SOURCE_WEIGHTS["spamhaus_xbl"]

    def test_default_weight_exists(self):
        assert 0.0 < DEFAULT_SOURCE_WEIGHT < 1.0


class TestApplySourceWeight:
    def test_known_source_applies_weight(self):
        base = 0.4
        result = apply_source_weight(base, "virustotal_malicious")
        assert result == pytest.approx(0.4 * 1.0, abs=1e-5)

    def test_abuseipdb_weight_lower_than_vt(self):
        base = 0.4
        vt_w = apply_source_weight(base, "virustotal_malicious")
        abuse_w = apply_source_weight(base, "abuseipdb")
        assert abuse_w < vt_w

    def test_unknown_source_uses_default(self):
        base = 0.4
        result = apply_source_weight(base, "totally_unknown_source")
        expected = min(1.0, base * DEFAULT_SOURCE_WEIGHT)
        assert result == pytest.approx(expected, abs=1e-5)

    def test_clamps_at_one(self):
        result = apply_source_weight(2.0, "virustotal_malicious")
        assert result == 1.0

    def test_zero_base_returns_zero(self):
        assert apply_source_weight(0.0, "google_safe_browsing") == 0.0


# ── 5. run_threat_intelligence entegrasyon (mock) ─────────────────────────────

class TestThreatIntelBayesianOutput:
    def test_clean_result_has_bayesian_fields(self, monkeypatch):
        """Tüm kaynaklar temiz: combined_probability 0 veya düşük olmalı."""
        import modules.phishing_detector.threat_intel as ti

        CLEAN_SHOT = {"available": True, "gemini_skipped": False, "risk_score": 0, "risk_level": "SAFE", "threat_indicators": [], "verdict": "Temiz"}
        CLEAN_VT = {"available": True, "malicious": 0, "suspicious": 0}
        CLEAN_GSB = {"available": True, "threat": False}
        CLEAN_ABUSEIPDB = {"abuse_score": 0}
        CLEAN_SG = {
            "urlhaus": {"listed": False, "available": True},
            "spamhaus_domain": {"listed": False, "available": True},
            "spamhaus_ip": {"listed": False, "available": True},
            "threatfox": {"found": False, "available": True},
        }

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SG)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)
        monkeypatch.setattr(ti, "write_ioc", lambda **k: None)

        result = ti.run_threat_intelligence("https://google.com")

        assert "combined_risk_probability" in result
        assert "scoring_model" in result
        assert "scoring_details" in result
        assert result["scoring_model"] == "bayesian-v1"
        assert result["combined_risk_probability"] == 0.0
        assert result["scoring_details"]["signal_count"] == 0
        assert result["scoring_details"]["penalty_events"] == []

    def test_malicious_vt_raises_probability(self, monkeypatch):
        """VT malicious >= 3: combined_probability yüksek olmalı."""
        import modules.phishing_detector.threat_intel as ti

        BAD_VT = {"available": True, "malicious": 5, "suspicious": 0}
        CLEAN_SHOT = {"available": True, "gemini_skipped": False, "risk_score": 0, "risk_level": "SAFE", "threat_indicators": [], "verdict": "Temiz"}
        CLEAN_GSB = {"available": True, "threat": False}
        CLEAN_ABUSEIPDB = {"abuse_score": 0}
        CLEAN_SG = {
            "urlhaus": {"listed": False, "available": True},
            "spamhaus_domain": {"listed": False, "available": True},
            "spamhaus_ip": {"listed": False, "available": True},
            "threatfox": {"found": False, "available": True},
        }

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: BAD_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SG)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)
        monkeypatch.setattr(ti, "write_ioc", lambda **k: None)

        result = ti.run_threat_intelligence("https://evil.example.com")

        events = result["scoring_details"]["penalty_events"]
        assert any(e["source_key"] == "virustotal_malicious" for e in events)
        vt_event = next(e for e in events if e["source_key"] == "virustotal_malicious")
        assert "weighted_probability" in vt_event
        assert vt_event["weighted_probability"] == vt_event["probability"] * 1.0

    def test_vt_stronger_than_abuseipdb_same_base(self, monkeypatch):
        """Aynı base sinyal: VT > AbuseIPDB weighted impact (Faz B)."""
        import modules.phishing_detector.threat_intel as ti
        from modules.phishing_detector.scoring import apply_source_weight, to_probability

        base = to_probability(25)
        vt_w = apply_source_weight(base, "virustotal_malicious")
        abuse_w = apply_source_weight(base, "abuseipdb")
        assert vt_w > abuse_w

    def test_multiple_signals_combine_correctly(self, monkeypatch):
        """VT + GSB birlikte: combined_probability > her birinden yüksek olmalı."""
        import modules.phishing_detector.threat_intel as ti

        BAD_VT = {"available": True, "malicious": 5, "suspicious": 0}
        BAD_GSB = {"available": True, "threat": "MALWARE"}
        CLEAN_SHOT = {"available": True, "gemini_skipped": False, "risk_score": 0, "risk_level": "SAFE", "threat_indicators": [], "verdict": "Temiz"}
        CLEAN_ABUSEIPDB = {"abuse_score": 0}
        CLEAN_SG = {
            "urlhaus": {"listed": False, "available": True},
            "spamhaus_domain": {"listed": False, "available": True},
            "spamhaus_ip": {"listed": False, "available": True},
            "threatfox": {"found": False, "available": True},
        }

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: BAD_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: BAD_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SG)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)
        monkeypatch.setattr(ti, "write_ioc", lambda **k: None)

        result = ti.run_threat_intelligence("https://evil.example.com")

        from modules.phishing_detector.scoring import apply_source_weight, to_probability
        w_vt = apply_source_weight(to_probability(40), "virustotal_malicious")
        w_gsb = apply_source_weight(to_probability(50), "google_safe_browsing")
        expected = 1 - (1 - w_vt) * (1 - w_gsb)
        assert result["combined_risk_probability"] == pytest.approx(expected, abs=0.01)
        assert result["scoring_details"]["signal_count"] == 2

    def test_correlation_boosts_in_scoring_details(self, monkeypatch):
        """Faz C: scoring_details.correlation_boosts ve signals mevcut olmalı."""
        import modules.phishing_detector.threat_intel as ti

        CLEAN_SHOT = {"available": True, "gemini_skipped": False, "risk_score": 0, "risk_level": "SAFE", "threat_indicators": [], "verdict": "Temiz"}
        CLEAN_VT = {"available": True, "malicious": 0, "suspicious": 0}
        CLEAN_GSB = {"available": True, "threat": False}
        CLEAN_ABUSEIPDB = {"abuse_score": 0}
        CLEAN_SG = {
            "urlhaus": {"listed": False, "available": True},
            "spamhaus_domain": {"listed": False, "available": True},
            "spamhaus_ip": {"listed": False, "available": True},
            "threatfox": {"found": False, "available": True},
        }

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SG)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)
        monkeypatch.setattr(ti, "write_ioc", lambda **k: None)

        result = ti.run_threat_intelligence("https://google.com")
        sd = result["scoring_details"]
        assert "correlation_boosts" in sd
        assert "signals" in sd
        assert "pre_boost_probability" in sd
        assert isinstance(sd["correlation_boosts"], list)
        assert isinstance(sd["signals"], dict)

    def test_legacy_penalty_preserved(self, monkeypatch):
        """Eski total_penalty ve yeni scoring_details birlikte mevcut olmalı."""
        import modules.phishing_detector.threat_intel as ti

        CLEAN_SHOT = {"available": True, "gemini_skipped": False, "risk_score": 0, "risk_level": "SAFE", "threat_indicators": [], "verdict": "Temiz"}
        CLEAN_VT = {"available": True, "malicious": 0, "suspicious": 0}
        CLEAN_GSB = {"available": True, "threat": False}
        CLEAN_ABUSEIPDB = {"abuse_score": 0}
        CLEAN_SG = {
            "urlhaus": {"listed": False, "available": True},
            "spamhaus_domain": {"listed": False, "available": True},
            "spamhaus_ip": {"listed": False, "available": True},
            "threatfox": {"found": False, "available": True},
        }

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SG)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)
        monkeypatch.setattr(ti, "write_ioc", lambda **k: None)

        result = ti.run_threat_intelligence("https://google.com")

        assert "total_penalty" in result
        assert "scoring_details" in result
        assert result["scoring_details"]["legacy_penalty"] == result["total_penalty"]


# ── 6. detect_signals (Faz C) ────────────────────────────────────────────────

class TestDetectSignals:
    def test_suspicious_tld_detected(self):
        s = detect_signals(domain="evil.xyz")
        assert s["suspicious_tld"] is True

    def test_clean_tld_not_suspicious(self):
        s = detect_signals(domain="google.com")
        assert s["suspicious_tld"] is False

    def test_credential_keyword_in_page_text(self):
        s = detect_signals(page_text="Please enter your password here")
        assert s["credential_form"] is True

    def test_no_credential_keyword(self):
        s = detect_signals(page_text="Welcome to our blog about cats")
        assert s["credential_form"] is False

    def test_abuseipdb_high_flag(self):
        s = detect_signals(abuseipdb={"abuse_score": 85})
        assert s["abuseipdb_high"] is True

    def test_abuseipdb_low_not_flagged(self):
        s = detect_signals(abuseipdb={"abuse_score": 30})
        assert s["abuseipdb_high"] is False

    def test_urlhaus_listed_flag(self):
        s = detect_signals(urlhaus={"listed": True})
        assert s["urlhaus_listed"] is True

    def test_screenshot_failed_when_none(self):
        s = detect_signals(screenshot_analysis=None)
        assert s["screenshot_failed"] is True

    def test_screenshot_not_failed_when_dict(self):
        s = detect_signals(screenshot_analysis={"risk_score": 10})
        assert s["screenshot_failed"] is False

    def test_structural_penalty_high_threshold(self):
        s = detect_signals(pre_penalty=20)
        assert s["structural_penalty_high"] is True
        s2 = detect_signals(pre_penalty=19)
        assert s2["structural_penalty_high"] is False

    def test_domain_new_with_age(self):
        s = detect_signals(domain_age_days=15)
        assert s["domain_new"] is True

    def test_domain_not_new_without_age(self):
        s = detect_signals(domain_age_days=None)
        assert s["domain_new"] is False

    def test_brand_mismatch_from_screenshot_indicators(self):
        shot = {"threat_indicators": ["brand impersonation detected"]}
        s = detect_signals(screenshot_analysis=shot)
        assert s["brand_mismatch"] is True

    def test_all_keys_present(self):
        s = detect_signals()
        for key in ("suspicious_tld", "credential_form", "brand_mismatch",
                    "abuseipdb_high", "urlhaus_listed", "screenshot_failed",
                    "structural_penalty_high", "domain_new"):
            assert key in s


# ── 7. apply_correlation_boost (Faz C) ───────────────────────────────────────

class TestApplyCorrelationBoost:
    def test_no_signals_no_boost(self):
        p, evs = apply_correlation_boost(0.5, {})
        assert p == 0.5
        assert evs == []

    def test_zero_input_stays_zero(self):
        p, evs = apply_correlation_boost(0.0, {"suspicious_tld": True, "credential_form": True})
        assert p == 0.0

    def test_rule1_suspicious_tld_credential_form(self):
        p, evs = apply_correlation_boost(0.5, {"suspicious_tld": True, "credential_form": True})
        assert p == pytest.approx(0.5 * 1.4, abs=1e-5)
        assert len(evs) == 1
        assert evs[0]["rule"] == "suspicious_tld+credential_form"
        assert evs[0]["factor"] == 1.4

    def test_rule2_brand_mismatch(self):
        p, evs = apply_correlation_boost(0.4, {"brand_mismatch": True})
        assert p == pytest.approx(0.4 * 1.3, abs=1e-5)
        assert evs[0]["rule"] == "brand_mismatch"

    def test_rule4_screenshot_failed_structural(self):
        p, evs = apply_correlation_boost(0.3, {"screenshot_failed": True, "structural_penalty_high": True})
        assert p == pytest.approx(0.3 * 1.2, abs=1e-5)
        assert evs[0]["rule"] == "screenshot_failed+structural_penalty_high"

    def test_multiple_rules_compound(self):
        p, evs = apply_correlation_boost(
            0.3,
            {"suspicious_tld": True, "credential_form": True, "brand_mismatch": True}
        )
        expected = min(1.0, min(1.0, 0.3 * 1.4) * 1.3)
        assert p == pytest.approx(expected, abs=1e-5)
        assert len(evs) == 2

    def test_result_never_exceeds_one(self):
        p, _ = apply_correlation_boost(0.9, {
            "suspicious_tld": True, "credential_form": True,
            "brand_mismatch": True, "screenshot_failed": True,
            "structural_penalty_high": True,
        })
        assert p <= 1.0

    def test_result_never_decreases(self):
        base = 0.4
        signals = {"suspicious_tld": True, "credential_form": True}
        p, _ = apply_correlation_boost(base, signals)
        assert p >= base

    def test_rule3_requires_all_three_conditions(self):
        p_only_age, _ = apply_correlation_boost(0.5, {"domain_new": True})
        p_all, evs = apply_correlation_boost(
            0.5,
            {"domain_new": True, "abuseipdb_high": True, "urlhaus_listed": True}
        )
        assert p_all > p_only_age
        assert any(e["rule"] == "domain_new+abuseipdb_high+urlhaus_listed" for e in evs)

    def test_boost_audit_trail_before_after(self):
        p, evs = apply_correlation_boost(0.5, {"suspicious_tld": True, "credential_form": True})
        assert evs[0]["before"] == 0.5
        assert evs[0]["after"] == pytest.approx(0.7, abs=1e-5)
