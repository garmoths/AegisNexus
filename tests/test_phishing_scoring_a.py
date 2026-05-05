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
    SOURCE_WEIGHTS,
    DEFAULT_SOURCE_WEIGHT,
    SCORING_MODEL_VERSION,
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
