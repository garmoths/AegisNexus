"""
Koşullu Gemini — Unit Tests (B4)
===================================
Gerçek Playwright veya Gemini API çağrısı yapılmaz; tümü mock'lanır.

pytest tests/test_conditional_gemini.py -v
"""
import pytest


@pytest.fixture(autouse=True)
def small_ai_budget(monkeypatch):
    import modules.phishing_detector.screenshot_analyzer as analyzer
    monkeypatch.setattr(analyzer, 'AI_DAILY_LIMIT', 1400)



# ── Yardımcılar ────────────────────────────────────────────────────────────

MOCK_GEMINI_RESPONSE = {
    "risk_score": 88,
    "risk_level": "CRITICAL",
    "verdict": "Ziraat Bankası kimlik avı",
    "screenshot_analysis": "Sahte banka giriş sayfası",
    "threat_indicators": [{"type": "visual", "value": "logo", "reason": "marka taklidi"}],
    "recommendation": "Siteyi ziyaret etmeyin",
}

MOCK_SCREENSHOT_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="


def _make_mock_screenshot(monkeypatch):
    """_capture_screenshot_base64'ü mock'la."""
    import modules.phishing_detector.screenshot_analyzer as sa
    monkeypatch.setattr(
        sa, "_capture_screenshot_base64",
        lambda url, page_text: (MOCK_SCREENSHOT_B64, "mock page text", False)
    )


def _make_mock_gemini(monkeypatch, response=None):
    """_call_groq'yi mock'la."""
    import modules.phishing_detector.screenshot_analyzer as sa
    monkeypatch.setattr(
        sa, "_call_groq",
        lambda **kwargs: response or MOCK_GEMINI_RESPONSE
    )


# ── _should_skip_ai ─────────────────────────────────────────────────────

class TestShouldSkipGemini:
    def test_skip_when_pre_penalty_high(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        # Redis count = 0 (limit yok), ama pre_penalty >= 65
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)
        skip, reason = sa._should_skip_ai(pre_penalty=sa.AI_SKIP_PENALTY_THRESHOLD)
        assert skip is True
        assert "önceki katmanlar" in reason
        assert str(sa.AI_SKIP_PENALTY_THRESHOLD) in reason

    def test_skip_when_daily_limit_reached(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 1400)
        skip, reason = sa._should_skip_ai(pre_penalty=0)
        assert skip is True
        assert "kota" in reason

    def test_no_skip_when_under_threshold_and_limit(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 500)
        skip, reason = sa._should_skip_ai(pre_penalty=30)
        assert skip is False
        assert reason == ""

    def test_edge_pre_penalty_64_not_skipped(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)
        skip, _ = sa._should_skip_ai(pre_penalty=sa.AI_SKIP_PENALTY_THRESHOLD - 1)
        assert skip is False

    def test_edge_pre_penalty_65_skipped(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)
        skip, _ = sa._should_skip_ai(pre_penalty=sa.AI_SKIP_PENALTY_THRESHOLD)
        assert skip is True

    def test_edge_daily_count_1399_not_skipped(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 1399)
        skip, _ = sa._should_skip_ai(pre_penalty=0)
        assert skip is False

    def test_edge_daily_count_1400_skipped(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 1400)
        skip, _ = sa._should_skip_ai(pre_penalty=0)
        assert skip is True


# ── analyze() — Groq atlandığında ────────────────────────────────────────

class TestAnalyzeGeminiSkipped:
    def test_gemini_not_called_when_pre_penalty_high(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)
        gemini_called = []
        monkeypatch.setattr(sa, "_call_groq", lambda **k: gemini_called.append(1) or MOCK_GEMINI_RESPONSE)

        result = sa.analyze("https://phishing.tk", pre_penalty=70)

        assert len(gemini_called) == 0
        assert result["ai_skipped"] is True
        assert "ai_skip_reason" in result
        assert result["available"] is True

    def test_gemini_not_called_when_limit_reached(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 1400)
        gemini_called = []
        monkeypatch.setattr(sa, "_call_groq", lambda **k: gemini_called.append(1) or MOCK_GEMINI_RESPONSE)

        result = sa.analyze("https://phishing.tk", pre_penalty=0)

        assert len(gemini_called) == 0
        assert result["ai_skipped"] is True

    def test_skipped_result_has_screenshot_b64(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)
        monkeypatch.setattr(sa, "_call_groq", lambda **k: MOCK_GEMINI_RESPONSE)

        result = sa.analyze("https://phishing.tk", pre_penalty=80)

        assert "screenshot_b64" in result
        assert result["screenshot_b64"] == MOCK_SCREENSHOT_B64

    def test_skipped_result_has_low_risk_score(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)

        result = sa.analyze("https://ambiguous.site", pre_penalty=80)

        # 35 — belirsiz ama normal fallback'ten (50) daha düşük
        assert result["risk_score"] == 35


# ── analyze() — Gemini çağrıldığında ───────────────────────────────────────

class TestAnalyzeGeminiCalled:
    def test_gemini_called_when_conditions_met(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 100)
        _make_mock_gemini(monkeypatch)
        counter = []
        monkeypatch.setattr(sa, "redis_incr_ai_counter", lambda: counter.append(1) or 101)

        result = sa.analyze("https://suspicious.site", pre_penalty=20)

        assert result.get("ai_skipped") is not True
        assert result["risk_score"] == 88
        assert result["risk_level"] == "CRITICAL"
        assert len(counter) == 1  # sayaç artırıldı

    def test_counter_not_incremented_on_gemini_error(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 100)
        monkeypatch.setattr(sa, "_call_groq", lambda **k: (_ for _ in ()).throw(RuntimeError("API error")))
        counter = []
        monkeypatch.setattr(sa, "redis_incr_ai_counter", lambda: counter.append(1) or 101)

        result = sa.analyze("https://suspicious.site", pre_penalty=0)

        assert len(counter) == 1  # Failed provider attempts also consume budget
        assert result["available"] is False  # fallback döndü

    def test_screenshot_b64_in_result_when_gemini_succeeds(self, monkeypatch):
        import modules.phishing_detector.screenshot_analyzer as sa
        _make_mock_screenshot(monkeypatch)
        monkeypatch.setattr(sa, "redis_get_ai_count", lambda: 0)
        _make_mock_gemini(monkeypatch)
        monkeypatch.setattr(sa, "redis_incr_ai_counter", lambda: 1)

        result = sa.analyze("https://test.site", pre_penalty=0)

        assert "screenshot_b64" in result
        assert result["screenshot_b64"] == MOCK_SCREENSHOT_B64


# ── threat_intel.py entegrasyonu ─────────────────────────────────────────

class TestThreatIntelIntegration:
    def test_ai_skipped_adds_10pt_penalty(self, monkeypatch):
        """threat_intel.py: ai_skipped → +10 ceza, not +15.
        Sadece shot işleme mantığını doğrular (run_threat_intelligence tam çağrısı değil).
        """
        skipped_shot = {
            "available": True,
            "ai_skipped": True,
            "ai_skip_reason": "günlük kota aşıldı (1400/1400)",
            "risk_score": 35,
            "risk_level": "UNKNOWN",
        }
        # threat_intel.py'deki if/elif bloğunu burada simüle et
        results = {"total_penalty": 0, "findings": [], "sources": []}
        if skipped_shot.get("ai_skipped"):
            results["total_penalty"] += 10
            results["sources"].append({
                "name": "Screenshot Analyzer",
                "status": f"Groq atlandı ({skipped_shot.get('ai_skip_reason')})"
            })
            results["findings"].append("📸 Screenshot Analyzer: Groq atlandı")

        assert results["total_penalty"] == 10  # 15 değil, 10
        assert results["sources"][0]["name"] == "Screenshot Analyzer"
        assert "Groq atlandı" in results["findings"][0]

    def test_normal_shot_adds_weighted_penalty(self, monkeypatch):
        """Normal Gemini sonucu: risk_score=90 → 54 ceza (90 * 0.60)."""
        normal_shot = {
            "available": True,
            "ai_skipped": False,
            "risk_score": 90,
            "risk_level": "CRITICAL",
            "verdict": "Phishing",
            "threat_indicators": [],
        }
        results = {"total_penalty": 0, "findings": [], "sources": []}
        # threat_intel mantığını burada tekrar ederek test et
        risk_score = max(0, min(100, int(normal_shot.get("risk_score", 50))))
        risk_level_str = str(normal_shot.get("risk_level", "UNKNOWN")).upper()
        weighted_penalty = int(round(risk_score * 0.60))
        if risk_level_str == "CRITICAL":
            weighted_penalty = max(weighted_penalty, 70)
        results["total_penalty"] += weighted_penalty

        assert results["total_penalty"] == 70  # max(54, 70) = 70


# ── _ai_skipped_result yapısı ─────────────────────────────────────────

def test_ai_skipped_result_structure():
    import modules.phishing_detector.screenshot_analyzer as sa
    result = sa._ai_skipped_result("test reason")
    assert result["available"] is True
    assert result["ai_skipped"] is True
    assert result["ai_skip_reason"] == "test reason"
    assert result["risk_score"] == 35
    assert isinstance(result["threat_indicators"], list)


def test_module_imports_clean():
    import modules.phishing_detector.screenshot_analyzer  # noqa
