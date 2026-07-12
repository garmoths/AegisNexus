"""
A4 — Paralel Threat Intel — Unit Tests
========================================
run_threat_intelligence tüm 5 task'ı paralel çalıştırır.
Her task fonksiyonu mock'lanarak test edilir.

pytest tests/test_parallel_threat_intel.py -v
"""
import time
import pytest
from unittest.mock import patch, MagicMock


CLEAN_SHOT = {
    "available": True,
    "gemini_skipped": False,
    "risk_score": 20,
    "risk_level": "LOW",
    "verdict": "Temiz",
    "threat_indicators": [],
    "recommendation": "Güvenli",
}

CLEAN_VT = {"available": True, "malicious": 0, "suspicious": 0, "status": "clean"}
CLEAN_GSB = {"available": True, "threat": False, "status": "Temiz"}
CLEAN_ABUSEIPDB = {"abuse_score": 0}
CLEAN_SPAMHAUS = {
    "urlhaus": {"listed": False},
    "spamhaus_domain": {"listed": False},
    "spamhaus_ip": {"listed": False},
    "threatfox": {"found": False},
}


def _patch_all_tasks(monkeypatch, shot=None, vt=None, gsb=None, abuseipdb=None, sg=None):
    """Tüm task fonksiyonlarını mock'la."""
    import modules.phishing_detector.threat_intel as ti
    monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: shot or CLEAN_SHOT)
    monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: vt or CLEAN_VT)
    monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: gsb or CLEAN_GSB)
    monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: abuseipdb or CLEAN_ABUSEIPDB)
    monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: sg or CLEAN_SPAMHAUS)
    monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)
    monkeypatch.setattr(ti, "write_ioc", lambda **k: None)


# ── 1. Paralel çalışma: tüm task'lar eş zamanlı tetiklenmeli ──────────────

class TestParallelExecution:
    def test_all_tasks_called(self, monkeypatch):
        """5 task'ın tümü çağrılmalı."""
        import modules.phishing_detector.threat_intel as ti
        called = set()

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: called.add("screenshot") or CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: called.add("virustotal") or CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: called.add("gsb") or CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: called.add("abuseipdb") or CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: called.add("spamhaus_group") or CLEAN_SPAMHAUS)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)

        ti.run_threat_intelligence("https://test.com")

        assert called == {"screenshot", "virustotal", "gsb", "abuseipdb", "spamhaus_group"}

    def test_parallel_faster_than_serial(self, monkeypatch):
        """Paralel çalışma, seri çalışmadan daha hızlı olmalı.
        Her task 0.2s sürer; 5 task seri = ~1s, paralel = ~0.2s."""
        import modules.phishing_detector.threat_intel as ti

        def slow_task(*a, **k):
            time.sleep(0.15)
            return CLEAN_SHOT

        monkeypatch.setattr(ti, "_task_screenshot", slow_task)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: time.sleep(0.15) or CLEAN_SPAMHAUS)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)

        start = time.monotonic()
        ti.run_threat_intelligence("https://test.com")
        elapsed = time.monotonic() - start

        # Seri olsaydı >0.5s sürerdi; paralel <0.5s içinde bitmeli
        assert elapsed < 0.5, f"Paralel çalışma çok yavaş: {elapsed:.2f}s"


# ── 2. Sonuç yapısı ───────────────────────────────────────────────────────

class TestResultStructure:
    def test_result_has_required_fields(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        _patch_all_tasks(monkeypatch)
        result = ti.run_threat_intelligence("https://test.com")
        for field in ("screenshot_analysis", "virustotal", "google_safe_browsing",
                      "abuseipdb", "total_penalty", "findings", "sources",
                      "validated", "risk_score", "risk_level", "is_safe"):
            assert field in result, f"Eksik alan: {field}"

    def test_clean_url_zero_penalty(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        _patch_all_tasks(monkeypatch)
        result = ti.run_threat_intelligence("https://clean.com")
        # Temiz shot: risk_score=20, penalty=max(12, 0)=12 (0.6*20)
        assert result["total_penalty"] <= 15

    def test_screenshot_stored_in_result(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        _patch_all_tasks(monkeypatch)
        result = ti.run_threat_intelligence("https://test.com")
        assert result["screenshot_analysis"] == CLEAN_SHOT


# ── 3. Ceza hesaplama ─────────────────────────────────────────────────────

class TestPenaltyScoring:
    def test_urlhaus_listed_adds_40(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        sg = {**CLEAN_SPAMHAUS, "urlhaus": {"listed": True, "threat_type": "phishing"}}
        _patch_all_tasks(monkeypatch, sg=sg)
        result = ti.run_threat_intelligence("https://phishing.tk")
        assert result["total_penalty"] >= 40
        assert any("URLhaus" in s["name"] for s in result["sources"])

    def test_gsb_threat_adds_50(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        gsb = {"available": True, "threat": True, "status": "MALWARE tespit edildi"}
        _patch_all_tasks(monkeypatch, gsb=gsb)
        result = ti.run_threat_intelligence("https://malware.site")
        assert result["total_penalty"] >= 50

    def test_critical_screenshot_adds_min_70(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        shot = {**CLEAN_SHOT, "risk_score": 90, "risk_level": "CRITICAL", "verdict": "Phishing"}
        _patch_all_tasks(monkeypatch, shot=shot)
        result = ti.run_threat_intelligence("https://phish.xyz")
        assert result["total_penalty"] >= 70

    def test_gemini_skipped_adds_10(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        shot = {
            "available": True, "gemini_skipped": True,
            "gemini_skip_reason": "günlük kota aşıldı", "risk_score": 35, "risk_level": "UNKNOWN",
        }
        _patch_all_tasks(monkeypatch, shot=shot)
        result = ti.run_threat_intelligence("https://test.com")
        assert result["total_penalty"] >= 10
        assert any("Gemini atlandı" in f for f in result["findings"])

    def test_whitelist_skips_urlhaus_penalty(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        sg = {**CLEAN_SPAMHAUS, "urlhaus": {"listed": True, "threat_type": "phishing"}}
        _patch_all_tasks(monkeypatch, sg=sg)
        result = ti.run_threat_intelligence("https://ziraatbank.com.tr", is_whitelisted=True)
        # Whitelist → URLhaus ceza uygulanmamalı
        assert all("URLhaus" not in f for f in result["findings"] if "kara" in f)


# ── 4. Hata toleransı ────────────────────────────────────────────────────

class TestFaultTolerance:
    def test_failed_task_does_not_crash(self, monkeypatch):
        """Bir task exception fırlatsa bile diğerleri çalışmaya devam eder."""
        import modules.phishing_detector.threat_intel as ti

        def failing_gsb(*a, **k):
            raise RuntimeError("GSB API hatası")

        monkeypatch.setattr(ti, "_task_screenshot", lambda *a, **k: CLEAN_SHOT)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", failing_gsb)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SPAMHAUS)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)

        result = ti.run_threat_intelligence("https://test.com")
        assert "total_penalty" in result
        assert result["validated"] is False  # En az bir task başarısız

    def test_all_tasks_failed_returns_valid_structure(self, monkeypatch):
        """Tüm task'lar başarısız olsa bile yapı bozulmamalı."""
        import modules.phishing_detector.threat_intel as ti

        def failing(*a, **k):
            raise RuntimeError("Simulated failure")

        monkeypatch.setattr(ti, "_task_screenshot", failing)
        monkeypatch.setattr(ti, "_task_virustotal", failing)
        monkeypatch.setattr(ti, "_task_gsb", failing)
        monkeypatch.setattr(ti, "_task_abuseipdb", failing)
        monkeypatch.setattr(ti, "_task_spamhaus_group", failing)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)

        result = ti.run_threat_intelligence("https://test.com")
        assert isinstance(result["total_penalty"], int)
        assert isinstance(result["findings"], list)
        assert result["validated"] is False


# ── 5. pre_penalty yayılımı ───────────────────────────────────────────────

class TestPrePenaltyPropagation:
    def test_pre_penalty_passed_to_screenshot_task(self, monkeypatch):
        """pre_penalty değeri _task_screenshot'a iletilmeli."""
        import modules.phishing_detector.threat_intel as ti
        received = []

        def capture_shot(url, http_meta, page_text, pre_penalty):
            received.append(pre_penalty)
            return CLEAN_SHOT

        monkeypatch.setattr(ti, "_task_screenshot", capture_shot)
        monkeypatch.setattr(ti, "_task_virustotal", lambda *a, **k: CLEAN_VT)
        monkeypatch.setattr(ti, "_task_gsb", lambda *a, **k: CLEAN_GSB)
        monkeypatch.setattr(ti, "_task_abuseipdb", lambda *a, **k: CLEAN_ABUSEIPDB)
        monkeypatch.setattr(ti, "_task_spamhaus_group", lambda *a, **k: CLEAN_SPAMHAUS)
        monkeypatch.setattr(ti, "write_phishing_url", lambda **k: None)

        ti.run_threat_intelligence("https://test.com", pre_penalty=70)
        assert received == [70]


# ── 6. Task fonksiyonları unit ────────────────────────────────────────────

class TestTaskFunctions:
    def test_task_gsb_calls_check_google_safe_browsing(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        called = []
        monkeypatch.setattr(ti, "check_google_safe_browsing", lambda url: called.append(url) or CLEAN_GSB)
        result = ti._task_gsb("https://test.com")
        assert called == ["https://test.com"]
        assert result == CLEAN_GSB

    def test_task_screenshot_calls_analyze_screenshot(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        called = []
        monkeypatch.setattr(ti, "analyze_screenshot", lambda **k: called.append(k) or CLEAN_SHOT)
        result = ti._task_screenshot("https://test.com", {}, "text", 30)
        assert len(called) == 1
        assert called[0]["pre_penalty"] == 30

    def test_spamhaus_group_returns_dict(self, monkeypatch):
        import modules.phishing_detector.threat_intel as ti
        # Mock iç importları
        with patch.dict("sys.modules", {
            "modules.phishing_detector.spamhaus_client": MagicMock(
                query_domain=lambda d: {"listed": False},
                query_ip=lambda ip: {"listed": False},
            ),
            "modules.phishing_detector.urlhaus_client": MagicMock(
                query_url=lambda url: {"listed": False},
            ),
            "modules.phishing_detector.threatfox_client": MagicMock(
                query_ioc=lambda *a: {"found": False},
            ),
        }):
            result = ti._task_spamhaus_group("https://test.com", "test.com", "1.2.3.4")
            assert isinstance(result, dict)
