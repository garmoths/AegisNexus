from datetime import datetime, timedelta, timezone


def test_screenshot_failed_penalty_thresholds():
    from modules.phishing_detector.threat_intel import _screenshot_failed_penalty

    assert _screenshot_failed_penalty(0) == 0
    assert _screenshot_failed_penalty(19) == 0
    assert _screenshot_failed_penalty(20) == 8
    assert _screenshot_failed_penalty(49) == 8
    assert _screenshot_failed_penalty(50) == 18
    assert _screenshot_failed_penalty(100) == 18


def test_domain_age_penalty_very_new_domain(monkeypatch):
    from modules.phishing_detector import threat_intel as ti

    event_date = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()

    class FakeResponse:
        ok = True
        status_code = 200
        content = b"{}"

        @staticmethod
        def json():
            return {"events": [{"eventAction": "registration", "eventDate": event_date}]}

    monkeypatch.setattr(ti.requests, "get", lambda *args, **kwargs: FakeResponse())
    result = ti._get_domain_age_penalty("example.test")

    assert result["available"] is True
    assert result["age_days"] is not None
    assert result["age_days"] <= 7
    assert result["penalty"] == 65


def test_domain_age_penalty_rdap_failure(monkeypatch):
    from modules.phishing_detector import threat_intel as ti

    def boom(*args, **kwargs):
        raise RuntimeError("rdap down")

    monkeypatch.setattr(ti.requests, "get", boom)
    result = ti._get_domain_age_penalty("example.test")

    assert result["available"] is False
    assert result["penalty"] == 15
    assert "alınamadı" in result["detail"].lower()
