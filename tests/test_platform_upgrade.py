"""
Platform Upgrade — Faz 1-7 Unit + Integration Testleri

Çalıştırma:
    pytest tests/test_platform_upgrade.py -v
"""
import pytest
from unittest.mock import patch, MagicMock


# ─────────────────────────────────────────────────────────────────────────────
# FAZ 1: EVENT BUS
# ─────────────────────────────────────────────────────────────────────────────

class TestEventBus:
    def setup_method(self):
        from modules.shared import events
        events._listeners.clear()

    def test_subscribe_and_publish(self):
        from modules.shared.events import subscribe, publish
        received = []
        subscribe("test.event", lambda p: received.append(p))
        publish("test.event", {"value": 42})
        assert received == [{"value": 42}]

    def test_publish_no_subscribers(self):
        from modules.shared.events import publish
        publish("unknown.event", {"x": 1})  # should not raise

    def test_multiple_subscribers(self):
        from modules.shared.events import subscribe, publish
        calls = []
        subscribe("multi.event", lambda p: calls.append("A"))
        subscribe("multi.event", lambda p: calls.append("B"))
        publish("multi.event", {})
        assert sorted(calls) == ["A", "B"]

    def test_subscriber_exception_does_not_propagate(self):
        from modules.shared.events import subscribe, publish
        subscribe("err.event", lambda p: (_ for _ in ()).throw(ValueError("boom")))
        publish("err.event", {})  # should NOT raise

    def test_register_event_listeners(self):
        from modules.shared.event_listeners import register_event_listeners
        from modules.shared import events
        register_event_listeners()
        assert "url.phishing_confirmed" in events._listeners
        assert "honeypot.ioc_collected" in events._listeners
        assert "report.pdf_requested" in events._listeners





# ─────────────────────────────────────────────────────────────────────────────
# FAZ 3: KVKK PDF
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# FAZ 4: VICTIM ATLAS TRENDS
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# FAZ 5: PASSWORD SHIELD HIBP
# ─────────────────────────────────────────────────────────────────────────────



# ─────────────────────────────────────────────────────────────────────────────
# FAZ 6: RISK DASHBOARD AGGREGATOR
# ─────────────────────────────────────────────────────────────────────────────

