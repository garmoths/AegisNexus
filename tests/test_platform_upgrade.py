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
        assert "victim_atlas.case_ingested" in events._listeners


# ─────────────────────────────────────────────────────────────────────────────
# FAZ 2: BREACH DOMAIN CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class TestDomainChecker:
    def test_invalid_email(self):
        from modules.breach_intel.domain_checker import check_email_domain
        r = check_email_domain("not-an-email")
        assert r["is_suspicious"] == False
        assert r["domain"] is None

    def test_suspicious_bank_domain(self):
        from modules.breach_intel.domain_checker import check_email_domain
        r = check_email_domain("musteri@garanti-destek.com")
        assert r["is_suspicious"] == True
        assert r["risk_score"] >= 40

    def test_suspicious_tld(self):
        from modules.breach_intel.domain_checker import check_email_domain
        r = check_email_domain("someone@domain.tk")
        assert r["risk_score"] >= 40

    def test_extract_domain_strips_at(self):
        from modules.breach_intel.domain_checker import _extract_domain
        assert _extract_domain("user@example.com") == "example.com"
        assert _extract_domain("user@sub.domain.co.uk") == "sub.domain.co.uk"


# ─────────────────────────────────────────────────────────────────────────────
# FAZ 3: KVKK PDF
# ─────────────────────────────────────────────────────────────────────────────

class TestKVKKPDF:
    def test_data_classes_translation(self):
        from modules.breach_intel.kvkk_pdf import _breach_data_classes_tr
        result = _breach_data_classes_tr(["Passwords", "Email addresses", "Phone numbers"])
        assert "Şifreler" in result
        assert "E-posta Adresleri" in result
        assert "Telefon Numaraları" in result

    def test_text_fallback_no_reportlab(self):
        from modules.breach_intel.kvkk_pdf import _generate_text_fallback
        breaches = [{"Name": "TestSite", "BreachDate": "2024-01-01", "DataClasses": ["Passwords"]}]
        r = _generate_text_fallback("test@example.com", breaches, None)
        assert r["method"] == "text_fallback"
        assert r["breach_count"] == 1
        assert r["pdf_base64"]  # non-empty
        assert "TestSite" in r["pdf_bytes"].decode("utf-8")

    def test_tr_date_format(self):
        from modules.breach_intel.kvkk_pdf import _tr_date
        from datetime import date
        d = date(2025, 3, 15)
        assert _tr_date(d) == "15 Mart 2025"

    def test_generate_kvkk_pdf_no_breach(self):
        from modules.breach_intel.kvkk_pdf import generate_kvkk_pdf
        result = generate_kvkk_pdf("clean@example.com", [], None)
        assert result["breach_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# FAZ 4: VICTIM ATLAS TRENDS
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackTrends:
    def _mock_session(self, rows):
        """Çift girdi: (attack_method, cnt) namedtuple gibi davranan nesneler."""
        from unittest.mock import MagicMock
        session = MagicMock()
        q = MagicMock()
        session.query.return_value = q
        q.filter.return_value = q
        q.group_by.return_value = q
        q.order_by.return_value = q
        q.limit.return_value = q
        q.all.return_value = rows
        return session

    def test_get_attack_trends_returns_list_empty(self):
        from unittest.mock import patch, MagicMock
        with patch("modules.victim_atlas.database.SessionLocal") as mock_sl:
            ctx = MagicMock()
            ctx.__enter__ = lambda s: self._mock_session([])
            ctx.__exit__ = MagicMock(return_value=False)
            mock_sl.return_value = ctx
            from modules.victim_atlas.database import get_attack_trends
            result = get_attack_trends(days=30, top_n=5)
        assert result == []

    def test_attack_trends_structure(self):
        from unittest.mock import patch, MagicMock
        from collections import namedtuple
        Row = namedtuple("Row", ["attack_method", "cnt"])
        fake_rows = [Row("phishing", 42), Row("smishing", 18)]
        with patch("modules.victim_atlas.database.SessionLocal") as mock_sl:
            ctx = MagicMock()
            ctx.__enter__ = lambda s: self._mock_session(fake_rows)
            ctx.__exit__ = MagicMock(return_value=False)
            mock_sl.return_value = ctx
            from modules.victim_atlas.database import get_attack_trends
            result = get_attack_trends(days=30, top_n=3)
        assert len(result) == 2
        assert result[0]["attack_method"] == "phishing"
        assert result[0]["count"] == 42
        assert result[0]["rank"] == 1
        assert result[0]["attack_method_tr"] == "Oltalama"
        for item in result:
            assert 0.0 <= item["pct"] <= 100.0

    def test_attack_trends_pct_sums_to_100(self):
        from unittest.mock import patch, MagicMock
        from collections import namedtuple
        Row = namedtuple("Row", ["attack_method", "cnt"])
        fake_rows = [Row("phishing", 60), Row("smishing", 40)]
        with patch("modules.victim_atlas.database.SessionLocal") as mock_sl:
            ctx = MagicMock()
            ctx.__enter__ = lambda s: self._mock_session(fake_rows)
            ctx.__exit__ = MagicMock(return_value=False)
            mock_sl.return_value = ctx
            from modules.victim_atlas.database import get_attack_trends
            result = get_attack_trends(days=30, top_n=5)
        total_pct = sum(r["pct"] for r in result)
        assert abs(total_pct - 100.0) < 0.1


# ─────────────────────────────────────────────────────────────────────────────
# FAZ 5: PASSWORD SHIELD HIBP
# ─────────────────────────────────────────────────────────────────────────────

class TestPwnedCheck:
    def test_sha1_hash_length(self):
        from modules.password_shield.pwned_check import _sha1_hash
        h = _sha1_hash("somepassword")
        assert len(h) == 40
        assert h == h.upper()

    def test_risk_level_mapping(self):
        from modules.password_shield.pwned_check import _risk_level
        assert _risk_level(0) == "safe"
        assert _risk_level(5) == "low"
        assert _risk_level(50) == "medium"
        assert _risk_level(5000) == "high"
        assert _risk_level(100000) == "critical"

    def test_empty_password(self):
        from modules.password_shield.pwned_check import check_pwned
        r = check_pwned("")
        assert r["pwned"] == False
        assert r["method"] == "skipped"

    @patch("urllib.request.urlopen")
    def test_not_pwned(self, mock_urlopen):
        from modules.password_shield.pwned_check import check_pwned, _sha1_hash
        sha1 = _sha1_hash("uniquepasswordXYZ123!@#")
        suffix = sha1[5:]
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"AAAAA:1\nBBBBB:2\n"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        r = check_pwned("uniquepasswordXYZ123!@#")
        assert r["pwned"] == False
        assert r["times_seen"] == 0
        assert r["risk_level"] == "safe"

    @patch("urllib.request.urlopen")
    def test_pwned_password(self, mock_urlopen):
        from modules.password_shield.pwned_check import check_pwned, _sha1_hash
        sha1 = _sha1_hash("password")
        suffix = sha1[5:]
        body = f"{suffix}:3333333\n".encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        r = check_pwned("password")
        assert r["pwned"] == True
        assert r["times_seen"] == 3333333
        assert r["risk_level"] == "critical"


# ─────────────────────────────────────────────────────────────────────────────
# FAZ 6: RISK DASHBOARD AGGREGATOR
# ─────────────────────────────────────────────────────────────────────────────

class TestRiskDashboardAggregator:
    def test_risk_label_thresholds(self):
        from modules.risk_dashboard.aggregator import _risk_label
        assert _risk_label(0) == "DÜŞÜK"
        assert _risk_label(34) == "DÜŞÜK"
        assert _risk_label(35) == "ORTA"
        assert _risk_label(59) == "ORTA"
        assert _risk_label(60) == "YÜKSEK"
        assert _risk_label(79) == "YÜKSEK"
        assert _risk_label(80) == "KRİTİK"
        assert _risk_label(100) == "KRİTİK"

    def test_clamp(self):
        from modules.risk_dashboard.aggregator import _clamp
        assert _clamp(-10) == 0.0
        assert _clamp(150) == 100.0
        assert _clamp(50) == 50.0

    def test_aggregate_risk_structure(self):
        from modules.risk_dashboard.aggregator import aggregate_risk
        result = aggregate_risk("test@example.com")
        assert "composite_score" in result
        assert "risk_label" in result
        assert "risk_color" in result
        assert "modules" in result
        assert "recommendations" in result
        assert "summary" in result
        assert 0 <= result["composite_score"] <= 100
        assert len(result["modules"]) == 4

    def test_aggregate_risk_color_codes(self):
        from modules.risk_dashboard.aggregator import _risk_color
        assert _risk_color(85) == "#d32f2f"
        assert _risk_color(65) == "#f57c00"
        assert _risk_color(50) == "#fbc02d"
        assert _risk_color(10) == "#388e3c"
