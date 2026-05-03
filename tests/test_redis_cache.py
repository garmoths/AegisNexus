"""
Redis Cache Layer — Unit Tests
================================
Redis bağlantısı gerektirir: redis-cli ping → PONG

Sadece unit test (Redis gerekmez):
    pytest tests/test_redis_cache.py -k "no_redis" -v

Redis ile tam test:
    pytest tests/test_redis_cache.py -v
"""
import json
import pytest
from unittest.mock import MagicMock, patch


# ── Yardımcılar ───────────────────────────────────────────────────────────

FAKE_RESULT = {
    "url": "https://test-phishing.tk",
    "safety_score": 12,
    "score": 12,
    "risk_level": "🚨 Tehlikeli",
    "details": ["Marka taklidi tespit edildi"],
    "sources": [{"name": "Screenshot Analyzer", "status": "CRITICAL (88/100)"}],
}

FAKE_SAFE_RESULT = {
    "url": "https://ziraatbank.com.tr",
    "safety_score": 97,
    "score": 97,
    "risk_level": "✅ Güvenli",
    "details": ["Whitelist eşleşmesi"],
    "sources": [],
}


# ── Graceful Fallback (Redis yokken) ─────────────────────────────────────

class TestRedisUnavailable:
    """Redis sunucusu kapalıyken hiçbir şey crash etmemeli."""

    def test_get_scan_returns_none_when_redis_down(self, monkeypatch):
        import modules.phishing_detector.redis_cache as rc
        monkeypatch.setattr(rc, "_redis_client", None)
        monkeypatch.setenv("REDIS_HOST", "127.0.0.1")
        monkeypatch.setenv("REDIS_PORT", "19999")  # kapalı port

        result = rc.redis_get_scan("any_hash")
        assert result is None  # Exception değil

    def test_set_scan_returns_false_when_redis_down(self, monkeypatch):
        import modules.phishing_detector.redis_cache as rc
        monkeypatch.setattr(rc, "_redis_client", None)
        monkeypatch.setenv("REDIS_PORT", "19999")

        ok = rc.redis_set_scan("any_hash", FAKE_RESULT)
        assert ok is False  # Exception değil

    def test_get_threat_returns_none_when_redis_down(self, monkeypatch):
        import modules.phishing_detector.redis_cache as rc
        monkeypatch.setattr(rc, "_redis_client", None)
        monkeypatch.setenv("REDIS_PORT", "19999")

        result = rc.redis_get_threat("spamhaus:ip:1.2.3.4")
        assert result is None

    def test_gemini_count_returns_zero_when_redis_down(self, monkeypatch):
        import modules.phishing_detector.redis_cache as rc
        monkeypatch.setattr(rc, "_redis_client", None)
        monkeypatch.setenv("REDIS_PORT", "19999")

        count = rc.redis_get_gemini_count()
        assert count == 0

    def test_gemini_incr_returns_zero_when_redis_down(self, monkeypatch):
        import modules.phishing_detector.redis_cache as rc
        monkeypatch.setattr(rc, "_redis_client", None)
        monkeypatch.setenv("REDIS_PORT", "19999")

        result = rc.redis_incr_gemini_counter()
        assert result == 0

    def test_health_reports_unavailable(self, monkeypatch):
        import modules.phishing_detector.redis_cache as rc
        monkeypatch.setattr(rc, "_redis_client", None)
        monkeypatch.setenv("REDIS_PORT", "19999")

        health = rc.redis_health()
        assert health["available"] is False


# ── Mock Redis (bağlantı gerektirmez) ────────────────────────────────────

class TestWithMockRedis:
    """Redis davranışını mock ederek test et."""

    @pytest.fixture
    def mock_redis(self):
        store = {}

        class FakeRedis:
            def ping(self): return True
            def get(self, key): return store.get(key)
            def setex(self, key, ttl, value): store[key] = value; return True
            def delete(self, key): store.pop(key, None); return 1
            def incr(self, key): store[key] = str(int(store.get(key, "0")) + 1); return int(store[key])
            def expire(self, key, ttl): return True
            def info(self, section): return {"used_memory_human": "1.5M"}
            def pipeline(self):
                class FakePipe:
                    def __init__(self): self._cmds = []
                    def incr(self, k): self._cmds.append(('incr', k)); return self
                    def expire(self, k, t): self._cmds.append(('expire', k, t)); return self
                    def execute(self_):
                        results = []
                        for cmd in self_._cmds:
                            if cmd[0] == 'incr':
                                store[cmd[1]] = str(int(store.get(cmd[1], "0")) + 1)
                                results.append(int(store[cmd[1]]))
                            else:
                                results.append(True)
                        return results
                return FakePipe()

        import modules.phishing_detector.redis_cache as rc
        rc._redis_client = FakeRedis()
        yield FakeRedis(), store
        rc._redis_client = None

    def test_set_and_get_scan(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        rc.redis_set_scan("abc123", FAKE_RESULT)
        result = rc.redis_get_scan("abc123")
        assert result is not None
        assert result["safety_score"] == 12
        assert result["_redis_hit"] is True

    def test_get_scan_miss_returns_none(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        result = rc.redis_get_scan("nonexistent_hash")
        assert result is None

    def test_invalidate_scan(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        rc.redis_set_scan("del_hash", FAKE_RESULT)
        assert rc.redis_get_scan("del_hash") is not None
        rc.redis_invalidate_scan("del_hash")
        assert rc.redis_get_scan("del_hash") is None

    def test_set_and_get_threat(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        data = {"listed": True, "threat_type": "phishing"}
        rc.redis_set_threat("urlhaus:domain:evil.tk", data)
        result = rc.redis_get_threat("urlhaus:domain:evil.tk")
        assert result["listed"] is True
        assert result["_cache_hit"] is True

    def test_gemini_counter_increments(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        before = rc.redis_get_gemini_count()
        rc.redis_incr_gemini_counter()
        after = rc.redis_get_gemini_count()
        assert after == before + 1

    def test_gemini_limit_reached(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        _, store = mock_redis
        store["gemini:daily_count"] = "1400"
        assert rc.gemini_limit_reached() is True

    def test_gemini_limit_not_reached(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        _, store = mock_redis
        store["gemini:daily_count"] = "500"
        assert rc.gemini_limit_reached() is False

    def test_health_returns_available(self, mock_redis):
        import modules.phishing_detector.redis_cache as rc
        health = rc.redis_health()
        assert health["available"] is True
        assert "used_memory_human" in health
        assert "gemini_daily_count" in health

    def test_json_serialization_preserved(self, mock_redis):
        """Karmaşık iç içe dict'ler doğru serialize/deserialize edilmeli."""
        import modules.phishing_detector.redis_cache as rc
        complex_result = {
            "url": "https://evil.com",
            "safety_score": 0,
            "threat_intel": {
                "screenshot_analysis": {"risk_score": 90, "verdict": "Phishing"},
                "total_penalty": 185,
            },
            "sources": [{"name": "VT", "status": "5 MAL"}],
        }
        rc.redis_set_scan("complex_hash", complex_result)
        result = rc.redis_get_scan("complex_hash")
        assert result["threat_intel"]["total_penalty"] == 185
        assert result["sources"][0]["name"] == "VT"


# ── Python syntax check ───────────────────────────────────────────────────

def test_module_imports_clean():
    """redis_cache.py sözdizimi ve import hataları olmamalı."""
    import modules.phishing_detector.redis_cache  # noqa
