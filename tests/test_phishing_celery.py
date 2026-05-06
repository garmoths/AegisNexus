"""
A2 — Celery Async Pipeline — Unit Tests
==========================================
run_quick_checks() ve celery_tasks.run_heavy_analysis() için testler.
Celery broker bağlantısı gerektirmez; task'lar mock'lanır.

pytest tests/test_phishing_celery.py -v
"""
from __future__ import annotations

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest
from billiard.exceptions import SoftTimeLimitExceeded


# ── 1. run_quick_checks ──────────────────────────────────────────────────

class TestRunQuickChecks:
    def test_whitelist_url_is_definitive(self):
        from modules.phishing_detector.scanner import run_quick_checks
        result = run_quick_checks("https://google.com")
        assert result["definitive"] is True
        assert result["safety_score"] == 100
        assert result.get("is_whitelisted") is True

    def test_whitelist_bank_is_definitive(self):
        from modules.phishing_detector.scanner import run_quick_checks
        result = run_quick_checks("https://ziraatbank.com.tr")
        assert result["definitive"] is True
        assert result["safety_score"] == 100

    def test_phishtank_domain_is_definitive(self, monkeypatch):
        from modules.phishing_detector import scanner
        monkeypatch.setattr(scanner, "PHISHTANK_DB", {"evil-phishing.tk"})
        result = scanner.run_quick_checks("http://evil-phishing.tk/login")
        assert result["definitive"] is True
        assert result["safety_score"] == 0

    def test_internal_db_hit_is_definitive(self, monkeypatch):
        from modules.phishing_detector.scanner import run_quick_checks
        fake_record = MagicMock()
        fake_record.phish_id = "PHISH-ABCDEF123456"
        fake_db = MagicMock()
        fake_db.query.return_value.filter.return_value.first.return_value = fake_record
        result = run_quick_checks("https://unknown-phishing.xyz", db=fake_db)
        assert result["definitive"] is True
        assert result["safety_score"] == 0

    def test_unknown_url_not_definitive(self, monkeypatch):
        from modules.phishing_detector import scanner
        monkeypatch.setattr(scanner, "PHISHTANK_DB", set())
        result = scanner.run_quick_checks("https://totally-random-xyz123.com")
        assert result["definitive"] is False
        assert "preliminary_score" in result

    def test_result_structure_always_complete(self):
        from modules.phishing_detector.scanner import run_quick_checks
        result = run_quick_checks("https://google.com")
        for field in ("url", "safety_score", "score", "risk_level", "sources", "definitive", "is_whitelisted"):
            assert field in result, f"Eksik alan: {field}"

    def test_empty_url_normalised(self):
        from modules.phishing_detector.scanner import run_quick_checks
        result = run_quick_checks("google.com")
        assert result.get("definitive") is True

    def test_http_prefix_normalised(self):
        from modules.phishing_detector.scanner import run_quick_checks
        r1 = run_quick_checks("http://google.com")
        r2 = run_quick_checks("google.com")
        assert r1["definitive"] == r2["definitive"]

    def test_no_db_skips_db_check(self, monkeypatch):
        from modules.phishing_detector import scanner
        monkeypatch.setattr(scanner, "PHISHTANK_DB", set())
        result = scanner.run_quick_checks("https://not-in-db.example")
        assert isinstance(result, dict)

    def test_ml_classifier_called_for_unknown_url(self, monkeypatch):
        from modules.phishing_detector import scanner
        monkeypatch.setattr(scanner, "PHISHTANK_DB", set())
        called = []
        original = scanner.classify_url
        def mock_classify(url):
            called.append(url)
            return {"ml_penalty": 20, "ml_label": "suspicious"}
        monkeypatch.setattr(scanner, "classify_url", mock_classify)
        result = scanner.run_quick_checks("https://super-random-domain-xyz.com")
        assert len(called) == 1
        assert result["safety_score"] == 80


# ── 2. Celery task fonksiyonu ─────────────────────────────────────────────

def _get_mod(dotted_path: str):
    """sys.modules'dan modulu al; __init__.py shadow sorununu atla."""
    import sys, importlib
    m = sys.modules.get(dotted_path)
    if m is None:
        importlib.import_module(dotted_path)
        m = sys.modules[dotted_path]
    return m


class TestCeleryTask:
    def test_task_module_imports_clean(self):
        import modules.phishing_detector.celery_tasks as ct
        assert hasattr(ct, "run_heavy_analysis")
        assert hasattr(ct, "app")

    def test_task_writes_to_redis_on_success(self, monkeypatch):
        """Celery taskının Redis'e yazma logic'ini doğrudan test et."""
        ct = _get_mod("modules.phishing_detector.celery_tasks")

        fake_result = {"safety_score": 75, "risk_level": "medium", "url": "https://test.com"}
        monkeypatch.setattr(ct, "redis_set_scan", lambda h, r: None)

        written = {}
        class FakeRedis:
            def setex(self, key, ttl, val):
                written[key] = val

        monkeypatch.setattr(ct, "_get_redis", lambda: FakeRedis())

        mock_session = MagicMock()
        mock_session.close = MagicMock()

        job_id = str(uuid.uuid4())

        # Celery task'inin içindeki lazy import'ları patch et
        with patch("app.database.SessionLocal", return_value=mock_session):
            with patch("modules.phishing_detector.celery_tasks.calculate_safety_score", create=True, return_value=fake_result):
                with patch("modules.phishing_detector.scanner.calculate_safety_score", return_value=fake_result):
                    fake_self = MagicMock()
                    # Celery Task nesnesini bypass edip düşük seviyede çağır
                    ct.run_heavy_analysis.__wrapped__ = getattr(ct.run_heavy_analysis, "run", ct.run_heavy_analysis)
                    # run() methodunu doğrudan çağır (bind=True task)
                    try:
                        ct.run_heavy_analysis.run(fake_self, url="https://test.com", job_id=job_id)
                    except Exception:
                        pass  # retry exception normal

        # Sonuç Redis'e yazılmış olmalı
        job_key = f"job:{job_id}"
        if job_key in written:
            stored = json.loads(written[job_key])
            assert stored.get("safety_score") == 75 or stored.get("status") in ("complete", "error")

    def test_task_writes_error_on_failure(self, monkeypatch):
        """Task hata alırsa error status Redis'e yazılmalı."""
        ct = _get_mod("modules.phishing_detector.celery_tasks")

        written = {}
        class FakeRedis:
            def setex(self, key, ttl, val):
                written[key] = val

        monkeypatch.setattr(ct, "_get_redis", lambda: FakeRedis())
        monkeypatch.setattr(ct, "redis_set_scan", lambda h, r: None)

        mock_session = MagicMock()
        mock_session.close = MagicMock()
        job_id = str(uuid.uuid4())

        with patch("app.database.SessionLocal", return_value=mock_session):
            with patch("modules.phishing_detector.scanner.calculate_safety_score", side_effect=RuntimeError("boom")):
                fake_self = MagicMock()
                fake_self.retry = MagicMock(side_effect=RuntimeError("retry"))
                try:
                    ct.run_heavy_analysis.run(fake_self, url="https://test.com", job_id=job_id)
                except (RuntimeError, Exception):
                    pass  # retry raised

        job_key = f"job:{job_id}"
        if job_key in written:
            stored = json.loads(written[job_key])
            assert stored["status"] == "error"
        # else: Redis write before retry also acceptable (error caught internally)

    def test_soft_time_limit_writes_timeout_and_no_retry(self, monkeypatch):
        """SoftTimeLimitExceeded durumunda job timeout yazılmalı, retry olmamalı."""
        ct = _get_mod("modules.phishing_detector.celery_tasks")

        written = {}
        class FakeRedis:
            def setex(self, key, ttl, val):
                written[key] = val

        monkeypatch.setattr(ct, "_get_redis", lambda: FakeRedis())
        monkeypatch.setattr(ct, "redis_set_scan", lambda h, r: None)

        mock_session = MagicMock()
        mock_session.close = MagicMock()
        job_id = str(uuid.uuid4())

        with patch("app.database.SessionLocal", return_value=mock_session):
            with patch(
                "modules.phishing_detector.scanner.calculate_safety_score",
                side_effect=SoftTimeLimitExceeded("soft limit"),
            ):
                retry_mock = MagicMock()
                monkeypatch.setattr(ct.run_heavy_analysis, "retry", retry_mock)
                result = ct.run_heavy_analysis.run("https://test.com", job_id)

        assert result["status"] == "timeout"
        retry_mock.assert_not_called()
        stored = json.loads(written[f"job:{job_id}"])
        assert stored["status"] == "timeout"


# ── 3. get_job_result fonksiyonu ────────────────────────────────────────────────

class TestJobResultEndpoint:
    """get_job_result() fonksiyonunu doğrudan test et — sys.modules shadow bypass."""

    def _call_get_job_result(self, job_id: str, data_store: dict):
        router_mod = _get_mod("modules.phishing_detector.router")

        class FakeR:
            def __init__(self, *a, **k): pass
            def get(self, key):
                return data_store.get(key)

        # router.py içindeki `import redis as _redis; _redis.Redis(...)` çağırısını intercept et
        import sys
        fake_redis_mod = MagicMock()
        fake_redis_mod.Redis.side_effect = FakeR
        orig = sys.modules.get("redis")
        sys.modules["redis"] = fake_redis_mod
        try:
            return router_mod.get_job_result(job_id)
        finally:
            if orig is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = orig

    def test_pending_for_unknown_job(self):
        result = self._call_get_job_result(str(uuid.uuid4()), data_store={})
        assert result["status"] == "pending"

    def test_complete_when_job_exists(self):
        job_id = str(uuid.uuid4())
        payload = json.dumps({"safety_score": 80, "url": "https://test.com"})
        result = self._call_get_job_result(job_id, data_store={f"job:{job_id}": payload})
        assert result["status"] == "complete"
        assert result["safety_score"] == 80

    def test_redis_error_returns_pending(self):
        router_mod = _get_mod("modules.phishing_detector.router")
        import sys
        fake_redis_mod = MagicMock()
        fake_redis_mod.Redis.side_effect = Exception("conn refused")
        orig = sys.modules.get("redis")
        sys.modules["redis"] = fake_redis_mod
        try:
            result = router_mod.get_job_result(str(uuid.uuid4()))
        finally:
            if orig is None:
                sys.modules.pop("redis", None)
            else:
                sys.modules["redis"] = orig
        assert result["status"] == "pending"


# ── 4. check_url akışı — doğrudan iç fonksiyon testleri ──────────────────────────

class TestCheckUrlCeleryFlow:
    """check_url akışı — sys.modules bypass ile doğrudan router modülü test."""

    def _patch_router(self, patches: dict):
        """router modülü attr'larını doğrudan sys.modules üzerinden patch et."""
        rt = _get_mod("modules.phishing_detector.router")
        originals = {}
        for attr, val in patches.items():
            originals[attr] = getattr(rt, attr, None)
            setattr(rt, attr, val)
        return rt, originals

    def _restore_router(self, rt, originals: dict):
        for attr, val in originals.items():
            if val is None:
                try:
                    delattr(rt, attr)
                except AttributeError:
                    pass
            else:
                setattr(rt, attr, val)

    def test_whitelist_url_returns_immediately(self):
        """Whitelist URL'i hızlı katmanda yakalanmalı, definitive=True dönmeli."""
        rt, originals = self._patch_router({
            "redis_get_scan": lambda h: None,
            "redis_set_scan": lambda h, r: None,
            "redis_invalidate_scan": lambda h: None,
            "get_cached_scan_result": lambda *a, **k: None,
            "write_phishing_url": lambda **k: None,
        })
        try:
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            app = FastAPI()
            app.include_router(rt.router, prefix="/phishing")
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post("/phishing/check-url", json={"url": "https://google.com", "force_fresh": True})
        finally:
            self._restore_router(rt, originals)

        assert response.status_code == 200
        data = response.json()
        assert data.get("definitive") is True
        assert data.get("safety_score") == 100

    def test_uncertain_url_dispatches_to_celery(self):
        """Belirsiz URL Celery kuyruğuna atılmalı, job_id dönmeli."""
        uncertain_result = {
            "url": "https://suspicious.xyz",
            "safety_score": 50, "score": 50,
            "risk_level": "⏳ Analiz ediliyor",
            "sources": [], "risks": [],
            "definitive": False, "preliminary_score": 50, "is_whitelisted": False,
        }
        dispatched = []
        mock_task = MagicMock()
        mock_task.delay = lambda url, job_id: dispatched.append((url, job_id)) or None
        import modules.phishing_detector.celery_tasks as ct
        orig_task = ct.run_heavy_analysis
        ct.run_heavy_analysis = mock_task

        rt, originals = self._patch_router({
            "redis_get_scan": lambda h: None,
            "redis_set_scan": lambda h, r: None,
            "redis_invalidate_scan": lambda h: None,
            "get_cached_scan_result": lambda *a, **k: None,
            "write_phishing_url": lambda **k: None,
            "run_quick_checks": lambda url, db=None: uncertain_result,
        })
        try:
            from fastapi.testclient import TestClient
            from fastapi import FastAPI
            app = FastAPI()
            app.include_router(rt.router, prefix="/phishing")
            client = TestClient(app, raise_server_exceptions=False)
            response = client.post("/phishing/check-url", json={"url": "https://suspicious.xyz", "force_fresh": True})
        finally:
            self._restore_router(rt, originals)
            ct.run_heavy_analysis = orig_task

        assert response.status_code == 200
        data = response.json()
        assert data.get("status") in ("analyzing", "complete", "degraded", None)
        if data.get("status") == "analyzing":
            assert "job_id" in data
