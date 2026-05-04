"""
A3 — Playwright Browser Pool — Unit Tests
==========================================
Gerçek Playwright/Chromium gerektirmeyen testler:
mock ile pool mantığını, acquire_browser_context context manager'ını,
close_pool temizliğini, is_healthy() ve screenshot_analyzer entegrasyonunu test eder.

pytest tests/test_playwright_pool.py -v
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ── Yardımcı mock'lar ────────────────────────────────────────────────────────

def _make_mock_context():
    ctx = MagicMock()
    ctx.close = MagicMock()
    page = MagicMock()
    page.goto = MagicMock()
    page.evaluate = MagicMock()
    page.wait_for_timeout = MagicMock()
    page.inner_text = MagicMock(return_value="page content")
    page.screenshot = MagicMock(return_value=b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)
    page.set_default_navigation_timeout = MagicMock()
    page.set_default_timeout = MagicMock()
    ctx.new_page = MagicMock(return_value=page)
    return ctx


def _make_mock_browser(healthy: bool = True):
    b = MagicMock()
    b.is_connected = MagicMock(return_value=healthy)
    ctx = _make_mock_context()
    b.new_context = MagicMock(return_value=ctx)
    return b


# ── 1. playwright_pool modülü ────────────────────────────────────────────────

class TestPlaywrightPool:
    def test_module_imports_clean(self):
        import modules.phishing_detector.playwright_pool as pool
        assert hasattr(pool, "init_pool")
        assert hasattr(pool, "close_pool")
        assert hasattr(pool, "acquire_browser_context")
        assert hasattr(pool, "is_healthy")

    def test_is_healthy_false_when_not_initialized(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        monkeypatch.setattr(pool, "_browser", None)
        assert pool.is_healthy() is False

    def test_is_healthy_true_when_connected(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser(healthy=True)
        monkeypatch.setattr(pool, "_browser", mock_browser)
        assert pool.is_healthy() is True

    def test_is_healthy_false_when_disconnected(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser(healthy=False)
        monkeypatch.setattr(pool, "_browser", mock_browser)
        assert pool.is_healthy() is False

    def test_close_pool_clears_state(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser()
        mock_pw = MagicMock()
        monkeypatch.setattr(pool, "_browser", mock_browser)
        monkeypatch.setattr(pool, "_playwright_handle", mock_pw)
        monkeypatch.setattr(pool, "_initialized", True)

        pool.close_pool()

        mock_browser.close.assert_called_once()
        mock_pw.stop.assert_called_once()
        assert pool._browser is None
        assert pool._playwright_handle is None
        assert pool._initialized is False

    def test_close_pool_tolerates_exception(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = MagicMock()
        mock_browser.close.side_effect = Exception("crash")
        monkeypatch.setattr(pool, "_browser", mock_browser)
        monkeypatch.setattr(pool, "_playwright_handle", None)
        # Hata fırlatmamalı
        pool.close_pool()
        assert pool._browser is None

    def test_init_pool_launches_browser(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser()
        launched = []

        def fake_ensure():
            launched.append(True)
            return mock_browser

        monkeypatch.setattr(pool, "_ensure_browser", fake_ensure)
        pool.init_pool()
        assert len(launched) == 1

    def test_acquire_browser_context_yields_context(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser()
        mock_ctx = _make_mock_context()
        mock_browser.new_context.return_value = mock_ctx
        monkeypatch.setattr(pool, "_ensure_browser", lambda: mock_browser)

        with pool.acquire_browser_context() as ctx:
            assert ctx is mock_ctx

        mock_ctx.close.assert_called_once()

    def test_acquire_browser_context_closes_on_exception(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser()
        mock_ctx = _make_mock_context()
        mock_browser.new_context.return_value = mock_ctx
        monkeypatch.setattr(pool, "_ensure_browser", lambda: mock_browser)

        with pytest.raises(ValueError, match="test error"):
            with pool.acquire_browser_context() as ctx:
                raise ValueError("test error")

        mock_ctx.close.assert_called_once()

    def test_acquire_browser_context_resets_browser_on_crash(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        mock_browser = _make_mock_browser()
        mock_browser.new_context.side_effect = Exception("browser crashed")
        monkeypatch.setattr(pool, "_browser", mock_browser)
        monkeypatch.setattr(pool, "_ensure_browser", lambda: mock_browser)

        with pytest.raises(Exception, match="browser crashed"):
            with pool.acquire_browser_context():
                pass

        assert pool._browser is None

    def test_ensure_browser_relaunches_if_disconnected(self, monkeypatch):
        import modules.phishing_detector.playwright_pool as pool
        dead_browser = _make_mock_browser(healthy=False)
        new_browser = _make_mock_browser(healthy=True)
        launched = []

        def fake_launch():
            launched.append(True)
            return new_browser

        monkeypatch.setattr(pool, "_browser", dead_browser)
        monkeypatch.setattr(pool, "_playwright_handle", None)
        monkeypatch.setattr(pool, "_launch", fake_launch)

        result = pool._ensure_browser()
        assert result is new_browser
        assert len(launched) == 1


# ── 2. screenshot_analyzer pool entegrasyonu ─────────────────────────────────

class TestScreenshotAnalyzerPool:
    def test_uses_pool_not_sync_playwright(self):
        """screenshot_analyzer artık sync_playwright() çağırmamalı."""
        import modules.phishing_detector.screenshot_analyzer as sa
        import inspect
        source = inspect.getsource(sa._capture_screenshot_base64)
        assert "sync_playwright" not in source, \
            "_capture_screenshot_base64 hala sync_playwright() kullanıyor!"
        assert "acquire_browser_context" in source

    def test_capture_uses_pool_context(self, monkeypatch):
        """_capture_screenshot_base64 pool'dan context almalı."""
        import modules.phishing_detector.screenshot_analyzer as sa

        mock_ctx = _make_mock_context()

        @contextmanager
        def fake_acquire(**kwargs):
            yield mock_ctx

        # screenshot_analyzer kendi namespace'inden import ettiği ismi patch ediyoruz
        monkeypatch.setattr(sa, "acquire_browser_context", fake_acquire)

        screenshot_b64, text = sa._capture_screenshot_base64("https://example.com", "")
        import base64
        raw = base64.b64decode(screenshot_b64)
        assert raw[:4] == b"\x89PNG"

    def test_screenshot_taken_once_per_call(self, monkeypatch):
        """Her çağrıda page.screenshot tam olarak 1 kez çağrılmalı."""
        import modules.phishing_detector.screenshot_analyzer as sa

        mock_ctx = _make_mock_context()
        page = mock_ctx.new_page.return_value

        @contextmanager
        def fake_acquire(**kwargs):
            yield mock_ctx

        monkeypatch.setattr(sa, "acquire_browser_context", fake_acquire)
        sa._capture_screenshot_base64("https://example.com", "")
        page.screenshot.assert_called_once()


# ── 3. cache-health endpoint playwright_pool durumu ──────────────────────────

def _get_router_mod():
    import sys, importlib
    m = sys.modules.get("modules.phishing_detector.router")
    if m is None:
        importlib.import_module("modules.phishing_detector.router")
        m = sys.modules["modules.phishing_detector.router"]
    return m


class TestCacheHealthPoolStatus:
    def _patch(self, rt, patches):
        originals = {}
        for k, v in patches.items():
            originals[k] = getattr(rt, k, None)
            setattr(rt, k, v)
        return originals

    def _restore(self, rt, originals):
        for k, v in originals.items():
            if v is None:
                try: delattr(rt, k)
                except AttributeError: pass
            else:
                setattr(rt, k, v)

    def test_cache_health_includes_playwright_pool(self, monkeypatch):
        rt = _get_router_mod()
        originals = self._patch(rt, {
            "redis_health": lambda: {"available": True},
        })
        import modules.phishing_detector.playwright_pool as pool
        monkeypatch.setattr(pool, "_browser", _make_mock_browser(healthy=True))
        try:
            result = rt.get_cache_health()
        finally:
            self._restore(rt, originals)
        assert "playwright_pool" in result
        assert result["playwright_pool"]["browser_alive"] is True

    def test_cache_health_pool_false_when_down(self, monkeypatch):
        rt = _get_router_mod()
        originals = self._patch(rt, {
            "redis_health": lambda: {"available": True},
        })
        import modules.phishing_detector.playwright_pool as pool
        monkeypatch.setattr(pool, "_browser", None)
        try:
            result = rt.get_cache_health()
        finally:
            self._restore(rt, originals)
        assert result["playwright_pool"]["browser_alive"] is False
