"""
A3 — Playwright Browser Pool (Sync)
=====================================
Her Celery worker process'i için tek persistent Chromium instance.
Her tarama isteği yeni BrowserContext alır (tam izolasyon), bitince kapatır.
Browser kapanmaz → launch overhead (~3-5s, ~300MB spike) ortadan kalkar.

Kullanım:
    from .playwright_pool import acquire_browser_context, init_pool, close_pool

    # Worker başlangıcında (opsiyonel, lazy init de çalışır):
    init_pool()

    # Her tarama isteğinde:
    with acquire_browser_context() as context:
        page = context.new_page()
        page.goto(url)
        ...
"""

from __future__ import annotations

import atexit
import logging
import os
import threading
from contextlib import contextmanager

from playwright.sync_api import Browser, BrowserContext, sync_playwright

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
POOL_SIZE = int(os.getenv("PLAYWRIGHT_POOL_SIZE", "1"))  # process başına browser sayısı
_LAUNCH_ARGS = [
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-gpu",
    "--disable-background-networking",
    "--disable-default-apps",
    "--disable-extensions",
    "--disable-sync",
    "--disable-translate",
    "--hide-scrollbars",
    "--metrics-recording-only",
    "--mute-audio",
    "--no-first-run",
    "--safebrowsing-disable-auto-update",
    "--js-flags=--max-old-space-size=128",
]

# ── Process-local state (her fork'ta sıfır) ───────────────────────────────────
_lock = threading.Lock()
_playwright_handle = None
_browser: Browser | None = None
_initialized: bool = False


def _launch() -> Browser:
    """Playwright + Chromium başlat. _lock içinde çağrılmalı."""
    global _playwright_handle, _browser, _initialized
    logger.info("[Pool] Chromium başlatılıyor...")
    if _playwright_handle is None:
        _playwright_handle = sync_playwright().start()
    _browser = _playwright_handle.chromium.launch(
        headless=True,
        args=_LAUNCH_ARGS,
    )
    _initialized = True
    logger.info("[Pool] Chromium hazır (PID=%d)", os.getpid())
    return _browser


def _ensure_browser() -> Browser:
    """Mevcut browser sağlıklıysa döndür; değilse yeniden başlat."""
    global _browser
    with _lock:
        if _browser is None or not _browser.is_connected():
            _browser = _launch()
        return _browser


def init_pool() -> None:
    """Worker başlangıcında pre-warm — ilk taramada 0ms overhead."""
    _ensure_browser()
    logger.info("[Pool] Pre-warm tamamlandı (PID=%d)", os.getpid())


def close_pool() -> None:
    """Worker kapanışında temiz kapat."""
    global _playwright_handle, _browser, _initialized
    with _lock:
        if _browser:
            try:
                _browser.close()
            except Exception:
                pass
            _browser = None
        if _playwright_handle:
            try:
                _playwright_handle.stop()
            except Exception:
                pass
            _playwright_handle = None
        _initialized = False
    logger.info("[Pool] Kapatıldı (PID=%d)", os.getpid())


# Process çıkışında otomatik temizle
atexit.register(close_pool)


@contextmanager
def acquire_browser_context(
    viewport_width: int = 1440,
    viewport_height: int = 900,
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
) -> BrowserContext:
    """
    Pool'daki browser'dan yeni BrowserContext al.
    Context işlem bitince otomatik kapatılır (browser değil).

    with acquire_browser_context() as ctx:
        page = ctx.new_page()
        ...
    """
    browser = _ensure_browser()
    context: BrowserContext | None = None
    try:
        context = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": viewport_width, "height": viewport_height},
            user_agent=user_agent,
        )
        yield context
    except Exception:
        # Browser çöktüyse sıfırla — bir sonraki çağrıda yeniden başlatılır
        global _browser
        with _lock:
            _browser = None
        raise
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass


def is_healthy() -> bool:
    """Monitoring için browser durumunu döndür."""
    try:
        return _browser is not None and _browser.is_connected()
    except Exception:
        return False
