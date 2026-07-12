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

from .stealh import DEFAULT_VIEWPORT, launch_chromium_sync, new_stealth_browser_context_sync

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────
POOL_SIZE = int(os.getenv("PLAYWRIGHT_POOL_SIZE", "1"))  # process başına browser sayısı

# ── Process-local state (her fork'ta sıfır) ───────────────────────────────────
_lock = threading.Lock()
_thread_resources: dict[int, tuple[object, Browser]] = {}
_initialized: bool = False


def _launch_for_current_thread() -> Browser:
    """Playwright + Chromium başlat (yalnızca mevcut thread için)."""
    global _initialized
    tid = threading.get_ident()
    logger.info("[Pool] Chromium başlatılıyor... (PID=%d, TID=%d)", os.getpid(), tid)
    playwright_handle = sync_playwright().start()
    browser = launch_chromium_sync(playwright_handle, headless=True)
    _thread_resources[tid] = (playwright_handle, browser)
    _initialized = True
    logger.info("[Pool] Chromium hazır (PID=%d, TID=%d)", os.getpid(), tid)
    return browser


def _ensure_browser() -> Browser:
    """Mevcut thread için browser sağlıklıysa döndür; değilse yeniden başlat."""
    tid = threading.get_ident()
    with _lock:
        pair = _thread_resources.get(tid)
        if pair is not None:
            _, browser = pair
            try:
                if browser.is_connected():
                    return browser
            except Exception:
                pass

            # Eski kaynak bozuksa kapatıp temizle
            try:
                browser.close()
            except Exception:
                pass
            try:
                pair[0].stop()
            except Exception:
                pass
            _thread_resources.pop(tid, None)

        return _launch_for_current_thread()


def init_pool() -> None:
    """Worker başlangıcında pre-warm — ilk taramada 0ms overhead."""
    _ensure_browser()
    logger.info("[Pool] Pre-warm tamamlandı (PID=%d)", os.getpid())


def close_pool() -> None:
    """Worker kapanışında temiz kapat."""
    global _initialized
    with _lock:
        for tid, (playwright_handle, browser) in list(_thread_resources.items()):
            try:
                browser.close()
            except Exception:
                pass
            try:
                playwright_handle.stop()
            except Exception:
                pass
            _thread_resources.pop(tid, None)
        _initialized = False
    logger.info("[Pool] Kapatıldı (PID=%d)", os.getpid())


# Process çıkışında otomatik temizle
atexit.register(close_pool)


@contextmanager
def acquire_browser_context(
    viewport_width: int | None = None,
    viewport_height: int | None = None,
    fingerprint: bool = False,
) -> BrowserContext:
    """
    Pool'daki browser'dan yeni BrowserContext al.
    Context işlem bitince otomatik kapatılır (browser değil).
    Stealth profili :mod:`~modules.phishing_detector.stealh` ile oluşturulur.

    with acquire_browser_context() as ctx:
        page = ctx.new_page()
        ...
    """
    browser = _ensure_browser()
    vp = DEFAULT_VIEWPORT.copy()
    if viewport_width is not None:
        vp["width"] = viewport_width
    if viewport_height is not None:
        vp["height"] = viewport_height
    context: BrowserContext | None = None
    try:
        context = new_stealth_browser_context_sync(
            browser,
            viewport=vp,
            fingerprint=fingerprint,
            ignore_https_errors=True,
        )
        yield context
    except Exception:
        # Browser çöktüyse mevcut thread kaynağını sıfırla — bir sonraki çağrıda yeniden başlatılır
        tid = threading.get_ident()
        with _lock:
            pair = _thread_resources.pop(tid, None)
            if pair is not None:
                try:
                    pair[1].close()
                except Exception:
                    pass
                try:
                    pair[0].stop()
                except Exception:
                    pass
        raise
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass


def is_healthy() -> bool:
    """Monitoring için mevcut thread browser durumunu döndür."""
    tid = threading.get_ident()
    try:
        pair = _thread_resources.get(tid)
        if pair is None:
            return False
        return pair[1].is_connected()
    except Exception:
        return False
