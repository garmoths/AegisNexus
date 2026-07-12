"""Playwright stealth launch + browser context."""

from __future__ import annotations

from typing import Sequence, TypedDict

from playwright.async_api import Browser as AsyncBrowser
from playwright.async_api import BrowserContext as AsyncBrowserContext
from playwright.async_api import Playwright as AsyncPlaywright
from playwright.sync_api import Browser as SyncBrowser
from playwright.sync_api import BrowserContext as SyncBrowserContext
from playwright.sync_api import Playwright as SyncPlaywright

# avoid decade-old Chrome/91 UAs.
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

CHROMIUM_LAUNCH_ARGS: tuple[str, ...] = (
    "--no-sandbox",
    "--disable-dev-shm-usage",
    "--disable-blink-features=AutomationControlled",
    "--disable-infobars",
    "--window-size=1280,800",
    "--lang=en-US",
)

IGNORE_DEFAULT_ARGS: tuple[str, ...] = ("--enable-automation",)


class ViewportSize(TypedDict):
    width: int
    height: int


DEFAULT_VIEWPORT: ViewportSize = {"width": 1280, "height": 800}

# set default viewport
_FINGERPRINT_SCREEN_WIDTH = 1920
_FINGERPRINT_SCREEN_HEIGHT = 1080

# minimal patches here
_STEALTH_INIT_SCRIPT = """
(() => {
  try {
    Object.defineProperty(navigator, "webdriver", { get: () => undefined });
  } catch (e) {}
  try {
    if (!window.chrome) {
      window.chrome = { runtime: {} };
    }
  } catch (e) {}
  try {
    const orig = Navigator.prototype.permissions.query;
    Navigator.prototype.permissions.query = (parameters) =>
      parameters && parameters.name === "notifications"
        ? Promise.resolve({ state: Notification.permission, onchange: null })
        : orig(parameters);
  } catch (e) {}
})();
"""

# webgl render manipulation and navigator signals
_FINGERPRINT_INIT_SCRIPT = f"""
(() => {{
  const SW = {_FINGERPRINT_SCREEN_WIDTH};
  const SH = {_FINGERPRINT_SCREEN_HEIGHT};
  const VW = {DEFAULT_VIEWPORT["width"]};
  const VH = {DEFAULT_VIEWPORT["height"]};

  const GL_VENDOR = "Google Inc. (Intel)";
  const GL_RENDERER =
    "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)";
  const UNMASKED_VENDOR_WEBGL = 0x9245;
  const UNMASKED_RENDERER_WEBGL = 0x9246;

  try {{
    Object.defineProperty(navigator, "hardwareConcurrency", {{ get: () => 8 }});
  }} catch (e) {{}}
  try {{
    if ("deviceMemory" in navigator) {{
      Object.defineProperty(navigator, "deviceMemory", {{ get: () => 8 }});
    }}
  }} catch (e) {{}}
  try {{
    Object.defineProperty(navigator, "platform", {{ get: () => "Win32" }});
  }} catch (e) {{}}
  try {{
    Object.defineProperty(navigator, "maxTouchPoints", {{ get: () => 0 }});
  }} catch (e) {{}}
  try {{
    Object.defineProperty(navigator, "languages", {{
      get: () => Object.freeze(["en-US", "en"]),
    }});
  }} catch (e) {{}}

  try {{
    Object.defineProperty(screen, "width", {{ get: () => SW }});
    Object.defineProperty(screen, "height", {{ get: () => SH }});
    Object.defineProperty(screen, "availWidth", {{ get: () => SW }});
    Object.defineProperty(screen, "availHeight", {{ get: () => SH - 40 }});
    Object.defineProperty(screen, "colorDepth", {{ get: () => 24 }});
    Object.defineProperty(screen, "pixelDepth", {{ get: () => 24 }});
  }} catch (e) {{}}

  try {{
    if (window.outerWidth === 0 || window.outerWidth === undefined) {{
      Object.defineProperty(window, "outerWidth", {{ get: () => VW }});
      Object.defineProperty(window, "outerHeight", {{ get: () => VH + 85 }});
    }}
  }} catch (e) {{}}

  try {{
    if (navigator.connection) {{
      Object.defineProperty(navigator.connection, "rtt", {{ get: () => 50 }});
      Object.defineProperty(navigator.connection, "downlink", {{ get: () => 10 }});
      Object.defineProperty(navigator.connection, "effectiveType", {{ get: () => "4g" }});
    }}
  }} catch (e) {{}}

  const patchWebGLGetParameter = (Proto) => {{
    if (!Proto || !Proto.prototype || !Proto.prototype.getParameter) return;
    const orig = Proto.prototype.getParameter;
    Proto.prototype.getParameter = function (param) {{
      if (param === UNMASKED_VENDOR_WEBGL) return GL_VENDOR;
      if (param === UNMASKED_RENDERER_WEBGL) return GL_RENDERER;
      return orig.call(this, param);
    }};
  }};
  try {{
    patchWebGLGetParameter(window.WebGLRenderingContext);
    patchWebGLGetParameter(window.WebGL2RenderingContext);
  }} catch (e) {{}}
}})();
"""


async def launch_chromium_for_takedown(
    playwright: AsyncPlaywright,
    *,
    headless: bool,
) -> AsyncBrowser:
    """Launch Chromium with anti-automation launch flags."""
    return await playwright.chromium.launch(
        headless=headless,
        args=list(CHROMIUM_LAUNCH_ARGS),
        ignore_default_args=list(IGNORE_DEFAULT_ARGS),
    )


def launch_chromium_sync(playwright: SyncPlaywright, *, headless: bool) -> SyncBrowser:
    """Sync Chromium launch (screenshot pool)."""
    return playwright.chromium.launch(
        headless=headless,
        args=list(CHROMIUM_LAUNCH_ARGS),
        ignore_default_args=list(IGNORE_DEFAULT_ARGS),
    )


async def new_stealth_browser_context(
    browser: AsyncBrowser,
    *,
    user_agent: str = DEFAULT_USER_AGENT,
    viewport: ViewportSize | None = None,
    locale: str = "en-US",
    timezone_id: str = "America/New_York",
    fingerprint: bool = False,
    extra_init_scripts: Sequence[str] | None = None,
) -> AsyncBrowserContext:
    """Create a browser context with a realistic desktop profile and stealth init.

    Args:
        browser: Connected Chromium instance from Playwright.
        user_agent: HTTP User-Agent header for the context.
        viewport: Optional viewport; defaults to :data:`DEFAULT_VIEWPORT`.
        locale: BCP-47 locale for the context.
        timezone_id: IANA timezone id (e.g. ``America/New_York``).
        fingerprint: If True, also inject WebGL / screen / navigator fingerprint
            patches (intended for X/Twitter help forms only for now).
        extra_init_scripts: Additional scripts injected after stealth (e.g. X Cloudflare hook).
    """
    vp = viewport or DEFAULT_VIEWPORT
    context = await browser.new_context(
        user_agent=user_agent,
        viewport=vp,
        device_scale_factor=1,
        locale=locale,
        timezone_id=timezone_id,
        has_touch=False,
        is_mobile=False,
        color_scheme="light",
        java_script_enabled=True,
    )
    await context.add_init_script(_STEALTH_INIT_SCRIPT)
    if fingerprint:
        await context.add_init_script(_FINGERPRINT_INIT_SCRIPT)
    if extra_init_scripts:
        for script in extra_init_scripts:
            await context.add_init_script(script)
    return context


def new_stealth_browser_context_sync(
    browser: SyncBrowser,
    *,
    user_agent: str = DEFAULT_USER_AGENT,
    viewport: ViewportSize | None = None,
    locale: str = "en-US",
    timezone_id: str = "America/New_York",
    fingerprint: bool = False,
    extra_init_scripts: Sequence[str] | None = None,
    ignore_https_errors: bool = False,
) -> SyncBrowserContext:
    """Sync :func:`new_stealth_browser_context` — used by ``playwright_pool``."""
    vp = viewport or DEFAULT_VIEWPORT
    context = browser.new_context(
        user_agent=user_agent,
        viewport=vp,
        device_scale_factor=1,
        locale=locale,
        timezone_id=timezone_id,
        has_touch=False,
        is_mobile=False,
        color_scheme="light",
        java_script_enabled=True,
        ignore_https_errors=ignore_https_errors,
    )
    context.add_init_script(_STEALTH_INIT_SCRIPT)
    if fingerprint:
        context.add_init_script(_FINGERPRINT_INIT_SCRIPT)
    if extra_init_scripts:
        for script in extra_init_scripts:
            context.add_init_script(script)
    return context
