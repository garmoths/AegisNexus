"""
Playwright + Claude Vision tabanli ekran goruntusu analizi.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Dict, Tuple

import requests
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

logger = logging.getLogger(__name__)

CLAUDE_MODEL = "claude-sonnet-4-20250514"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"
MAX_PAGE_TEXT = 3000
PLAYWRIGHT_TIMEOUT_MS = 15000

SYSTEM_PROMPT = """
You are a senior phishing detection analyst specialized in visual deception detection.
Analyze screenshots for phishing, credential harvesting, impersonation, fake urgency,
malicious UI patterns, and scam indicators.

Return ONLY valid JSON (no markdown, no explanations) with this exact schema:
{
  "risk_score": 0-100 integer,
  "risk_level": "SAFE|LOW|MEDIUM|HIGH|CRITICAL|UNKNOWN",
  "verdict": "short verdict",
  "screenshot_analysis": "detailed but concise analysis",
  "threat_indicators": [
    {
      "type": "url|domain|ip|hash|visual",
      "value": "ioc or indicator text",
      "reason": "why suspicious"
    }
  ],
  "recommendation": "action recommendation"
}
"""


def _fallback_result() -> Dict[str, Any]:
    return {
        "risk_score": 50,
        "risk_level": "UNKNOWN",
        "verdict": "Ekran görüntüsü alınamadı",
        "screenshot_analysis": "Playwright veya Claude analizi tamamlanamadı.",
        "threat_indicators": [],
        "recommendation": "URL'yi manuel olarak inceleyin ve kullanıcı etkileşimini engelleyin.",
        "available": False,
    }


def _clean_page_text(page_text: str | None) -> str:
    return (page_text or "").strip()[:MAX_PAGE_TEXT]


def _capture_screenshot_base64(url: str, page_text: str) -> Tuple[str, str]:
    """Headless Chromium ile tam sayfa PNG al ve base64'e cevir."""
    captured_text = page_text
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 900})
        page = context.new_page()
        page.set_default_navigation_timeout(PLAYWRIGHT_TIMEOUT_MS)
        page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)

        page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT_MS)
        page.wait_for_timeout(1000)

        if not captured_text:
            try:
                captured_text = (page.inner_text("body") or "")[:MAX_PAGE_TEXT]
            except Exception:
                captured_text = ""

        screenshot_bytes = page.screenshot(type="png", full_page=True)
        browser.close()
    return base64.b64encode(screenshot_bytes).decode("utf-8"), captured_text


def _extract_json(text: str) -> Dict[str, Any]:
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw.replace("json\n", "", 1).strip()

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end != -1 and end > start:
        raw = raw[start : end + 1]

    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Claude response is not JSON object")
    return data


def _normalize_result(data: Dict[str, Any]) -> Dict[str, Any]:
    result = _fallback_result()
    try:
        risk_score = int(data.get("risk_score", 50))
    except Exception:
        risk_score = 50

    result.update(
        {
            "risk_score": max(0, min(100, risk_score)),
            "risk_level": str(data.get("risk_level", "UNKNOWN")).upper(),
            "verdict": str(data.get("verdict", result["verdict"])),
            "screenshot_analysis": str(data.get("screenshot_analysis", result["screenshot_analysis"])),
            "recommendation": str(data.get("recommendation", result["recommendation"])),
            "available": True,
        }
    )

    indicators = data.get("threat_indicators", [])
    if isinstance(indicators, list):
        result["threat_indicators"] = indicators
    else:
        result["threat_indicators"] = []
    return result


def _call_claude(url: str, screenshot_b64: str, http_meta: Dict[str, Any], page_text: str) -> Dict[str, Any]:
    api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not configured")

    user_payload = {
        "url": url,
        "http_meta": http_meta or {},
        "page_text": _clean_page_text(page_text),
        "output_requirements": {
            "format": "json",
            "strict_schema": True,
            "language": "tr",
        },
    }

    body = {
        "model": CLAUDE_MODEL,
        "max_tokens": 1200,
        "temperature": 0,
        "system": SYSTEM_PROMPT,
        "messages": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "Phishing risk analizi yap. Asagidaki baglamsal veriyi kullan:\n"
                            f"{json.dumps(user_payload, ensure_ascii=False)}"
                        ),
                    },
                    {
                        "type": "image",
                        "source": {"type": "base64", "media_type": "image/png", "data": screenshot_b64},
                    },
                ],
            }
        ],
    }

    response = requests.post(
        ANTHROPIC_API_URL,
        headers={
            "x-api-key": api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        },
        json=body,
        timeout=20,
    )
    response.raise_for_status()
    payload = response.json()
    content = payload.get("content", [])
    text_parts = [part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text"]
    if not text_parts:
        raise ValueError("Claude response has no text content")
    return _extract_json("\n".join(text_parts))


def analyze(url: str, http_meta: Dict[str, Any] | None = None, page_text: str | None = None) -> Dict[str, Any]:
    """
    URL ekran goruntusunu alip Claude vision ile phishing analizi yapar.
    Hata durumunda exception firlatmaz, fallback dondurur.
    """
    normalized_url = (url or "").strip()
    if not normalized_url:
        return _fallback_result()

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = f"https://{normalized_url}"

    try:
        screenshot_b64, captured_text = _capture_screenshot_base64(
            normalized_url,
            _clean_page_text(page_text),
        )
    except PlaywrightTimeoutError as exc:
        logger.warning(f"Screenshot timeout for {normalized_url}: {exc}")
        return _fallback_result()
    except Exception as exc:
        logger.warning(f"Screenshot capture failed for {normalized_url}: {exc}")
        return _fallback_result()

    try:
        claude_result = _call_claude(
            url=normalized_url,
            screenshot_b64=screenshot_b64,
            http_meta=http_meta or {},
            page_text=captured_text,
        )
        return _normalize_result(claude_result)
    except Exception as exc:
        logger.warning(f"Claude screenshot analysis failed for {normalized_url}: {exc}")
        return _fallback_result()
