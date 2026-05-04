"""
Playwright + Gemini Vision tabanli ekran goruntusu analizi.
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Any, Dict, Tuple

import requests
from google import genai
from google.genai import types
from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from .playwright_pool import acquire_browser_context

from .redis_cache import redis_get_gemini_count, redis_incr_gemini_counter, GEMINI_DAILY_LIMIT

logger = logging.getLogger(__name__)
_gemini_client = None

GEMINI_MODEL = "gemini-2.0-flash"
GEMINI_SKIP_PENALTY_THRESHOLD = int(os.getenv("GEMINI_SKIP_THRESHOLD", "65"))
MAX_PAGE_TEXT = 3000
PLAYWRIGHT_TIMEOUT_MS = 25000
_SCREENSHOT_SETTLE_MS = 2500
_SCREENSHOT_MAX_RETRIES = 2

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
        "screenshot_analysis": "Playwright veya Gemini analizi tamamlanamadı.",
        "threat_indicators": [],
        "recommendation": "URL'yi manuel olarak inceleyin ve kullanıcı etkileşimini engelleyin.",
        "available": False,
    }


def _gemini_skipped_result(reason: str) -> Dict[str, Any]:
    """Gemini atlandığında dönen sonuç — screenshot alınmış ama AI analizi yapılmamış."""
    return {
        "risk_score": 35,
        "risk_level": "UNKNOWN",
        "verdict": "AI analizi atlandı",
        "screenshot_analysis": f"Gemini çağrısı atlandı: {reason}",
        "threat_indicators": [],
        "recommendation": "Önceki katmanlar yeterli bilgi sağladı veya günlük kota aşıldı.",
        "available": True,
        "gemini_skipped": True,
        "gemini_skip_reason": reason,
    }


def _should_skip_gemini(pre_penalty: int) -> tuple[bool, str]:
    """Gemini çağrısının atlanıp atlanmayacağını belirler.
    
    Returns:
        (skip: bool, reason: str)
    """
    if pre_penalty >= GEMINI_SKIP_PENALTY_THRESHOLD:
        return True, f"önceki katmanlar yeterli (pre_penalty={pre_penalty}>={GEMINI_SKIP_PENALTY_THRESHOLD})"
    daily_count = redis_get_gemini_count()
    if daily_count >= GEMINI_DAILY_LIMIT:
        return True, f"günlük kota aşıldı ({daily_count}/{GEMINI_DAILY_LIMIT})"
    return False, ""


def _clean_page_text(page_text: str | None) -> str:
    return (page_text or "").strip()[:MAX_PAGE_TEXT]


def _capture_screenshot_base64(url: str, page_text: str) -> Tuple[str, str]:
    """Headless Chromium ile tam sayfa PNG al ve base64'e cevir.

    A3: Her çağrıda yeni browser başlatmaz — pool'dan BrowserContext al.
    Browser process'e bağlı persistent kalır; sadece context (tab) açılıp kapatılır.

    Strateji:
    1. networkidle ile beklemeyi dener; timeout olursa domcontentloaded'a düşer.
    2. Sayfayı en alta kaydırarak lazy-load içeriklerin yüklenmesini tetikler.
    3. _SCREENSHOT_SETTLE_MS kadar dinleyerek animasyonların bitmesini bekler.
    4. _SCREENSHOT_MAX_RETRIES kez yeniden dener.
    """
    captured_text = page_text
    last_exc: Exception | None = None

    for attempt in range(1, _SCREENSHOT_MAX_RETRIES + 1):
        try:
            with acquire_browser_context() as context:
                page = context.new_page()
                page.set_default_navigation_timeout(PLAYWRIGHT_TIMEOUT_MS)
                page.set_default_timeout(PLAYWRIGHT_TIMEOUT_MS)

                # networkidle tercih edilir; bazı siteler bitmez — fallback: domcontentloaded
                try:
                    page.goto(url, wait_until="networkidle", timeout=PLAYWRIGHT_TIMEOUT_MS)
                except PlaywrightTimeoutError:
                    logger.debug(f"networkidle timeout, falling back to domcontentloaded for {url}")
                    page.goto(url, wait_until="domcontentloaded", timeout=PLAYWRIGHT_TIMEOUT_MS)

                # Lazy-load içerikleri tetikle: en alta kaydır, bekle, en üste dön
                try:
                    page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    page.wait_for_timeout(800)
                    page.evaluate("window.scrollTo(0, 0)")
                except Exception:
                    pass

                # Animasyonlar / son yüklemeler için bekle
                page.wait_for_timeout(_SCREENSHOT_SETTLE_MS)

                if not captured_text:
                    try:
                        captured_text = (page.inner_text("body") or "")[:MAX_PAGE_TEXT]
                    except Exception:
                        captured_text = ""

                screenshot_bytes = page.screenshot(type="png", full_page=True)

            return base64.b64encode(screenshot_bytes).decode("utf-8"), captured_text

        except PlaywrightTimeoutError as exc:
            last_exc = exc
            logger.warning(f"Screenshot attempt {attempt}/{_SCREENSHOT_MAX_RETRIES} timeout for {url}: {exc}")
        except Exception as exc:
            last_exc = exc
            logger.warning(f"Screenshot attempt {attempt}/{_SCREENSHOT_MAX_RETRIES} failed for {url}: {exc}")
            if attempt >= _SCREENSHOT_MAX_RETRIES:
                break

    raise last_exc or RuntimeError("Screenshot capture failed after retries")


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
        raise ValueError("Gemini response is not JSON object")
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


def _get_gemini_client(api_key: str):
    global _gemini_client
    if _gemini_client is None:
        _gemini_client = genai.Client(api_key=api_key)
    return _gemini_client


def _call_gemini(url: str, screenshot_b64: str, http_meta: Dict[str, Any], page_text: str) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not configured")

    client = _get_gemini_client(api_key)

    user_payload = {
        "url": url,
        "http_meta": http_meta or {},
        "page_text": _clean_page_text(page_text),
    }

    image_part = types.Part.from_bytes(
        data=base64.b64decode(screenshot_b64),
        mime_type="image/png",
    )

    text_part = (
        "Phishing risk analizi yap. Asagidaki baglamsal veriyi kullan:\n"
        f"{json.dumps(user_payload, ensure_ascii=False)}"
    )

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=[text_part, image_part],
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0,
            max_output_tokens=1200,
            response_mime_type="application/json",
        ),
    )

    text = response.text if response.text else ""
    if not text:
        raise ValueError("Gemini response has no text content")
    return _extract_json(text)


def analyze(
    url: str,
    http_meta: Dict[str, Any] | None = None,
    page_text: str | None = None,
    pre_penalty: int = 0,
) -> Dict[str, Any]:
    """
    URL ekran goruntusunu alip Gemini vision ile phishing analizi yapar.
    Hata durumunda exception firlatmaz, fallback dondurur.

    Args:
        pre_penalty: B1/B2/B3 katmanlarından gelen toplam ceza.
                     >= GEMINI_SKIP_PENALTY_THRESHOLD ise Gemini atlanır.
    """
    normalized_url = (url or "").strip()
    if not normalized_url:
        return _fallback_result()

    if not normalized_url.startswith(("http://", "https://")):
        normalized_url = f"https://{normalized_url}"

    screenshot_b64 = None
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

    # B2: pHash logo karşılaştırma — Gemini'den önce çalışır
    try:
        from .visual_analyzer import check_logo_phash
        import base64 as _b64
        phash_result = check_logo_phash(_b64.b64decode(screenshot_b64), url=normalized_url)
        if phash_result.get("definitive") and phash_result.get("penalty", 0) >= 60:
            brand = phash_result.get("brand", "bilinmeyen")
            logger.info(f"[pHash] Marka logosu tespit edildi ({brand}), Gemini atlanıyor: {normalized_url}")
            result = _gemini_skipped_result(f"pHash logo eşleşti: {brand}")
            result.update({
                "risk_score": 85,
                "risk_level": "HIGH",
                "verdict": f"Marka taklidi tespit edildi: {brand}",
                "screenshot_b64": screenshot_b64,
                "phash_logo": phash_result,
                "available": True,
                "gemini_skipped": True,
                "gemini_skip_reason": f"pHash logo eşleşti: {brand}",
            })
            return result
    except Exception as exc:
        logger.debug(f"[pHash] Kontrol atlandı: {exc}")

    # B3: OCR metin analizi — pHash'ten sonra, Gemini'den önce
    ocr_result = None
    try:
        from .visual_analyzer import analyze_with_ocr
        import base64 as _b64
        from urllib.parse import urlparse as _urlparse
        _domain = _urlparse(normalized_url).netloc or normalized_url
        ocr_result = analyze_with_ocr(_b64.b64decode(screenshot_b64), domain=_domain)
        if ocr_result.get("definitive") and ocr_result.get("penalty", 0) >= 65:
            logger.info(f"[OCR] Kesin sonuç, Gemini atlanıyor: {normalized_url}")
            result = _gemini_skipped_result(ocr_result.get("detail", "OCR kesin sonuç"))
            result.update({
                "risk_score": min(95, 70 + ocr_result.get("penalty", 0) // 5),
                "risk_level": "HIGH",
                "verdict": ocr_result.get("detail", "Marka/credential OCR ile tespit edildi"),
                "screenshot_b64": screenshot_b64,
                "ocr_analysis": ocr_result,
                "available": True,
                "gemini_skipped": True,
                "gemini_skip_reason": "OCR kesin sonuç",
            })
            return result
        # Kesin değil ama penalty varsa → Gemini skip kararına ekle
        pre_penalty = pre_penalty + ocr_result.get("penalty", 0)
    except ImportError:
        logger.debug("[OCR] easyocr yüklü değil, atlanıyor")
    except Exception as exc:
        logger.debug(f"[OCR] Kontrol atlandı: {exc}")

    # Koşullu Gemini: önceki katmanlar yeterliyse veya kota dolmuşsa atla
    skip, skip_reason = _should_skip_gemini(pre_penalty)
    if skip:
        logger.info(f"Gemini atlandı ({normalized_url}): {skip_reason}")
        result = _gemini_skipped_result(skip_reason)
        if screenshot_b64:
            result["screenshot_b64"] = screenshot_b64
        return result

    try:
        gemini_result = _call_gemini(
            url=normalized_url,
            screenshot_b64=screenshot_b64,
            http_meta=http_meta or {},
            page_text=captured_text,
        )
        # Başarılı Gemini çağrısı → sayacı artır
        new_count = redis_incr_gemini_counter()
        logger.debug(f"Gemini çağrıldı ({normalized_url}), günlük toplam: {new_count}/{GEMINI_DAILY_LIMIT}")
        result = _normalize_result(gemini_result)
        if screenshot_b64:
            result["screenshot_b64"] = screenshot_b64
        return result
    except Exception as exc:
        logger.warning(f"Gemini screenshot analysis failed for {normalized_url}: {exc}")
        result = _fallback_result()
        if screenshot_b64:
            result["screenshot_b64"] = screenshot_b64
        return result
