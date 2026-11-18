"""Gemini AI servis katmanı — olay bildirimi analizi (analyze_user_report).

Özellikler:
- Retry mekanizması (3 deneme, üstel geri çekilme)
- Token limit kontrolü
- JSON parse fallback
- Hata yönetimi ve logging
"""
import json
import logging
import os
import time
from typing import Any, Dict

from google import genai
from google.genai import types

from .prompts.analyze_report import ANALYZE_REPORT_SYSTEM, ANALYZE_REPORT_USER

logger = logging.getLogger(__name__)

# ── Yapılandırma ─────────────────────────────────────────

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2  # saniye
MAX_OUTPUT_TOKENS = 2048
MAX_INPUT_CHARS = 30000  # ~8K tokens

_client = None


def _get_client():
    """Lazy client init."""
    global _client
    if _client is not None:
        return _client
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY ortam değişkeni ayarlanmamış.")
    _client = genai.Client(api_key=GEMINI_API_KEY)
    return _client


# ── Retry wrapper ─────────────────────────────────────────

def _call_gemini(system: str, user: str) -> str:
    """Gemini'yi çağır, retry ile."""
    client = _get_client()

    # Input truncate
    if len(user) > MAX_INPUT_CHARS:
        user = user[:MAX_INPUT_CHARS] + "\n[...metin kısaltıldı]"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            from app.ai_budget import reserve_ai_call
            reserve_ai_call()
            response = client.models.generate_content(
                model=GEMINI_MODEL,
                contents=user,
                config=types.GenerateContentConfig(
                    system_instruction=system,
                    max_output_tokens=MAX_OUTPUT_TOKENS,
                    temperature=0.3,
                ),
            )
            if response.text:
                return response.text
            # Boş yanıt — retry
            logger.warning("Gemini boş yanıt döndü (deneme %d/%d)", attempt, MAX_RETRIES)
        except Exception as e:
            logger.warning("Gemini çağrı hatası (deneme %d/%d): %s", attempt, MAX_RETRIES, e)
            if attempt == MAX_RETRIES:
                raise RuntimeError(f"Gemini çağrısı {MAX_RETRIES} deneme sonrasında başarısız: {e}")

        delay = RETRY_BASE_DELAY * (2 ** (attempt - 1))
        time.sleep(delay)

    raise RuntimeError("Gemini çağrısı beklenmeyen şekilde sona erdi.")


# ── JSON parse yardımcı ──────────────────────────────────

def _extract_json(text: str) -> Dict[str, Any]:
    """Metin içinden JSON çıkar — ```json bloğu veya direkt JSON."""
    # ```json ... ``` bloğu ara
    if "```json" in text:
        start = text.index("```json") + 7
        end = text.find("```", start)
        text = text[start:end]
    elif "```" in text:
        start = text.index("```") + 3
        end = text.find("```", start)
        text = text[start:end]

    try:
        return json.loads(text.strip())
    except json.JSONDecodeError:
        return {}


# ── Analiz parser ─────────────────────────────────────────

def _parse_analysis(text: str) -> Dict[str, Any]:
    """Kullanıcı analiz yanıtını parse et."""
    result = {
        "attack_type": "unknown",
        "risk_score": 50,
        "loss_type": "other",
        "target_platform": "web",
        "critical_warning": "",
        "protection_plan": "",
        "ai_analysis": {},
    }

    # JSON bulunmaya çalış
    json_data = _extract_json(text)
    if json_data:
        result.update({k: v for k, v in json_data.items() if v is not None})
        return result

    # Metin tabanlı parse
    lines = text.split("\n")
    for line in lines:
        line = line.strip()
        if "Saldırı Tipi" in line or "Saldırı türü" in line:
            result["attack_type"] = line.split(":")[-1].strip().strip("[]")
        elif "Risk Skoru" in line or "Risk skoru" in line:
            try:
                val = int("".join(filter(str.isdigit, line.split(":")[-1])))
                result["risk_score"] = min(100, max(0, val))
            except ValueError:
                pass
        elif "Kayıp Türü" in line:
            result["loss_type"] = line.split(":")[-1].strip().strip("[]")
        elif "Kritik Uyarı" in line:
            result["critical_warning"] = line.split(":")[-1].strip()

    # Korunma planı — numaralı satırları topla
    steps = []
    in_plan = False
    for line in lines:
        stripped = line.strip()
        if "KORUNMA PLANI" in stripped or "Korunma planı" in stripped:
            in_plan = True
            continue
        if in_plan and stripped and stripped[0].isdigit():
            step = stripped.lstrip("0123456789.-) ").strip()
            if step:
                steps.append(step)
        if in_plan and stripped.startswith("BAŞVURU") or stripped.startswith("KURALLAR"):
            in_plan = False

    if steps:
        result["protection_plan"] = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))

    result["ai_analysis"] = {"raw_response": text[:500]}
    return result


# ── Public fonksiyonlar ───────────────────────────────────

def analyze_user_report(user_text: str) -> Dict[str, Any]:
    """Kullanıcının anlattığı olayı Gemini ile analiz et.

    Returns:
        dict: attack_type, risk_score, loss_type, protection_plan, ai_analysis
    """
    prompt = ANALYZE_REPORT_USER.format(description=user_text)
    raw = _call_gemini(ANALYZE_REPORT_SYSTEM, prompt)
    return _parse_analysis(raw)

