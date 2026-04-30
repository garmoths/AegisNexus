"""Gemini AI servis katmanı — Victim Atlas için 4 ana fonksiyon.

Fonksiyonlar:
1. analyze_user_report — Kullanıcı anlatımını analiz et
2. classify_case — Ham vaka metnini sınıflandır
3. generate_weekly_digest — Haftalık bülten üret
4. generate_protection_card — Kişiselleştirilmiş korunma kartı

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
from typing import Any, Dict, List, Optional

import google.generativeai as genai

from .prompts.analyze_report import ANALYZE_REPORT_SYSTEM, ANALYZE_REPORT_USER
from .prompts.classify_case import CLASSIFY_CASE_SYSTEM, CLASSIFY_CASE_USER
from .prompts.protection_card import PROTECTION_CARD_SYSTEM, PROTECTION_CARD_USER
from .prompts.weekly_digest import WEEKLY_DIGEST_SYSTEM, WEEKLY_DIGEST_USER

logger = logging.getLogger(__name__)

# ── Yapılandırma ─────────────────────────────────────────

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2  # saniye
MAX_OUTPUT_TOKENS = 2048
MAX_INPUT_CHARS = 30000  # ~8K tokens

_model = None


def _get_model():
    """Lazy model init."""
    global _model
    if _model is not None:
        return _model
    if not GEMINI_API_KEY:
        raise RuntimeError("GEMINI_API_KEY ortam değişkeni ayarlanmamış.")
    genai.configure(api_key=GEMINI_API_KEY)
    _model = genai.GenerativeModel(
        GEMINI_MODEL,
        generation_config=genai.types.GenerationConfig(
            max_output_tokens=MAX_OUTPUT_TOKENS,
            temperature=0.3,
        ),
    )
    return _model


# ── Retry wrapper ─────────────────────────────────────────

def _call_gemini(system: str, user: str) -> str:
    """Gemini'yi çağır, retry ile."""
    model = _get_model()

    # Input truncate
    if len(user) > MAX_INPUT_CHARS:
        user = user[:MAX_INPUT_CHARS] + "\n[...metin kısaltıldı]"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = model.generate_content(
                [system, user],
                request_options={"timeout": 60},
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


def classify_case(raw_text: str) -> Dict[str, Any]:
    """Ham vaka metnini Gemini ile sınıflandır.

    Returns:
        dict: attack_method, loss_type, severity, confidence, tags, region, critical_warning, narrative_summary
    """
    prompt = CLASSIFY_CASE_USER.format(raw_text=raw_text)
    raw = _call_gemini(CLASSIFY_CASE_SYSTEM, prompt)
    result = _extract_json(raw)

    # Fallback: JSON parse başarısızsa varsayılan değerler
    if not result:
        result = {
            "attack_method": "other",
            "loss_type": "other",
            "severity": 50,
            "confidence": 40,
            "tags": [],
            "region": None,
            "critical_warning": "Sınıflandırma yapılamadı.",
            "narrative_summary": raw_text[:200],
        }

    # Tip dönüşümleri
    for int_key in ("severity", "confidence"):
        if int_key in result:
            try:
                result[int_key] = int(result[int_key])
            except (ValueError, TypeError):
                result[int_key] = 50

    return result


def generate_weekly_digest(cases: List[Dict[str, Any]]) -> str:
    """Son haftanın vakalarından haftalık bülten üret.

    Args:
        cases: [{"title": ..., "method": ..., "severity": ...}, ...]

    Returns:
        str: 3 paragraf Türkçe bülten metni
    """
    cases_text = "\n".join(
        f"- {c.get('title', 'Başlıksız')} | {c.get('method', '?')} | Şiddet: {c.get('severity', '?')}"
        for c in cases[:20]
    )
    if not cases_text:
        cases_text = "Bu hafta kayıtlı vaka bulunmuyor."

    prompt = WEEKLY_DIGEST_USER.format(cases_text=cases_text)
    return _call_gemini(WEEKLY_DIGEST_SYSTEM, prompt)


def generate_protection_card(case: Dict[str, Any]) -> Dict[str, Any]:
    """Vaka için kişiselleştirilmiş korunma kartı üret.

    Args:
        case: Vaka detay dict (case_title, attack_method, vb.)

    Returns:
        dict: card_text, attack_method, severity
    """
    prompt = PROTECTION_CARD_USER.format(
        case_title=case.get("case_title", ""),
        attack_method=case.get("attack_method", ""),
        loss_type=case.get("loss_type", ""),
        target_platform=case.get("target_platform", ""),
        severity_score=case.get("severity_score", 50),
        confidence_score=case.get("confidence_score", 50),
        narrative_summary=case.get("narrative_summary", ""),
        critical_warning=case.get("critical_warning", ""),
        region=case.get("region") or "Belirtilmemiş",
    )
    card_text = _call_gemini(PROTECTION_CARD_SYSTEM, prompt)

    return {
        "card_text": card_text,
        "attack_method": case.get("attack_method"),
        "severity": case.get("severity_score"),
    }
