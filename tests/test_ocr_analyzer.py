"""
B3 — EasyOCR Metin Okuma — Unit Tests
========================================
Gerçek EasyOCR modeli gerekmez; `get_ocr_reader()` mock'lanır.

pytest tests/test_ocr_analyzer.py -v
"""
from __future__ import annotations

import base64
import io
from unittest.mock import MagicMock, patch

import pytest


# ── Test helpers ─────────────────────────────────────────────────────────────

def _make_png_bytes(color=(255, 255, 255)) -> bytes:
    from PIL import Image
    img = Image.new("RGB", (100, 100), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _mock_reader(text_lines: list[str]):
    """EasyOCR reader mock'u — readtext() verilen satırları döndürür."""
    mock = MagicMock()
    mock.readtext.return_value = text_lines
    return mock


# ── 1. get_ocr_reader singleton ───────────────────────────────────────────────

class TestGetOcrReader:
    def test_singleton_returns_same_instance(self, monkeypatch):
        import modules.phishing_detector.visual_analyzer as va
        fake_reader = MagicMock()
        monkeypatch.setattr(va, "_ocr_reader", None)
        with patch("easyocr.Reader", return_value=fake_reader):
            r1 = va.get_ocr_reader()
            r2 = va.get_ocr_reader()
        assert r1 is r2

    def test_singleton_reuses_existing(self, monkeypatch):
        import modules.phishing_detector.visual_analyzer as va
        existing = MagicMock()
        monkeypatch.setattr(va, "_ocr_reader", existing)
        result = va.get_ocr_reader()
        assert result is existing


# ── 2. analyze_with_ocr temel mantık ─────────────────────────────────────────

class TestAnalyzeWithOcr:
    def _patch_reader(self, monkeypatch, text_lines: list[str]):
        import modules.phishing_detector.visual_analyzer as va
        mock = _mock_reader(text_lines)
        monkeypatch.setattr(va, "_ocr_reader", mock)
        return mock

    def test_empty_bytes_returns_zero_penalty(self, monkeypatch):
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, [])
        result = va.analyze_with_ocr(b"", domain="x.com")
        assert result["penalty"] == 0
        assert result["definitive"] is False

    def test_brand_on_fake_domain_gets_penalty(self, monkeypatch):
        """OCR 'ziraat' görüyor, domain sahte → penalty=55."""
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, ["Ziraat Bankası Giriş Sayfası"])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="evil-ziraat.tk")
        # Domain 'ziraat' içeriyor ama BRAND_DOMAINS'da yok → _brand_matches_url False
        # Bu URL için: brand_lower="ziraat", url="https://evil-ziraat.tk"
        # "ziraat" in url → True, official_domains = ["ziraatbank.com.tr", "ziraat.com.tr"]
        # none of those in url → False → ceza verilir
        assert result["penalty"] >= 55
        assert "ziraat" in result["brands_found"]

    def test_brand_on_official_domain_no_penalty(self, monkeypatch):
        """OCR 'ziraat' görüyor, domain resmi → penalty=0."""
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, ["Ziraat Bankası Online Şubesi"])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="ziraatbank.com.tr")
        assert result["penalty"] == 0
        assert result["brands_found"] == []

    def test_credential_keyword_adds_extra_penalty(self, monkeypatch):
        """Marka + şifre → 55 + extra."""
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, ["Akbank giriş şifre kart no cvv"])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="attacker.tk")
        assert result["penalty"] > 55
        assert len(result["credentials_found"]) >= 1

    def test_credential_only_no_brand_penalty(self, monkeypatch):
        """Sadece credential keyword → marka yoksa 0 penalty (brand gerekli)."""
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, ["lütfen şifrenizi giriniz"])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="unknown.com")
        # Sadece credential, marka yok → penalty=0 (brand check tetikleyici)
        assert result["penalty"] == 0

    def test_max_penalty_cap(self, monkeypatch):
        """Penalty 70'i geçmemeli."""
        import modules.phishing_detector.visual_analyzer as va
        many_creds = ["şifre pin cvv kart iban tc kimlik username password otp"]
        self._patch_reader(monkeypatch, many_creds + ["ziraat paypal google"])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="evil.tk")
        assert result["penalty"] <= 70

    def test_definitive_true_when_high_penalty(self, monkeypatch):
        """penalty >= 65 → definitive=True."""
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, ["Ziraat Bankası şifre kart numarası cvv"])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="phishing.ru")
        assert result["definitive"] is True
        assert result["penalty"] >= 65

    def test_result_always_has_required_keys(self, monkeypatch):
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, [])
        result = va.analyze_with_ocr(_make_png_bytes(), domain="x.com")
        for key in ("penalty", "definitive", "ocr_text_sample",
                    "brands_found", "credentials_found", "detail"):
            assert key in result, f"Eksik anahtar: {key}"

    def test_invalid_png_no_exception(self, monkeypatch):
        """Geçersiz PNG → exception fırlatmamalı."""
        import modules.phishing_detector.visual_analyzer as va
        self._patch_reader(monkeypatch, [])
        result = va.analyze_with_ocr(b"NOT A PNG", domain="x.com")
        assert result["penalty"] == 0

    def test_ocr_text_sample_truncated(self, monkeypatch):
        """ocr_text_sample max 300 karakter olmalı."""
        import modules.phishing_detector.visual_analyzer as va
        long_text = ["a" * 500]
        self._patch_reader(monkeypatch, long_text)
        result = va.analyze_with_ocr(_make_png_bytes(), domain="x.com")
        assert len(result["ocr_text_sample"]) <= 300

    def test_import_error_graceful(self, monkeypatch):
        """easyocr yoksa penalty=0, exception yok."""
        import modules.phishing_detector.visual_analyzer as va
        monkeypatch.setattr(va, "_ocr_reader", None)
        with patch.dict("sys.modules", {"easyocr": None}):
            result = va.analyze_with_ocr(_make_png_bytes(), domain="x.com")
        assert result["penalty"] == 0


# ── 3. screenshot_analyzer OCR entegrasyonu ──────────────────────────────────

class TestScreenshotAnalyzerOcrIntegration:
    def _setup(self, monkeypatch, ocr_text_lines: list[str]):
        """screenshot_analyzer için gerekli mock'ları kur."""
        import modules.phishing_detector.screenshot_analyzer as sa
        import modules.phishing_detector.visual_analyzer as va

        png = _make_png_bytes()
        b64 = base64.b64encode(png).decode()
        monkeypatch.setattr(sa, "_capture_screenshot_base64",
                            lambda url, text: (b64, "page text"))

        mock_reader = _mock_reader(ocr_text_lines)
        monkeypatch.setattr(va, "_ocr_reader", mock_reader)
        # pHash DB boş bırak → pHash bypass yok
        monkeypatch.setattr(va, "_LOGO_DB", {})

        return sa, va

    def test_ocr_definitive_skips_gemini(self, monkeypatch):
        """OCR kesin sonuç → Gemini çağrılmaz."""
        sa, va = self._setup(monkeypatch,
                             ["Ziraat Bankası giriş şifre kart numarası"])
        monkeypatch.setattr(sa, "redis_get_gemini_count", lambda: 0)
        monkeypatch.setattr(sa, "redis_incr_gemini_counter", lambda: 1)

        gemini_calls = []
        monkeypatch.setattr(sa, "_call_gemini",
                            lambda **k: gemini_calls.append(1) or {})

        result = sa.analyze("https://evil-ziraat.ru")
        assert gemini_calls == [], "Gemini çağrılmamalıydı!"
        assert result.get("gemini_skipped") is True

    def test_no_ocr_match_falls_through_to_gemini(self, monkeypatch):
        """OCR eşleşme yok → Gemini normal çalışır."""
        sa, va = self._setup(monkeypatch, ["hello world benign text"])
        monkeypatch.setattr(sa, "redis_get_gemini_count", lambda: 0)
        monkeypatch.setattr(sa, "redis_incr_gemini_counter", lambda: 1)
        monkeypatch.setattr(sa, "_should_skip_gemini", lambda p: (False, ""))

        gemini_calls = []
        monkeypatch.setattr(sa, "_call_gemini",
                            lambda **k: gemini_calls.append(1) or
                            {"risk_score": 10, "risk_level": "LOW", "verdict": "safe",
                             "screenshot_analysis": "", "recommendation": "",
                             "threat_indicators": []})

        sa.analyze("https://benign-site.com")
        assert len(gemini_calls) == 1

    def test_ocr_penalty_accumulates_into_pre_penalty(self, monkeypatch):
        """OCR partial penalty → pre_penalty yükselir, _should_skip_gemini etkilenir."""
        sa, va = self._setup(monkeypatch, ["akbank giriş sayfası"])
        monkeypatch.setattr(sa, "redis_get_gemini_count", lambda: 0)
        monkeypatch.setattr(sa, "redis_incr_gemini_counter", lambda: 1)

        skip_calls = []
        def _fake_skip(pre_penalty):
            skip_calls.append(pre_penalty)
            return (False, "")

        monkeypatch.setattr(sa, "_should_skip_gemini", _fake_skip)
        monkeypatch.setattr(sa, "_call_gemini",
                            lambda **k: {"risk_score": 10, "risk_level": "LOW",
                                         "verdict": "ok", "screenshot_analysis": "",
                                         "recommendation": "", "threat_indicators": []})

        sa.analyze("https://attacker.tk")
        # pre_penalty'e OCR penalty eklenmeli
        assert len(skip_calls) >= 1
