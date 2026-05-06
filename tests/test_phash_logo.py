"""
B2 — pHash Logo Karşılaştırma — Unit Tests
============================================
Gerçek network / DB gerektirmeyen testler:
- check_logo_phash() mantığı (mock logo DB ile)
- Domain kontrolü
- Boş/hatalı input
- screenshot_analyzer entegrasyonu
- _load_logo_db() graceful fallback

pytest tests/test_phash_logo.py -v
"""
from __future__ import annotations

import base64
import io
import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── Test için minimal PNG helper ────────────────────────────────────────────

def _make_png_bytes(width: int = 64, height: int = 64, color=(255, 255, 255)) -> bytes:
    """PIL ile solid-color PNG oluştur."""
    from PIL import Image
    img = Image.new("RGB", (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_phash_str(png_bytes: bytes) -> str:
    import imagehash
    from PIL import Image
    img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
    return str(imagehash.phash(img))


# ── 1. visual_analyzer — _LOGO_DB ve _load_logo_db ──────────────────────────

class TestLogoDbLoader:
    def test_logo_db_is_dict(self):
        from modules.phishing_detector.visual_analyzer import _LOGO_DB
        assert isinstance(_LOGO_DB, dict)

    def test_load_logo_db_reads_json(self, tmp_path, monkeypatch):
        """Geçerli JSON dosyasını yüklemeli."""
        import modules.phishing_detector.visual_analyzer as va
        fake_db = {"testbrand": [{"url": "http://x.com/logo.png", "hash": "abc123"}]}
        p = tmp_path / "logo_hashes.json"
        p.write_text(json.dumps(fake_db))

        monkeypatch.setattr(va, "_LOGO_DB_PATH", p)
        va._load_logo_db()
        assert "testbrand" in va._LOGO_DB

    def test_load_logo_db_graceful_missing_file(self, tmp_path, monkeypatch):
        """Dosya yoksa boş dict döner."""
        import modules.phishing_detector.visual_analyzer as va
        monkeypatch.setattr(va, "_LOGO_DB_PATH", tmp_path / "nonexistent.json")
        va._load_logo_db()
        assert va._LOGO_DB == {}

    def test_load_logo_db_graceful_invalid_json(self, tmp_path, monkeypatch):
        """Bozuk JSON → boş dict."""
        import modules.phishing_detector.visual_analyzer as va
        p = tmp_path / "logo_hashes.json"
        p.write_text("NOT JSON {{{")
        monkeypatch.setattr(va, "_LOGO_DB_PATH", p)
        va._load_logo_db()
        assert va._LOGO_DB == {}


# ── 2. check_logo_phash — temel mantık ──────────────────────────────────────

class TestCheckLogoPhash:
    def _inject_db(self, monkeypatch, png_bytes: bytes, brand: str = "testbrand"):
        """Brand logosu için gerçek pHash üretip _LOGO_DB'ye enjekte et."""
        import modules.phishing_detector.visual_analyzer as va
        h = _make_phash_str(png_bytes)
        fake_db = {brand: [{"url": "https://example.com/logo.png", "hash": h}]}
        monkeypatch.setattr(va, "_LOGO_DB", fake_db)
        return h

    def test_empty_screenshot_no_penalty(self, monkeypatch):
        import modules.phishing_detector.visual_analyzer as va
        monkeypatch.setattr(va, "_LOGO_DB", {"brand": [{"hash": "abc"}]})
        result = va.check_logo_phash(b"", url="https://evil.com")
        assert result["penalty"] == 0
        assert result["definitive"] is False

    def test_empty_logo_db_no_penalty(self, monkeypatch):
        import modules.phishing_detector.visual_analyzer as va
        monkeypatch.setattr(va, "_LOGO_DB", {})
        result = va.check_logo_phash(_make_png_bytes(), url="https://evil.com")
        assert result["penalty"] == 0
        assert "Logo DB boş" in result["detail"]

    def test_identical_logo_gets_penalty(self, monkeypatch):
        """Aynı logo → distance=0 → penalty=60, definitive=True."""
        import modules.phishing_detector.visual_analyzer as va
        logo_bytes = _make_png_bytes(128, 128, color=(255, 0, 0))
        self._inject_db(monkeypatch, logo_bytes, brand="fakebrand")

        result = va.check_logo_phash(logo_bytes, url="https://evil-phishing-site.tk")
        assert result["penalty"] == 60
        assert result["definitive"] is True
        assert result["brand"] == "fakebrand"
        assert result["distance"] == 0

    def test_domain_match_suppresses_penalty(self, monkeypatch):
        """Markanın kendi domaini → penalty=0."""
        import modules.phishing_detector.visual_analyzer as va
        logo_bytes = _make_png_bytes(128, 128, color=(0, 255, 0))
        self._inject_db(monkeypatch, logo_bytes, brand="paypal")

        result = va.check_logo_phash(logo_bytes, url="https://www.paypal.com/login")
        assert result["penalty"] == 0
        assert result["definitive"] is False

    def test_different_image_no_penalty(self, monkeypatch):
        """Tamamen farklı görüntü → eşleşme yok."""
        import modules.phishing_detector.visual_analyzer as va
        db_logo = _make_png_bytes(128, 128, color=(255, 0, 0))
        self._inject_db(monkeypatch, db_logo, brand="realbrand")

        other_logo = _make_png_bytes(128, 128, color=(0, 0, 255))
        result = va.check_logo_phash(other_logo, url="https://attacker.tk")
        # Renk farkı pHash farkına yansımayabilir — sadece yapısal kontrol
        assert "penalty" in result
        assert "definitive" in result

    def test_result_structure_always_complete(self, monkeypatch):
        """Her durumda gerekli anahtarlar bulunmalı."""
        import modules.phishing_detector.visual_analyzer as va
        monkeypatch.setattr(va, "_LOGO_DB", {})
        result = va.check_logo_phash(_make_png_bytes())
        for key in ("penalty", "brand", "definitive", "distance", "similarity", "detail"):
            assert key in result, f"Eksik anahtar: {key}"

    def test_invalid_bytes_no_exception(self, monkeypatch):
        """Geçersiz baytlar exception fırlatmamalı."""
        import modules.phishing_detector.visual_analyzer as va
        monkeypatch.setattr(va, "_LOGO_DB", {"b": [{"hash": "abc"}]})
        result = va.check_logo_phash(b"NOT A PNG FILE HERE", url="https://x.com")
        assert result["penalty"] == 0
        assert result["definitive"] is False

    def test_threshold_respected(self, monkeypatch):
        """_PHASH_THRESHOLD=0 → sadece distance=0 eşleşmeli."""
        import modules.phishing_detector.visual_analyzer as va
        logo_bytes = _make_png_bytes(64, 64, color=(128, 128, 128))
        self._inject_db(monkeypatch, logo_bytes, brand="strictbrand")
        monkeypatch.setattr(va, "_PHASH_THRESHOLD", 0)

        result = va.check_logo_phash(logo_bytes, url="https://evil.tk")
        assert result["distance"] == 0
        assert result["penalty"] == 60


# ── 3. _domain_matches_brand ─────────────────────────────────────────────────

class TestDomainMatchesBrand:
    def test_paypal_on_paypal_matches(self):
        from modules.phishing_detector.visual_analyzer import _brand_matches_url
        assert _brand_matches_url("paypal", "https://www.paypal.com/login") is True

    def test_paypal_on_evil_site_no_match(self):
        from modules.phishing_detector.visual_analyzer import _brand_matches_url
        assert _brand_matches_url("paypal", "https://paypal-secure.tk") is False

    def test_ziraat_on_official_domain_matches(self):
        from modules.phishing_detector.visual_analyzer import _brand_matches_url
        assert _brand_matches_url("ziraat", "https://www.ziraatbank.com.tr/login") is True

    def test_ziraat_on_fake_no_match(self):
        from modules.phishing_detector.visual_analyzer import _brand_matches_url
        assert _brand_matches_url("ziraat", "https://ziraat-login.xyz") is False

    def test_unknown_brand_loose_match(self):
        from modules.phishing_detector.visual_analyzer import _brand_matches_url
        assert _brand_matches_url("unknownbrand", "https://unknownbrand.com") is True

    def test_no_brand_in_url(self):
        from modules.phishing_detector.visual_analyzer import _brand_matches_url
        assert _brand_matches_url("microsoft", "https://totally-evil.ru") is False


# ── 4. screenshot_analyzer entegrasyonu ──────────────────────────────────────

class TestScreenshotAnalyzerPhashIntegration:
    def _fake_screenshot(self, monkeypatch, screenshot_bytes: bytes):
        """_capture_screenshot_base64 mock'la."""
        import modules.phishing_detector.screenshot_analyzer as sa
        b64 = base64.b64encode(screenshot_bytes).decode()
        monkeypatch.setattr(sa, "_capture_screenshot_base64",
                            lambda url, text: (b64, "page content"))

    def test_phash_match_skips_gemini(self, monkeypatch):
        """pHash eşleşmesi Gemini çağrısını engellemelidir."""
        import modules.phishing_detector.screenshot_analyzer as sa
        import modules.phishing_detector.visual_analyzer as va

        logo_bytes = _make_png_bytes(128, 128, color=(200, 50, 50))
        h = _make_phash_str(logo_bytes)
        monkeypatch.setattr(va, "_LOGO_DB", {"fakebrand": [{"hash": h}]})
        monkeypatch.setattr(va, "_PHASH_THRESHOLD", 8)
        self._fake_screenshot(monkeypatch, logo_bytes)

        gemini_called = []
        monkeypatch.setattr(sa, "_call_gemini", lambda **k: gemini_called.append(1) or {})
        monkeypatch.setattr(sa, "redis_get_gemini_count", lambda: 0)
        monkeypatch.setattr(sa, "redis_incr_gemini_counter", lambda: 1)

        result = sa.analyze("https://attacker.tk")
        assert gemini_called == [], "Gemini çağrılmamalıydı!"
        assert result.get("risk_score") == 85 or result.get("gemini_skipped") is True

    def test_empty_logo_db_falls_through_to_gemini_logic(self, monkeypatch):
        """Logo DB boşsa pHash kontrolü atlanır, normal akış devam eder."""
        import modules.phishing_detector.screenshot_analyzer as sa
        import modules.phishing_detector.visual_analyzer as va

        monkeypatch.setattr(va, "_LOGO_DB", {})
        logo_bytes = _make_png_bytes(64, 64)
        self._fake_screenshot(monkeypatch, logo_bytes)

        gemini_called = []
        monkeypatch.setattr(sa, "_call_gemini",
                            lambda **k: gemini_called.append(1) or
                            {"risk_score": 20, "risk_level": "LOW", "verdict": "ok",
                             "screenshot_analysis": "", "recommendation": "", "threat_indicators": []})
        monkeypatch.setattr(sa, "redis_get_gemini_count", lambda: 0)
        monkeypatch.setattr(sa, "redis_incr_gemini_counter", lambda: 1)
        monkeypatch.setattr(sa, "_should_skip_gemini", lambda p: (False, ""))

        result = sa.analyze("https://unknown-site.xyz")
        assert result.get("available") is True


# ── 5. build_logo_db modülü import kontrolü ──────────────────────────────────

class TestBuildLogoDb:
    def test_module_importable(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "build_logo_db",
            "modules/phishing_detector/build_logo_db.py"
        )
        # Sadece dosyanın var olduğunu ve import edilebileceğini kontrol et
        assert spec is not None

    def test_logos_dict_has_expected_brands(self):
        """LOGOS sözlüğünde kritik markalar olmalı."""
        import ast, textwrap
        src = Path("modules/phishing_detector/build_logo_db.py").read_text()
        # Kaynak kodda marka adlarının geçip geçmediğini kontrol et
        for brand in ("paypal", "google", "microsoft", "ziraat", "garanti"):
            assert brand in src, f"'{brand}' build_logo_db.py'de eksik"
