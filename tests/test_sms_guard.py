"""
Tests for SMS Guard smishing/phishing analysis module.
"""
from unittest.mock import MagicMock

import pytest


def _mock_db_no_hit():
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
    return db


def _analyze(text, sender=None, db=None):
    from modules.sms_guard.router import _analyze_sms
    return _analyze_sms(text, sender, db or _mock_db_no_hit())


# ── Clean SMS ────────────────────────────────────────────────────────────────

def test_clean_sms_low_risk():
    r = _analyze("Merhaba, yarın toplantı saat 10'da.")
    assert r.risk_score < 20
    assert r.category == "temiz"
    assert r.action == "ALLOW"


def test_clean_sms_no_url():
    r = _analyze("Siparişiniz hazırlandı. İyi günler.")
    assert r.action in ("ALLOW", "MONITOR")


# ── Smishing: Short URL ───────────────────────────────────────────────────────

def test_short_url_detected():
    r = _analyze("Paketiniz bekliyor: https://bit.ly/3xYZ")
    assert r.risk_score >= 30
    urls = [u for u in r.urls if u.is_suspicious]
    assert len(urls) >= 1


def test_short_url_tinyurl():
    r = _analyze("Kargonuz teslim edilecek: http://tinyurl.com/abc123")
    assert any(u.is_suspicious for u in r.urls)


# ── Smishing: IP-based URL ────────────────────────────────────────────────────

def test_ip_url_detected():
    r = _analyze("Güvenlik doğrulaması: http://192.168.1.1/verify")
    assert any(u.is_suspicious for u in r.urls)
    assert r.risk_score >= 25


# ── Turkish phishing keywords ─────────────────────────────────────────────────

def test_phishing_keywords_trigger():
    r = _analyze("Hesabınız askıya alındı. Paketiniz teslim edilmedi. Acil işlem gerekli.")
    assert r.risk_score >= 25
    assert len(r.indicators) >= 1


def test_urgency_words():
    r = _analyze("Acil! Hemen tıklayın. Son gün!")
    assert r.risk_score >= 15


# ── Sender spoofing ───────────────────────────────────────────────────────────

def test_bank_sender_spoofing():
    r = _analyze("Şüpheli giriş tespit edildi.", sender="GARANTI-BANK")
    assert r.risk_score >= 20
    assert any("kurum" in ind.lower() or "taklid" in ind.lower() for ind in r.indicators)


def test_ptt_sender_spoofing():
    r = _analyze("Paketiniz şubemizde bekliyor.", sender="PTT")
    assert r.risk_score >= 20


# ── High risk → BLOCK ────────────────────────────────────────────────────────

def test_high_risk_blocked():
    sms = (
        "Hesabınız askıya alındı! Acil işlem gerekli. Paketiniz teslim edilemedi. "
        "Şüpheli giriş tespit edildi. Doğrulama: http://bit.ly/xyz123 "
        "Kredi kartı bilgilerini hemen girin. Son tarih bugün. 24 saat içinde işlem yapın."
    )
    r = _analyze(sms, sender="GARANTI-BANK")
    assert r.risk_score >= 75
    assert r.action == "BLOCK"
    assert r.category == "smishing"


# ── IOC DB hit ────────────────────────────────────────────────────────────────

def test_ioc_db_hit_increases_risk():
    db = MagicMock()
    ioc_mock = MagicMock()
    ioc_mock.risk_score = 90
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = ioc_mock

    r = _analyze("Tıklayın: http://evil-known-ioc.com/phish", db=db)
    assert any(u.in_ioc_db for u in r.urls)
    assert r.risk_score >= 40


# ── Response schema ───────────────────────────────────────────────────────────

def test_response_has_required_fields():
    r = _analyze("Test mesajı")
    assert hasattr(r, "risk_score")
    assert hasattr(r, "category")
    assert hasattr(r, "confidence")
    assert hasattr(r, "action")
    assert hasattr(r, "explanation")
    assert hasattr(r, "analyzed_at")
    assert 0 <= r.risk_score <= 100
    assert 0.0 <= r.confidence <= 1.0
    assert r.action in ("ALLOW", "MONITOR", "WARN", "BLOCK")


def test_confidence_bounded():
    r = _analyze("A" * 1500)
    assert r.confidence <= 0.99
