"""Regression cases found by tracing real inputs through legacy modules."""
from unittest.mock import MagicMock

import pytest


def test_malformed_sms_url_is_an_indicator_not_a_crash():
    from modules.sms_guard.service import _analyze_sms
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
    report = _analyze_sms('Mesajınız: https://[invalid', None, db)
    assert report.urls[0].is_suspicious
    assert 'geçersiz' in report.urls[0].reason.lower()


def test_url_checker_accepts_modern_tld_and_uses_real_hostname():
    from modules.ai_analyzer.url_checker import URLSecurityChecker
    checker = URLSecurityChecker()
    assert checker._is_valid_url('https://example.technology')
    assert checker.check_url('https://google.com')['risk_score'] == 0
    assert checker.check_url('https://apple.com')['risk_score'] == 0
    assert checker.check_url('https://spring.example')['risk_score'] == 0
    assert checker.check_url('https://google.gov.evil.example')['risk_score'] >= 40
    assert checker.check_url('https://google.com:443')['risk_score'] == 0


def redirect_pool(monkeypatch, location):
    import socket

    import urllib3
    calls = []
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('93.184.216.34', 443))])
    class Response:
        def __init__(self, first):
            self.status = 302 if first else 200
            self.headers = {'Location': location} if first else {}
        def stream(self, *args, **kwargs):
            yield b'ok'
        def close(self):
            pass
    class Pool:
        def __init__(self, *args, **kwargs):
            pass
        def urlopen(self, method, path, **kwargs):
            calls.append({'method': method, **kwargs})
            return Response(len(calls) == 1)
        def close(self):
            pass
    monkeypatch.setattr(urllib3, 'HTTPSConnectionPool', Pool)
    monkeypatch.setattr(urllib3, 'HTTPConnectionPool', Pool)
    return calls


def test_cross_origin_redirect_does_not_forward_custom_secrets(monkeypatch):
    from app.outbound import safe_request
    calls = redirect_pool(monkeypatch, 'https://other.example/')
    safe_request('GET', 'https://source.example', headers={'X-API-Key': 'secret', 'Referer': 'private', 'Authorization': 'secret', 'User-Agent': 'scanner'})
    assert len(calls) == 2
    assert calls[1]['headers'] == {'Host': 'other.example', 'User-Agent': 'scanner'}


@pytest.mark.parametrize('method,body,location', [('POST', b'private', 'https://other.example/'), ('GET', None, 'http://source.example/')])
def test_redirect_rejects_body_leaks_and_tls_downgrades(monkeypatch, method, body, location):
    from app.outbound import UnsafeTarget, safe_request
    calls = redirect_pool(monkeypatch, location)
    with pytest.raises(UnsafeTarget):
        safe_request(method, 'https://source.example/', data=body)
    assert len(calls) == 1


@pytest.mark.parametrize('url', ['https://127.0.0.1', 'https://[::1]', 'https://169.254.169.254', 'https://10.0.0.2'])
def test_advanced_certificate_check_never_connects_to_private_network(monkeypatch, url):
    from modules.ai_analyzer.advanced_phishing_detector import AdvancedPhishingDetector
    calls = []
    def connect(*args, **kwargs):
        calls.append(args)
        raise OSError('No real networking in regression test')
    monkeypatch.setattr('socket.create_connection', connect)
    assert AdvancedPhishingDetector()._check_ssl(url) == 0.5
    assert calls == []


def test_advanced_certificate_check_pins_resolved_ip(monkeypatch):
    from modules.ai_analyzer.advanced_phishing_detector import AdvancedPhishingDetector
    monkeypatch.setattr('socket.getaddrinfo', lambda *a, **k: [(2, 1, 6, '', ('93.184.216.34', 443))])
    calls = []
    def connect(target, **kwargs):
        calls.append(target)
        raise OSError('No real networking in regression test')
    monkeypatch.setattr('socket.create_connection', connect)
    AdvancedPhishingDetector()._check_ssl('https://public.example:443/path')
    assert calls == [('93.184.216.34', 443)]


def test_advanced_brand_matching_uses_domain_boundaries():
    from modules.ai_analyzer.advanced_phishing_detector import AdvancedPhishingDetector
    detector = AdvancedPhishingDetector()
    assert detector._check_suspicious_domain('https://google.com.evil.example') >= .4
    assert detector._check_suspicious_domain('https://google.com:443') == 0
    assert detector._check_suspicious_domain('https://www.google.com') == 0
