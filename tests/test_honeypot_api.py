"""Honeypot / IOC API: contracts, statistics and the decoy page."""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import IndicatorOfCompromise, PhishingURL


@pytest.fixture
def client():
    with SessionLocal() as db:
        db.query(IndicatorOfCompromise).delete()
        db.query(PhishingURL).delete()
        db.commit()
    return TestClient(app)


def add_ioc(db, value, risk, *, days_ago=0, threat='phishing', source='abuse_urlhaus'):
    created = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=days_ago)
    db.add(IndicatorOfCompromise(ioc_type='domain', ioc_value=value, ioc_value_hash=value, source=source,
                                 threat_type=threat, risk_score=risk, confidence=0.9, created_at=created,
                                 first_seen=created, last_seen=created))


def test_ioc_stats_counts_today_and_week(client):
    """Regression: CAST(x AS DATE) on SQLite returned the year, so these were always 0."""
    with SessionLocal() as db:
        add_ioc(db, 'a.example', 90)
        add_ioc(db, 'b.example', 30)
        add_ioc(db, 'c.example', 55, days_ago=3, threat='malware', source='abuseipdb')
        db.commit()
    body = client.get('/api/v2/honeypot/ioc/stats').json()
    assert body['status'] == 'success'
    assert body['stats']['total_iocs'] == 3 and body['today_added'] == 2
    assert len(body['weekly_growth']) == 8 and sum(d['count'] for d in body['weekly_growth']) == 3
    assert body['stats']['high_risk_count'] == 1 and body['stats']['low_risk_count'] == 1
    assert {t['type'] for t in body['top_threats']} == {'phishing', 'malware'}


def test_phishing_stats_counts_today(client):
    with SessionLocal() as db:
        db.add(PhishingURL(phish_id='p1', url='https://evil.example/login', domain_norm='evil.example', target='bank', status='online'))
        db.commit()
    body = client.get('/api/v2/honeypot/phishing/stats').json()
    assert body['total_urls'] == 1 and body['daily_new'] == 1
    assert body['top_domains'] == [{'domain': 'evil.example', 'count': 1}]


def test_risk_band_and_validation(client):
    with SessionLocal() as db:
        add_ioc(db, 'crit.example', 99)
        add_ioc(db, 'low.example', 10)
        db.commit()
    body = client.get('/api/v2/honeypot/ioc/by-risk-score', params={'level': 'critical'}).json()
    assert body['score_range'] == {'min': 95, 'max': 100} and [i['value'] for i in body['iocs']] == ['crit.example']
    assert client.get('/api/v2/honeypot/ioc/by-risk-score', params={'level': 'extreme'}).status_code == 422
    assert client.get('/api/v2/honeypot/ioc/by-risk-score', params={'level': 'low', 'limit': 0}).status_code == 422


def test_search_escapes_like_wildcards(client):
    with SessionLocal() as db:
        add_ioc(db, 'shop.example', 50)
        add_ioc(db, 'a_b.example', 50)
        db.commit()
    assert client.get('/api/v2/honeypot/ioc/search', params={'q': '%%'}).json()['found'] == 0
    assert [r['value'] for r in client.get('/api/v2/honeypot/ioc/search', params={'q': 'a_b'}).json()['results']] == ['a_b.example']
    assert client.get('/api/v2/honeypot/ioc/search', params={'q': 'x'}).status_code == 422


def test_decoy_page_embeds_session_and_uses_no_real_brand(client):
    html = client.get('/api/v2/honeypot/decoy').text
    assert '__SESSION_ID__' not in html and "const sessionId = '" in html
    assert 'Ziraat' not in html
    assert 'customer_id: customerId' not in html  # typed identity values are never sent


def test_persist_external_iocs_upserts_duplicates():
    from modules.honeypot.ioc_collector import IOCCollectorEngine, IOCRecord
    from modules.honeypot.service import persist_external_iocs
    now = datetime.now(UTC).replace(tzinfo=None)
    record = IOCRecord(ioc_type='domain', ioc_value='dup.example', source='abuse_urlhaus', threat_type='phishing',
                       risk_score=40, confidence=0.5, first_seen=now, last_seen=now)
    engine = IOCCollectorEngine()
    with SessionLocal() as db:
        db.query(IndicatorOfCompromise).delete()
        assert persist_external_iocs(db, engine, [record]) == 1
        record.risk_score = 80
        assert persist_external_iocs(db, engine, [record]) == 0
        row = db.query(IndicatorOfCompromise).filter_by(ioc_value='dup.example').one()
        assert row.risk_score == 80 and row.detection_count == 2
