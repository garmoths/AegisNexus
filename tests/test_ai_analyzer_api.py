"""AI analyzer API: verdict reconciliation and private URL history."""
import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import URLAnalizHistory, UserRole
from tests.test_authorization import make_user


@pytest.fixture
def client():
    return TestClient(app)


def fake_detector(verdict, score=0.95, confidence=0.9):
    def detect(text, url, email_signals=None):
        return {'verdict': verdict, 'score': score, 'confidence': confidence, 'reason': 'test', 'breakdown': {},
                'hard_override': False, 'matched_categories': ['urgency'], 'evidence': ['e1']}
    return detect


@pytest.mark.parametrize('verdict, risk, status', [('PHİSHİNG', 'critical', 'TEHLİKELİ'), ('TEMİZ', 'low', 'GÜVENLİ')])
def test_analyze_reconciles_legacy_report_with_hybrid_verdict(client, monkeypatch, verdict, risk, status):
    import modules.ai_analyzer.service as service
    monkeypatch.setattr(service, 'detect_phishing', fake_detector(verdict))
    body = client.post('/api/v2/ai-analyzer/analyze', json={'message': 'Hesabınız askıya alındı, hemen tıklayın'}).json()
    assessment = body['security_assessment']
    assert assessment['risk_level'] == risk and assessment['safety_status'] == status
    assert assessment['is_phishing'] is (verdict == 'PHİSHİNG')
    assert body['summary'].startswith(f'[{verdict}]') and body['matched_categories'] == ['urgency']


def test_analyze_falls_back_to_legacy_engine(client, monkeypatch):
    import modules.ai_analyzer.service as service

    def broken(*_a, **_k):
        raise RuntimeError('provider down')
    monkeypatch.setattr(service, 'detect_phishing', broken)
    response = client.post('/api/v2/ai-analyzer/analyze', json={'message': 'Tebrikler, ödül kazandınız!'})
    assert response.status_code == 200 and 'security_assessment' in response.json()


def test_url_check_is_saved_to_history_only_for_authenticated_callers(client):
    user_id, key = make_user(UserRole.free)
    client.post('/api/v2/ai-analyzer/check-url', json={'url': 'https://anon.example/login'})
    client.post('/api/v2/ai-analyzer/check-url', json={'url': 'https://mine.example/login'}, headers={'X-API-Key': key})
    with SessionLocal() as db:
        assert db.query(URLAnalizHistory).filter_by(url='https://anon.example/login').count() == 0
    history = client.get('/api/v2/ai-analyzer/history', headers={'X-API-Key': key}).json()
    assert [row['url'] for row in history['data']] == ['https://mine.example/login']
    detail = client.get(f"/api/v2/ai-analyzer/history/{history['data'][0]['id']}", headers={'X-API-Key': key}).json()
    assert detail['domain'] == 'mine.example' and detail['url_checks'] is not None


def test_history_detail_of_missing_row_is_404(client):
    _, key = make_user(UserRole.free)
    response = client.get('/api/v2/ai-analyzer/history/999999', headers={'X-API-Key': key})
    assert response.status_code == 404 and response.json()['error']['code'] == 'not_found'
