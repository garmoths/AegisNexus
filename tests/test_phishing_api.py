"""Phishing detector API: database endpoints, validation and admin-only maintenance."""
import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import PhishingURL, UserRole
from tests.test_authorization import make_user


@pytest.fixture
def client():
    with SessionLocal() as db:
        db.query(PhishingURL).delete()
        db.add_all([PhishingURL(phish_id=f'p{i}', url=f'https://bad{i}.example/login', domain_norm=f'bad{i}.example',
                                target='Bank', status='online' if i % 2 else 'offline') for i in range(5)])
        db.add(PhishingURL(phish_id='w', url='https://wild_card.example/', domain_norm='wild_card.example', status='online'))
        db.commit()
    return TestClient(app)


def test_latest_paged_orders_active_first_and_paginates(client):
    body = client.get('/api/v2/phishing/latest-paged', params={'limit': 2, 'page': 1}).json()
    assert body['total'] == 6 and body['total_pages'] == 3 and len(body['data']) == 2
    assert all(row['status'] == 'online' for row in body['data'])


def test_search_serializes_rows_and_reports_has_more(client):
    body = client.get('/api/v2/phishing/search', params={'url': 'bad', 'limit': 3}).json()
    assert body['status'] == 'DANGER' and len(body['data']) == 3 and body['has_more'] is True
    assert set(body['data'][0]) == {'id', 'url', 'domain', 'target', 'status', 'submission_time', 'phish_id'}


def test_search_treats_like_wildcards_literally(client):
    assert client.get('/api/v2/phishing/search', params={'url': '%'}).json()['status'] == 'SAFE'
    assert client.get('/api/v2/phishing/search', params={'url': 'wild_card'}).json()['total'] == 1


@pytest.mark.parametrize('params', [{'limit': 0}, {'limit': 1000}, {'page': 0}])
def test_pagination_bounds_are_validated(client, params):
    assert client.get('/api/v2/phishing/latest-paged', params=params).status_code == 422


def test_unsafe_scan_target_is_rejected_with_error_code(client):
    response = client.post('/api/v2/phishing/check-url', json={'url': 'http://127.0.0.1/admin'})
    assert response.status_code == 422 and response.json()['error']['code'] == 'unsafe_target'


def test_invalid_job_id_is_rejected(client):
    assert client.get('/api/v2/phishing/result/not-a-uuid').json()['error']['code'] == 'invalid_job_id'


def test_add_site_rejects_duplicates(client):
    _, key = make_user(UserRole.admin)
    first = client.post('/api/v2/phishing/add-site', json={'url': 'https://new.example/x', 'target': 'Bank'}, headers={'X-API-Key': key})
    again = client.post('/api/v2/phishing/add-site', json={'url': 'https://new.example/x', 'target': 'Bank'}, headers={'X-API-Key': key})
    assert first.status_code == 201 and first.json()['id'].startswith('PHISH-')
    assert again.status_code == 409


def test_cleanup_is_not_public(client):
    """Regression: POST /cleanup deleted records without any authentication."""
    assert client.post('/api/v2/phishing/cleanup', params={'dry_run': True}).status_code == 401
