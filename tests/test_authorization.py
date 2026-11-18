"""One auth model: API key or session cookie -> APIKey.role drives every permission."""
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.auth import generate_api_key, hash_secret
from app.database import SessionLocal
from app.main import app
from app.models import APIKey, RecoveryToken, User, UserRole, UserSession

ADMIN_ONLY = [
    ('post', '/api/v2/phishing/fetch-all', None),
    ('post', '/api/v2/phishing/update-db', None),
    ('post', '/api/v2/phishing/add-site', {'url': 'https://x.example', 'target': 'x', 'status': 'online'}),
    ('get', '/api/v2/admin/users', None),
    ('get', '/api/v2/system/operations', None),
]


def make_user(role: UserRole) -> tuple[int, str]:
    raw, key_hash, prefix = generate_api_key()
    with SessionLocal() as db:
        user = User(email=f'{role.value}-{prefix}@example.com', role=role)
        db.add(user)
        db.flush()
        db.add(APIKey(user_id=user.id, key_hash=key_hash, key_prefix=prefix, role=role, rate_limit_tier=role.value))
        db.commit()
        return user.id, raw


@pytest.fixture
def client():
    return TestClient(app)


@pytest.mark.parametrize('method, path, body', ADMIN_ONLY)
def test_admin_endpoints_require_authentication(client, method, path, body):
    assert getattr(client, method)(path, **({'json': body} if body else {})).status_code == 401


@pytest.mark.parametrize('method, path, body', ADMIN_ONLY)
@pytest.mark.parametrize('role', [UserRole.free, UserRole.premium, UserRole.corporate])
def test_admin_endpoints_reject_non_admin_roles(client, method, path, body, role):
    _, key = make_user(role)
    response = getattr(client, method)(path, headers={'X-API-Key': key}, **({'json': body} if body else {}))
    assert response.status_code == 403


def test_admin_role_is_accepted(client):
    _, key = make_user(UserRole.admin)
    assert client.post('/api/v2/phishing/update-db', headers={'X-API-Key': key}).status_code == 200


def test_admin_cannot_remove_own_admin_role(client):
    user_id, key = make_user(UserRole.admin)
    response = client.patch(f'/api/v2/admin/users/{user_id}', json={'role': 'free'}, headers={'X-API-Key': key})
    assert response.status_code == 409


def test_admin_can_change_other_users_role_and_keys_follow(client):
    _, admin_key = make_user(UserRole.admin)
    user_id, _ = make_user(UserRole.free)
    response = client.patch(f'/api/v2/admin/users/{user_id}', json={'role': 'premium'}, headers={'X-API-Key': admin_key})
    assert response.status_code == 200 and response.json()['new_role'] == 'premium'
    with SessionLocal() as db:
        assert {k.role for k in db.query(APIKey).filter_by(user_id=user_id)} == {UserRole.premium}


def test_purge_expired_credentials_keeps_live_ones():
    from app.workflow_tasks import purge_expired_credentials
    user_id, _ = make_user(UserRole.free)
    now = datetime.now(UTC)
    with SessionLocal() as db:
        key_id = db.query(APIKey.id).filter_by(user_id=user_id).scalar()
        db.add_all([
            UserSession(token_hash=hash_secret('old'), api_key_id=key_id, expires_at=now - timedelta(hours=1)),
            UserSession(token_hash=hash_secret('live'), api_key_id=key_id, expires_at=now + timedelta(hours=1)),
            RecoveryToken(user_id=user_id, token_hash=hash_secret('used'), expires_at=now + timedelta(minutes=5), used_at=now),
            RecoveryToken(user_id=user_id, token_hash=hash_secret('pending'), expires_at=now + timedelta(minutes=5)),
        ])
        db.commit()
    purge_expired_credentials.run()
    with SessionLocal() as db:
        assert db.query(UserSession).filter_by(token_hash=hash_secret('old')).first() is None
        assert db.query(UserSession).filter_by(token_hash=hash_secret('live')).first() is not None
        assert db.query(RecoveryToken).filter_by(token_hash=hash_secret('used')).first() is None
        assert db.query(RecoveryToken).filter_by(token_hash=hash_secret('pending')).first() is not None
