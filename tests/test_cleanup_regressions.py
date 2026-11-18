"""Security and cross-process storage checks, isolated from external services."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.database import Base, get_db
from app.models import APIKey, User
from app.routers.auth import router


@pytest.fixture
def auth_client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)

    def override_db():
        with sessions() as db:
            yield db

    app = FastAPI()
    app.include_router(router, prefix="/auth")
    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client, sessions
    engine.dispose()


@pytest.mark.parametrize("role", ["admin", "corporate", "premium"])
def test_public_registration_rejects_privileged_roles(auth_client, role):
    client, sessions = auth_client
    response = client.post("/auth/register", json={"email": "test@example.com", "role": role})
    assert response.status_code == 422
    with sessions() as db:
        assert db.query(User).count() == 0
        assert db.query(APIKey).count() == 0


@pytest.mark.parametrize("extra", [{}, {"role": "free"}])
def test_public_registration_creates_only_free_accounts(auth_client, extra):
    client, sessions = auth_client
    response = client.post("/auth/register", json={"email": "test@example.com", **extra})
    assert response.status_code == 200
    payload = response.json()
    assert payload["role"] == "free"
    login = client.post("/auth/login", json={"email": payload["email"], "api_key": payload["api_key"]})
    assert login.status_code == 200
    assert login.json()["role"] == "free"
    with sessions() as db:
        key = db.query(APIKey).one()
        assert key.role.value == "free"
        assert key.rate_limit_tier == "free"


CACHE_SOURCE = Path(__file__).resolve().parents[1] / "modules/phishing_detector/cache_db.py"


def load_cache():
    # Load the storage unit without importing the scanner package and its network clients.
    spec = importlib.util.spec_from_file_location("cache_under_test", CACHE_SOURCE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_scan_cache_uses_main_database():
    from app.database import DB_FILE
    cache = load_cache()
    assert cache._db_path() == DB_FILE


def test_worker_result_visible_to_separate_api_process(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNTIME_DB_PATH", str(tmp_path / "nested/runtime.db"))
    program = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('worker_cache', sys.argv[1])
cache = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cache)
assert cache.set_celery_job('job:example', {'status': 'complete', 'safety_score': 75})
assert cache.set_celery_job('job:expired', {'status': 'complete'}, ttl_seconds=-10)
"""
    subprocess.run([sys.executable, "-c", program, str(CACHE_SOURCE)], check=True, env=os.environ.copy())
    cache = load_cache()
    assert cache.get_celery_job("job:example") == {"status": "complete", "safety_score": 75}
    assert cache.get_celery_job("job:expired") is None
