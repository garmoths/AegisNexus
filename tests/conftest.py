"""Tests use disposable storage and never call paid/external services implicitly."""
import os
import tempfile
from pathlib import Path

import pytest

_TEST_ROOT = Path(tempfile.mkdtemp(prefix='aegis-tests-'))
# Never read the developer's .env during tests.
os.environ['AEGIS_ENV_FILE'] = ''
os.environ['DATABASE_URL'] = 'sqlite:///' + str(_TEST_ROOT / 'app.db')
os.environ['RUNTIME_DB_PATH'] = str(_TEST_ROOT / 'runtime.db')
os.environ['PDF_OUTPUT_DIR'] = str(_TEST_ROOT / 'reports')
os.environ['CELERY_BROKER_URL'] = 'memory://'
os.environ['DEMO_MODE'] = '0'
os.environ['CELERY_PRELOAD_MODELS'] = '0'
for key in ('GEMINI_API_KEY', 'GROQ_API_KEY', 'OPENAI_API_KEY', 'VIRUSTOTAL_API_KEYS', 'GOOGLE_SAFE_BROWSING_KEYS', 'URLSCAN_API_KEYS', 'ABUSE_API_KEY', 'ABUSEIPDB_API_KEYS',
            'SPAMHAUS_USERNAME', 'SPAMHAUS_PASSWORD', 'PHISHTANK_APP_KEY', 'SMTP_HOST', 'SMTP_PASSWORD'):
    os.environ[key] = ''


@pytest.fixture(scope='session', autouse=True)
def initialize_test_schema():
    # Build the shared test database through the real migrations, like ./run.sh does.
    from app.database import engine
    from app.migrations import upgrade_to_head
    upgrade_to_head(engine)
    yield
    engine.dispose()


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    monkeypatch.setenv('RUNTIME_DB_PATH', str(tmp_path / 'runtime.db'))
    monkeypatch.setenv('PDF_OUTPUT_DIR', str(tmp_path / 'reports'))
    # Tarama önbelleği ana DB'de: her test boş önbellekle başlasın.
    from app.database import engine
    with engine.begin() as connection:
        connection.exec_driver_sql('DELETE FROM scan_results')
        connection.exec_driver_sql('DELETE FROM scan_events')
    # Modules that intentionally exercise a network response install their own mocks.
    import urllib.request

    import requests
    import urllib3
    def blocked(*args, **kwargs):
        raise requests.ConnectionError('External network disabled during tests')
    monkeypatch.setattr(requests.sessions.Session, 'request', blocked)
    monkeypatch.setattr(urllib3.HTTPConnectionPool, 'urlopen', blocked)

    monkeypatch.setattr(urllib.request, 'urlopen', blocked)

    import socket
    def blocked_socket(*args, **kwargs):
        raise OSError('External socket disabled during tests')
    def blocked_dns(*args, **kwargs):
        raise socket.gaierror('External DNS disabled during tests')
    monkeypatch.setattr(socket, 'create_connection', blocked_socket)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked_dns)
